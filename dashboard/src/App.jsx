import React, { useState, useEffect, useRef, useCallback } from 'react'
import PipelineVisualizer from './components/PipelineVisualizer.jsx'
import FindingsTable from './components/FindingsTable.jsx'
import DiffViewer from './components/DiffViewer.jsx'
import GateResults from './components/GateResults.jsx'
import DeployStatus from './components/DeployStatus.jsx'
import KbHealth from './components/KbHealth.jsx'
import TraceViewer from './components/TraceViewer.jsx'
import StatsBar from './components/StatsBar.jsx'
import RLLearningCurve from './components/RLLearningCurve.jsx'
import ScopeBoundaryAlert from './components/ScopeBoundaryAlert.jsx'
import HumanReview from './components/HumanReview.jsx'
import CliConsole from './components/CliConsole.jsx'

const API = ''  // proxied by Vite dev server

const VAULT_EXAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() { owner = msg.sender; }

    // VULN-1: reentrancy — call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;  // too late!
    }

    function deposit() external payable { balances[msg.sender] += msg.value; }

    // VULN-2: missing access control
    function setOwner(address newOwner) external {
        owner = newOwner;  // anyone can call!
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
`

// Paste of the full UnpatchableVault source — loaded via fetch for brevity
const UNPATCHABLE_PLACEHOLDER = `// Loading UnpatchableVault.sol…
// This contract has 6 vulnerability classes designed to defeat auto-patching.
// The pipeline will escalate to SLOW PATH (human review required).`

const PRESETS = [
  {
    label: '⚡ VulnerableVault',
    description: 'Simple reentrancy + missing access control. Pipeline heals this autonomously.',
    source: VAULT_EXAMPLE,
    badge: 'AUTO-PATCHABLE',
    badgeColor: 'var(--yellow)',
  },
  {
    label: '💀 UnpatchableVault',
    description: '6 vulnerability classes: cross-contract reentrancy, oracle manipulation, storage collision, flash loan, selfdestruct governance. Pipeline escalates to SLOW PATH.',
    source: null,
    file: '/UnpatchableVault.sol',
    badge: 'SLOW PATH',
    badgeColor: 'var(--red)',
  },
  {
    label: '✅ SafeVault',
    description: 'CEI pattern, nonReentrant, two-step ownership, safe oracle, multi-sig governance, no selfdestruct, no delegatecall. Pipeline finds no critical vulnerabilities.',
    source: null,
    file: '/SafeVault.sol',
    badge: 'SECURE',
    badgeColor: 'var(--green)',
  },
]

export default function App() {
  // Form state
  const [source,     setSource]     = useState(VAULT_EXAMPLE)
  const [address,    setAddress]    = useState('0x' + '1'.repeat(40))
  const [tvl,        setTvl]        = useState('0')
  const [presetIdx,  setPresetIdx]  = useState(0)

  // Pipeline state
  const [pipelineId,     setPipelineId]     = useState(null)
  const [pipelineStatus, setPipelineStatus] = useState('idle')
  const [healingState,   setHealingState]   = useState({})
  const [completedNodes, setCompletedNodes] = useState([])
  const [currentNode,    setCurrentNode]    = useState(null)
  const [rollbackHistory, setRollbackHistory] = useState([])
  const [sseLog,         setSseLog]         = useState([])

  const esRef = useRef(null)

  // ── Load a preset contract ───────────────────────────────────────────
  async function loadPreset(idx) {
    const preset = PRESETS[idx]
    setPresetIdx(idx)
    if (preset.source) {
      setSource(preset.source)
    } else if (preset.file) {
      try {
        const r = await fetch(preset.file)
        setSource(r.ok ? await r.text() : UNPATCHABLE_PLACEHOLDER)
      } catch {
        setSource(UNPATCHABLE_PLACEHOLDER)
      }
    }
  }

  // ── Launch pipeline ──────────────────────────────────────────────────
  async function heal() {
    setPipelineId(null)
    setPipelineStatus('starting')
    setHealingState({})
    setCompletedNodes([])
    setCurrentNode(null)
    setRollbackHistory([])
    setSseLog([])

    const resp = await fetch(`${API}/heal`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contract_source:  source,
        contract_address: address,
        tvl_estimate:     parseFloat(tvl) || 0,
      }),
    })
    const { pipeline_id } = await resp.json()
    setPipelineId(pipeline_id)
    setPipelineStatus('running')
    startSSE(pipeline_id)
  }

  // ── SSE subscriber ───────────────────────────────────────────────────
  function startSSE(id) {
    if (esRef.current) esRef.current.close()
    const es = new EventSource(`${API}/pipeline/${id}/stream`)
    esRef.current = es

    es.addEventListener('node_complete', e => {
      const event = JSON.parse(e.data)
      const node = event.node
      const state = event.state || {}

      // Store the full event (with state) so the CLI Console can render rich details
      setSseLog(prev => [...prev, { node, state, anomalies: event.anomalies, error: event.error, ts: Date.now() }])

      if (node === '__done__') {
        setPipelineStatus('complete')
        setHealingState(state)
        setCurrentNode(null)
        es.close()
        return
      }
      if (node === '__error__') {
        setPipelineStatus('error')
        setHealingState(prev => ({ ...prev, error: event.error }))
        setCurrentNode(null)
        es.close()
        return
      }
      if (node === '__rollback__' || node === 'RollbackTriggered') {
        setPipelineStatus('rolled_back')
        setHealingState(state)
        setCurrentNode(null)
        es.close()
        return
      }

      setCurrentNode(node)
      setHealingState(state)
      setCompletedNodes(prev => prev.includes(node) ? prev : [...prev, node])
    })

    es.onerror = () => {
      if (pipelineStatus !== 'complete') setPipelineStatus('error')
      es.close()
    }
  }

  // Keep rollback history synced
  useEffect(() => {
    if (!pipelineId) return
    const interval = setInterval(async () => {
      try {
        const r = await fetch(`${API}/pipeline/${pipelineId}`)
        const data = await r.json()
        setRollbackHistory(data.rollback_history || [])
      } catch {}
    }, 3000)
    return () => clearInterval(interval)
  }, [pipelineId])

  // ── Pause / Rollback ─────────────────────────────────────────────────
  async function onPause(a1, a2) {
    await fetch(`${API}/pipeline/${pipelineId}/pause`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approver_1: a1, approver_2: a2 }),
    })
    setPipelineStatus('paused')
  }

  async function onRollback(a1, a2) {
    const resp = await fetch(`${API}/pipeline/${pipelineId}/force-rollback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approver_1: a1, approver_2: a2 }),
    })
    if (!resp.ok) {
      const e = await resp.json()
      alert(`Rollback rejected: ${e.detail}`)
      return
    }
    setPipelineStatus('rollback_initiated')
  }

  // ── Inject anomaly (demo money shot) ────────────────────────────────
  async function injectAnomaly() {
    setPipelineStatus('monitoring')
    startSSE(pipelineId)   // re-subscribe BEFORE posting so we catch the rollback event
    await fetch(`${API}/demo/inject-anomaly/${pipelineId}`, { method: 'POST' })
  }

  // ── Status dot ───────────────────────────────────────────────────────
  const statusColor = {
    idle: 'grey', starting: 'yellow', running: 'green',
    complete: 'green', error: 'red', paused: 'yellow',
    monitoring: 'yellow', rollback_initiated: 'yellow', rolled_back: 'red',
  }[pipelineStatus] || 'grey'

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-title">
          <h1>🔐 Self-Healing Smart Contracts</h1>
          <span className="badge">LIVE</span>
        </div>
        <div style={{ fontSize: '.8rem', color: 'var(--text-muted)' }}>
          LangGraph · 5-Agent Detection · UUPS Deploy · Auto-Rollback
        </div>
      </header>

      {/* Stats bar — top, auto-refresh */}
      <StatsBar />

      {/* Launch bar */}
      <div className="launch-bar">
        {/* Preset selector */}
        <div className="field" style={{ flex: '0 0 auto' }}>
          <label>Contract Preset</label>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {PRESETS.map((p, i) => (
              <button
                key={i}
                className="btn"
                style={{
                  fontSize: '.72rem',
                  padding: '3px 10px',
                  background: presetIdx === i ? p.badgeColor : 'var(--bg-panel)',
                  color: presetIdx === i ? '#000' : 'var(--text-muted)',
                  border: `1px solid ${presetIdx === i ? p.badgeColor : 'var(--border)'}`,
                  fontWeight: presetIdx === i ? 700 : 400,
                }}
                onClick={() => loadPreset(i)}
                title={p.description}
              >
                {p.label}
                {p.badge && (
                  <span style={{
                    marginLeft: 5,
                    fontSize: '.58rem',
                    padding: '1px 4px',
                    borderRadius: 4,
                    background: presetIdx === i ? 'rgba(0,0,0,0.2)' : p.badgeColor,
                    color: presetIdx === i ? '#000' : '#000',
                    fontWeight: 700,
                    verticalAlign: 'middle',
                  }}>
                    {p.badge}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>
        <div className="field">
          <label>Contract Source (Solidity)</label>
          <textarea value={source} onChange={e => setSource(e.target.value)} />
        </div>
        <div className="field">
          <label>Proxy Address</label>
          <input value={address} onChange={e => setAddress(e.target.value)} />
        </div>
        <div className="field">
          <label>TVL (USD)</label>
          <input value={tvl} onChange={e => setTvl(e.target.value)} style={{ width: '12ch' }} />
        </div>
        <button className="btn" onClick={heal} disabled={pipelineStatus === 'running' || pipelineStatus === 'starting'}>
          {pipelineStatus === 'running' ? '⟳ Healing…' : '▶ Heal'}
        </button>
        {pipelineStatus === 'complete' && healingState.deployed && (
          <button
            className="btn"
            style={{ background: 'var(--yellow)', color: '#000', border: '1px solid #a07010' }}
            onClick={injectAnomaly}
          >
            ⚡ Inject Anomaly
          </button>
        )}
      </div>

      {/* Main grid */}
      <div className="main">
        {/* Left column */}
        <div className="left-col">
          <PipelineVisualizer
            completedNodes={completedNodes}
            currentNode={currentNode}
            state={healingState}
            pipelineId={pipelineId}
            onPause={onPause}
            onRollback={onRollback}
            onLoadHistory={(row) => {
              setHealingState({ ...healingState, ...row })
              setPipelineId(row.pipeline_id)
              setPipelineStatus(row.healed ? 'complete' : 'error')
            }}
          />
          <GateResults
            gateResults={healingState.gate_results || {}}
            validationPassed={healingState.validation_passed}
          />
          <DeployStatus
            state={healingState}
            rollbackHistory={rollbackHistory}
          />
          <KbHealth />
        </div>

        {/* Right column */}
        <div className="right-col">
          <ScopeBoundaryAlert pipelineId={pipelineId} pipelineStatus={pipelineStatus} />
          <HumanReview
            pipelineId={pipelineId}
            pipelineStatus={pipelineStatus}
            healingState={healingState}
            originalSource={source}
            onDeployed={(result) => {
              setPipelineStatus('complete')
              setHealingState(prev => ({
                ...prev,
                healed: true,
                deployed: true,
                tx_hash: result.tx_hash,
                route: 'manual',
                selected_patch: prev.selected_patch,
              }))
            }}
          />
          <RLLearningCurve />
          <TraceViewer pipelineId={pipelineId} pipelineStatus={pipelineStatus} />
          <FindingsTable findings={healingState.all_findings || []} />
          <DiffViewer
            originalSource={source}
            candidates={healingState.candidate_patches || []}
          />

          {/* Live CLI-style console — every agent, gate, LLM call, deploy step */}
          <CliConsole
            events={sseLog}
            pipelineId={pipelineId}
            pipelineStatus={pipelineStatus}
          />
        </div>
      </div>

      {/* Status bar */}
      <div className="status-bar">
        <span><span className={`dot ${statusColor}`} />Pipeline: <strong>{pipelineStatus}</strong></span>
        {pipelineId && <span>ID: <span className="mono">{pipelineId.slice(0, 16)}…</span></span>}
        {healingState.route && <span>Route: {healingState.route}</span>}
        {healingState.retry_count > 0 && <span>Retries: {healingState.retry_count}</span>}
        {healingState.rl_reward != null && healingState.rl_reward !== 0 && (
          <span>RL: {healingState.rl_reward >= 0 ? '+' : ''}{healingState.rl_reward.toFixed(2)}</span>
        )}
      </div>
    </div>
  )
}
