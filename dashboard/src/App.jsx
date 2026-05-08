import React, { useState, useEffect, useRef, useCallback } from 'react'
import PipelineVisualizer from './components/PipelineVisualizer.jsx'
import FindingsTable from './components/FindingsTable.jsx'
import DiffViewer from './components/DiffViewer.jsx'
import GateResults from './components/GateResults.jsx'
import DeployStatus from './components/DeployStatus.jsx'
import KbHealth from './components/KbHealth.jsx'

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

export default function App() {
  // Form state
  const [source, setSource]   = useState(VAULT_EXAMPLE)
  const [address, setAddress] = useState('0x' + '1'.repeat(40))
  const [tvl, setTvl]         = useState('0')

  // Pipeline state
  const [pipelineId,     setPipelineId]     = useState(null)
  const [pipelineStatus, setPipelineStatus] = useState('idle')
  const [healingState,   setHealingState]   = useState({})
  const [completedNodes, setCompletedNodes] = useState([])
  const [currentNode,    setCurrentNode]    = useState(null)
  const [rollbackHistory, setRollbackHistory] = useState([])
  const [sseLog,         setSseLog]         = useState([])

  const esRef = useRef(null)

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

      setSseLog(prev => [...prev, { node, ts: Date.now() }])

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

  // ── Status dot ───────────────────────────────────────────────────────
  const statusColor = {
    idle: 'grey', starting: 'yellow', running: 'green',
    complete: 'green', error: 'red', paused: 'yellow',
    rollback_initiated: 'yellow', rolled_back: 'red',
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

      {/* Launch bar */}
      <div className="launch-bar">
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
          <FindingsTable findings={healingState.all_findings || []} />
          <DiffViewer
            originalSource={source}
            candidates={healingState.candidate_patches || []}
          />

          {/* SSE event log */}
          <div className="panel" style={{ flex: '0 0 auto' }}>
            <div className="panel-header">
              <h2>Event Log</h2>
              <span className="tag">{sseLog.length} events</span>
            </div>
            <div style={{ maxHeight: 120, overflowY: 'auto', fontFamily: 'monospace', fontSize: '.75rem' }}>
              {sseLog.length === 0
                ? <span className="empty">Awaiting SSE events…</span>
                : sseLog.map((e, i) => (
                    <div key={i} style={{ color: e.node.startsWith('_') ? 'var(--yellow)' : 'var(--green)' }}>
                      [{new Date(e.ts).toLocaleTimeString()}] node_complete → <strong>{e.node}</strong>
                    </div>
                  ))
              }
            </div>
          </div>
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
