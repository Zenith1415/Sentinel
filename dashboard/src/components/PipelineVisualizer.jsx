import React, { useState, useEffect } from 'react'

const API = ''

const NODES = [
  { id: 'detect',    label: 'Detect',    icon: '🔍', sub: '5 agents parallel' },
  { id: 'correlate', label: 'Correlate', icon: '🔗', sub: 'merge + confidence' },
  { id: 'route',     label: 'Route',     icon: '🚦', sub: 'fast / medium / slow' },
  { id: 'patch',     label: 'Patch',     icon: '🩹', sub: '3 candidates' },
  { id: 'validate',  label: 'Validate',  icon: '✅', sub: '5-gate validator' },
  { id: 'deploy',    label: 'Deploy',    icon: '🚀', sub: 'UUPS proxy upgrade' },
  { id: 'monitor',   label: 'Monitor',   icon: '📡', sub: 'anomaly watch' },
]

export default function PipelineVisualizer({ completedNodes, currentNode, state, pipelineId, onPause, onRollback, onLoadHistory }) {
  const [approver1,   setApprover1]   = useState('')
  const [approver2,   setApprover2]   = useState('')
  const [showApprove, setShowApprove] = useState(null) // 'pause' | 'rollback'
  const [showHistory, setShowHistory] = useState(false)
  const [history,     setHistory]     = useState([])
  const [histLoading, setHistLoading] = useState(false)

  const fetchHistory = async () => {
    setHistLoading(true)
    try {
      const r = await fetch(`${API}/pipelines/history?limit=10`)
      if (r.ok) setHistory(await r.json())
    } catch {}
    setHistLoading(false)
  }

  useEffect(() => {
    if (showHistory) fetchHistory()
  }, [showHistory])

  function nodeStatus(id) {
    if (state?.error && !state?.healed && id === currentNode) return 'failed'
    if (completedNodes.includes(id)) return 'passed'
    if (currentNode === id) return 'running'
    return 'pending'
  }

  const icons = { pending: '○', running: '◉', passed: '✓', failed: '✗' }

  async function submit(action) {
    if (!approver1.trim() || !approver2.trim()) return alert('Both approvers required')
    if (action === 'pause') await onPause(approver1, approver2)
    else await onRollback(approver1, approver2)
    setShowApprove(null)
    setApprover1('')
    setApprover2('')
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Pipeline</h2>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {pipelineId && <span className="tag mono">{pipelineId.slice(0, 8)}…</span>}
          <button
            className="btn outline"
            style={{ padding: '2px 8px', fontSize: '.72rem' }}
            onClick={() => setShowHistory(h => !h)}
          >
            {showHistory ? 'Current' : 'History'}
          </button>
        </div>
      </div>

      {showHistory && (
        <div style={{ marginBottom: '.75rem' }}>
          {histLoading ? (
            <span className="empty">Loading…</span>
          ) : history.length === 0 ? (
            <span className="empty">No pipeline history in Atlas yet.</span>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '.72rem' }}>
                <thead>
                  <tr style={{ color: 'var(--text-muted)', textAlign: 'left' }}>
                    <th style={{ padding: '3px 6px' }}>Address</th>
                    <th style={{ padding: '3px 6px' }}>Route</th>
                    <th style={{ padding: '3px 6px' }}>Healed</th>
                    <th style={{ padding: '3px 6px' }}>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map(row => (
                    <tr
                      key={row.pipeline_id}
                      style={{ cursor: 'pointer', borderTop: '1px solid var(--border)' }}
                      onClick={() => { onLoadHistory && onLoadHistory(row); setShowHistory(false) }}
                    >
                      <td style={{ padding: '4px 6px', fontFamily: 'monospace' }}>
                        {row.contract_address ? row.contract_address.slice(0, 10) + '…' : '—'}
                      </td>
                      <td style={{ padding: '4px 6px', color: row.route === 'slow' ? 'var(--red)' : 'var(--green)' }}>
                        {row.route || '—'}
                      </td>
                      <td style={{ padding: '4px 6px', color: row.healed ? 'var(--green)' : 'var(--red)' }}>
                        {row.healed ? '✓' : '✗'}
                      </td>
                      <td style={{ padding: '4px 6px', color: 'var(--text-muted)' }}>
                        {row.created_at ? new Date(row.created_at).toLocaleString() : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}


      <div className="pipeline-steps">
        {NODES.map(n => {
          const status = nodeStatus(n.id)
          return (
            <div key={n.id} className={`step ${status}`}>
              <span className="step-icon">{n.icon}</span>
              <span className="step-label">{n.label}</span>
              <span className="step-sub">{status === 'running' ? '…' : n.sub}</span>
              <span style={{ marginLeft: '4px', fontSize: '.8rem' }}>{icons[status]}</span>
            </div>
          )
        })}
      </div>

      {pipelineId && (
        <div style={{ marginTop: '.75rem' }}>
          {!showApprove ? (
            <div className="pipeline-actions">
              <button className="btn outline" onClick={() => setShowApprove('pause')}>Pause</button>
              <button className="btn danger" onClick={() => setShowApprove('rollback')}>Force Rollback</button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '.5rem', marginTop: '.5rem' }}>
              <small style={{ color: 'var(--text-muted)' }}>
                {showApprove === 'pause' ? 'Pause' : 'Force Rollback'} — 2 approvers required
              </small>
              <input className="field input" placeholder="Approver 1 (email)" value={approver1}
                onChange={e => setApprover1(e.target.value)}
                style={{ background: 'var(--surface2)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '.35rem .5rem' }} />
              <input className="field input" placeholder="Approver 2 (email)" value={approver2}
                onChange={e => setApprover2(e.target.value)}
                style={{ background: 'var(--surface2)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '.35rem .5rem' }} />
              <div style={{ display: 'flex', gap: '.5rem' }}>
                <button className="btn" onClick={() => submit(showApprove)}>Confirm</button>
                <button className="btn outline" onClick={() => setShowApprove(null)}>Cancel</button>
              </div>
            </div>
          )}
        </div>
      )}

      {state?.route && (
        <div style={{ marginTop: '.5rem', fontSize: '.78rem', color: 'var(--text-muted)' }}>
          Route: <strong style={{ color: state.route === 'slow' ? 'var(--red)' : 'var(--green)' }}>{state.route}</strong>
          {state.confidence_score > 0 && <> · Confidence: {(state.confidence_score * 100).toFixed(0)}%</>}
        </div>
      )}
    </div>
  )
}
