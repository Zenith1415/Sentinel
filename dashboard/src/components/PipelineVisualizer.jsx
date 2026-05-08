import React, { useState } from 'react'

const NODES = [
  { id: 'detect',    label: 'Detect',    icon: '🔍', sub: '5 agents parallel' },
  { id: 'correlate', label: 'Correlate', icon: '🔗', sub: 'merge + confidence' },
  { id: 'route',     label: 'Route',     icon: '🚦', sub: 'fast / medium / slow' },
  { id: 'patch',     label: 'Patch',     icon: '🩹', sub: '3 candidates' },
  { id: 'validate',  label: 'Validate',  icon: '✅', sub: '5-gate validator' },
  { id: 'deploy',    label: 'Deploy',    icon: '🚀', sub: 'UUPS proxy upgrade' },
  { id: 'monitor',   label: 'Monitor',   icon: '📡', sub: 'anomaly watch' },
]

export default function PipelineVisualizer({ completedNodes, currentNode, state, pipelineId, onPause, onRollback }) {
  const [approver1, setApprover1] = useState('')
  const [approver2, setApprover2] = useState('')
  const [showApprove, setShowApprove] = useState(null) // 'pause' | 'rollback'

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
        {pipelineId && <span className="tag mono">{pipelineId.slice(0, 8)}…</span>}
      </div>

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
