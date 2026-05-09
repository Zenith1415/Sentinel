import React, { useState, useEffect } from 'react'

const API = ''

const SEVERITY_COLOR = {
  critical: 'var(--red)',
  high:     '#ff6b35',
  medium:   'var(--yellow)',
  low:      'var(--text-muted)',
}

const SEVERITY_ICON = {
  critical: '🚨',
  high:     '⛔',
  medium:   '⚠️',
  low:      'ℹ️',
}

function AlertCard({ alert }) {
  const color = SEVERITY_COLOR[alert.severity] || 'var(--text-muted)'
  const icon  = SEVERITY_ICON[alert.severity]  || '·'

  return (
    <div style={{
      border:       `1px solid ${color}`,
      borderRadius: 6,
      padding:      '8px 10px',
      marginBottom: 6,
      background:   'var(--bg-panel)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
        <span style={{ fontSize: '.85rem' }}>{icon}</span>
        <span style={{ fontSize: '.75rem', fontWeight: 700, color }}>
          {alert.title}
        </span>
        <span style={{
          marginLeft: 'auto',
          fontSize: '.62rem',
          padding: '1px 5px',
          borderRadius: 8,
          background: color,
          color: '#000',
          fontWeight: 600,
          textTransform: 'uppercase',
        }}>
          {alert.severity}
        </span>
      </div>

      <p style={{ fontSize: '.7rem', color: 'var(--text-muted)', margin: '0 0 4px 0', lineHeight: 1.4 }}>
        {alert.message}
      </p>

      {alert.confidence_score != null && (
        <div style={{ fontSize: '.65rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          Confidence: <strong style={{ color }}>{(alert.confidence_score * 100).toFixed(1)}%</strong>
          {alert.findings_count != null && (
            <> · Findings: <strong>{alert.findings_count}</strong></>
          )}
          {alert.cross_contract_flags > 0 && (
            <> · Cross-contract: <strong style={{ color: 'var(--red)' }}>{alert.cross_contract_flags}</strong></>
          )}
        </div>
      )}

      {alert.retry_count != null && (
        <div style={{ fontSize: '.65rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          Retry attempts: <strong>{alert.retry_count}/3</strong>
          {alert.failed_gates?.length > 0 && (
            <> · Failed gates: <strong style={{ color }}>{alert.failed_gates.join(', ')}</strong></>
          )}
        </div>
      )}

      {alert.novel_types?.length > 0 && (
        <div style={{ fontSize: '.65rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          Novel types: <span style={{ fontFamily: 'monospace' }}>
            {alert.novel_types.slice(0, 3).join(', ')}
            {alert.novel_types.length > 3 && ` +${alert.novel_types.length - 3} more`}
          </span>
        </div>
      )}

      <div style={{
        fontSize: '.65rem',
        color: 'var(--green)',
        borderTop: '1px solid var(--border)',
        paddingTop: 4,
        marginTop: 4,
      }}>
        → <em>{alert.action}</em>
      </div>
    </div>
  )
}

export default function ScopeBoundaryAlert({ pipelineId, pipelineStatus }) {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(false)

  const fetchAlerts = async () => {
    if (!pipelineId) return
    setLoading(true)
    try {
      const r = await fetch(`${API}/pipeline/${pipelineId}/scope-alerts`)
      if (r.ok) setData(await r.json())
    } catch {}
    finally { setLoading(false) }
  }

  useEffect(() => {
    if (pipelineStatus === 'complete' || pipelineStatus === 'error') {
      fetchAlerts()
    }
    if (!pipelineId) setData(null)
  }, [pipelineStatus, pipelineId])

  // Nothing to show if pipeline is healthy
  if (!data || !data.requires_human_review) return null

  const alerts = data.alerts || []

  return (
    <div className="panel" style={{ borderLeft: '3px solid var(--red)' }}>
      <div className="panel-header">
        <h2>⛔ Scope Boundary — Human Review Required</h2>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{
            fontSize: '.68rem', padding: '2px 8px', borderRadius: 10,
            background: 'var(--red)', color: '#fff', fontWeight: 700,
          }}>
            {alerts.length} ALERT{alerts.length !== 1 ? 'S' : ''}
          </span>
          <button
            className="btn"
            style={{ padding: '2px 10px', fontSize: '.72rem' }}
            onClick={fetchAlerts}
            disabled={loading}
          >
            {loading ? '⟳' : '↻'}
          </button>
        </div>
      </div>

      <div style={{
        fontSize: '.72rem',
        color: 'var(--text-muted)',
        background: 'rgba(255,0,0,0.05)',
        border: '1px solid var(--red)',
        borderRadius: 4,
        padding: '6px 10px',
        marginBottom: 10,
        lineHeight: 1.5,
      }}>
        <strong style={{ color: '#ff6b35' }}>System correctly identified this contract exceeds autonomous patching capability.</strong>
        {' '}Route: <code style={{ color: 'var(--red)' }}>{data.route}</code>
        {data.confidence_score != null && (
          <> · Confidence: <code style={{ color: 'var(--yellow)' }}>{(data.confidence_score * 100).toFixed(1)}%</code></>
        )}
        <br />
        <em>Escalating to human review — this is correct behavior.</em>
      </div>

      {alerts.map((alert, i) => (
        <AlertCard key={i} alert={alert} />
      ))}
    </div>
  )
}
