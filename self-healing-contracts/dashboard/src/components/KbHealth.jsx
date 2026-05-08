import React, { useState, useEffect } from 'react'

export default function KbHealth() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)

  async function refresh() {
    setLoading(true)
    try {
      const r = await fetch('/kb/health')
      setData(await r.json())
    } catch (e) {
      setData({ status: 'error', error: e.message })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { refresh() }, [])

  const parts = data?.partitions || {}

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>KB Health</h2>
        <button className="btn outline" style={{ fontSize: '.75rem', padding: '.2rem .6rem' }} onClick={refresh} disabled={loading}>
          {loading ? '…' : '↻ Refresh'}
        </button>
      </div>

      {!data ? (
        <div className="empty">Loading…</div>
      ) : data.status === 'error' ? (
        <div style={{ color: 'var(--red)', fontSize: '.82rem' }}>{data.error}</div>
      ) : (
        <>
          <div className="kb-grid">
            <div className="kb-card">
              <div className="num">{parts.proven_patches ?? 0}</div>
              <div className="lbl">Proven Patches</div>
            </div>
            <div className="kb-card">
              <div className="num">{parts.rejected_patches ?? 0}</div>
              <div className="lbl">Rejected Patches</div>
            </div>
            <div className="kb-card">
              <div className="num">{parts.vuln_patterns ?? 0}</div>
              <div className="lbl">Vuln Patterns</div>
            </div>
          </div>

          <div style={{ marginTop: '.75rem', display: 'flex', gap: '1rem', flexWrap: 'wrap', fontSize: '.8rem' }}>
            <span>Total: <strong>{data.total_entries}</strong></span>
            <span style={{ color: data.stale_count > 0 ? 'var(--yellow)' : 'var(--green)' }}>
              Stale: <strong>{data.stale_count}</strong>
            </span>
            <span style={{ color: data.conflict_count > 0 ? 'var(--yellow)' : 'var(--green)' }}>
              Conflicts: <strong>{data.conflict_count}</strong>
            </span>
            <span style={{ color: 'var(--text-muted)' }}>TTL: {data.ttl_days}d</span>
          </div>
        </>
      )}
    </div>
  )
}
