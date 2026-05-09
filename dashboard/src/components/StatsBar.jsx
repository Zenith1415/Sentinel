import React, { useState, useEffect } from 'react'

const API = ''

export default function StatsBar() {
  const [stats, setStats] = useState(null)

  const fetchStats = async () => {
    try {
      const r = await fetch(`${API}/pipelines/stats`)
      if (r.ok) setStats(await r.json())
    } catch {}
  }

  useEffect(() => {
    fetchStats()
    const id = setInterval(fetchStats, 30_000)
    return () => clearInterval(id)
  }, [])

  if (!stats) return null

  const successPct = stats.heal_success_rate != null
    ? (stats.heal_success_rate * 100).toFixed(1)
    : '—'

  return (
    <div style={{
      display: 'flex', gap: '1.5rem', alignItems: 'center',
      background: 'var(--bg-panel)', border: '1px solid var(--border)',
      borderRadius: 8, padding: '.6rem 1.2rem', marginBottom: '.75rem',
      flexWrap: 'wrap',
    }}>
      <StatChip label="Total Runs"    value={stats.total_pipelines_run ?? 0}     color="var(--blue)" />
      <StatChip label="Success Rate"  value={`${successPct}%`}                    color="var(--green)" />
      <StatChip label="Rollbacks"     value={stats.rollback_count ?? 0}            color="var(--red)" />
      <StatChip label="Avg Confidence" value={`${((stats.avg_confidence_score ?? 0) * 100).toFixed(0)}%`} color="var(--yellow)" />
      {(stats.most_common_vuln_types || []).length > 0 && (
        <div style={{ fontSize: '.7rem', color: 'var(--text-muted)' }}>
          Top vulns: <strong>{stats.most_common_vuln_types.slice(0, 3).join(', ')}</strong>
        </div>
      )}
      <div style={{ marginLeft: 'auto', fontSize: '.65rem', color: 'var(--text-muted)' }}>
        auto-refresh 30s
      </div>
    </div>
  )
}

function StatChip({ label, value, color }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 60 }}>
      <span style={{ fontSize: '1.1rem', fontWeight: 700, color }}>{value}</span>
      <span style={{ fontSize: '.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.04em' }}>{label}</span>
    </div>
  )
}
