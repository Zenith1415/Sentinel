import React from 'react'

function short(addr) {
  if (!addr || addr.length < 12) return addr || '—'
  return addr.slice(0, 8) + '…' + addr.slice(-6)
}

export default function DeployStatus({ state = {}, rollbackHistory = [] }) {
  const { deployed, healed, tx_hash, rollback_target, contract_address, rl_reward } = state

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Deploy Status</h2>
        <span style={{ fontSize: '.85rem', fontWeight: 600, color: healed ? 'var(--green)' : 'var(--text-muted)' }}>
          {healed ? '🟢 HEALED' : deployed ? '🟡 DEPLOYED' : '⚪ PENDING'}
        </span>
      </div>

      <div className="deploy-grid">
        <div className="deploy-card">
          <div className="label">Proxy Address</div>
          <div className="value" title={contract_address}>{short(contract_address)}</div>
        </div>
        <div className="deploy-card">
          <div className="label">Tx Hash</div>
          <div className="value" title={tx_hash}>{short(tx_hash)}</div>
        </div>
        <div className="deploy-card">
          <div className="label">Rollback Target</div>
          <div className="value" title={rollback_target}>{short(rollback_target)}</div>
        </div>
        <div className="deploy-card">
          <div className="label">RL Reward</div>
          <div className="value" style={{ color: rl_reward >= 0 ? 'var(--green)' : 'var(--red)' }}>
            {rl_reward != null ? (rl_reward >= 0 ? '+' : '') + rl_reward.toFixed(2) : '—'}
          </div>
        </div>
      </div>

      {rollbackHistory.length > 0 && (
        <div className="rollback-list">
          <h3 style={{ marginBottom: '.4rem', color: 'var(--yellow)' }}>⚠ Rollback History</h3>
          {rollbackHistory.map((r, i) => (
            <div key={i} className="rollback-item">
              <div style={{ color: 'var(--red)', fontWeight: 600 }}>RollbackTriggered</div>
              <div>Target: <span className="mono">{short(r.rollback_target)}</span></div>
              <div>Proxy: <span className="mono">{short(r.proxy_address)}</span></div>
              <div style={{ color: 'var(--text-muted)' }}>
                {new Date(r.timestamp * 1000).toLocaleTimeString()} · {r.triggered_by}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
