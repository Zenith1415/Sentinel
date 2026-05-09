import React, { useState } from 'react'

const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 }

const VULN_DESCRIPTIONS = {
  Reentrancy: 'External call made before state update — attacker can re-enter the function and drain funds before balances are decremented.',
  MissingAccessControl: 'Setter/admin function lacks an access control modifier (onlyOwner / onlyRole / onlyAdmin) — any address can invoke it.',
  MissingOwnershipProtection: 'setOwner() can be called by anyone — leads to immediate ownership hijack.',
  UnprotectedInitializer: 'initialize() can be called multiple times because no one-shot guard (initializer / _initialized / onlyInitializing) is present — front-runner can take over.',
  DangerousDelegatecall: 'delegatecall executes target contract code in this contract\'s storage context. Storage layout mismatches or untrusted targets can corrupt state or hijack execution.',
  SelfdestructPresent: 'Contract contains selfdestruct — even if guarded, this opcode is being deprecated and locks funds in proxies that delegatecall a destroyed implementation.',
  MultiContractArchitecture: 'File defines multiple contracts that interact. Cross-contract behaviour cannot be patched in isolation — patches must coordinate storage layouts and call paths.',
  CrossContractReentrancy: 'Reentrancy enters via a different contract in the call chain. nonReentrant on a single function does NOT protect against re-entry from a sibling contract.',
  GovernanceReentrancy: 'External call inside a governance function (onlyOwner / onlyRole) — attacker who controls the called address can re-enter before state is committed.',
  OracleManipulation: 'Price oracle can return stale, zero, or manipulable values. When combined with unchecked arithmetic, this can lead to division-by-zero or massive overflow during liquidations.',
  DelegatecallStorageCollision: 'Multiple contracts use delegatecall and share storage slot 0 for different variables (address vs bool vs uint256). Writing one corrupts the others.',
  FlashLoanCallbackReentrancy: 'ERC-3156 callback is invoked between disbursement and repayment check. Reentrant deposit() during callback can inflate the balance and bypass repayment validation.',
  SelfdestructGovernance: 'selfdestruct combined with weak governance (1-token vote, no timelock) lets an attacker acquire minimal voting power, change the owner, and destroy the implementation contract.',
  TxOriginAuth: 'Authorization uses tx.origin instead of msg.sender — phishing contracts can bypass access control.',
  IntegerOverflow: 'Arithmetic operation can overflow. In Solidity ≥0.8 this reverts unless inside an unchecked block.',
  TIMEOUT: 'Mythril symbolic execution exceeded its time budget without producing a result. This usually indicates contract complexity beyond automated analysis.',
}

const METHODOLOGY_LABEL = {
  static:     { label: 'Static',     color: 'var(--blue)',      hint: 'Slither + regex-based pattern matching' },
  symbolic:   { label: 'Symbolic',   color: 'var(--cyan)',      hint: 'Mythril symbolic execution' },
  semantic:   { label: 'Semantic',   color: 'var(--green)',     hint: 'LLM analysis of code intent and ambiguity' },
  governance: { label: 'Governance', color: 'var(--yellow)',    hint: 'Pattern matching on access control / multisig / timelock' },
  pattern:    { label: 'Threat',     color: '#ff6b35',          hint: 'Threat-pattern matching against known exploit signatures' },
  unknown:    { label: '?',          color: 'var(--text-muted)', hint: 'Unknown methodology' },
}

function FindingRow({ f, idx, expanded, onToggle }) {
  const meth = METHODOLOGY_LABEL[f.methodology] || METHODOLOGY_LABEL.unknown
  const vulnType = f.vuln_type || f.type || '—'
  const description = VULN_DESCRIPTIONS[vulnType]
  const lineRange = Array.isArray(f.line_range) ? f.line_range : null

  return (
    <>
      <tr style={{ cursor: 'pointer' }} onClick={() => onToggle(idx)}>
        <td style={{ width: 14, fontSize: '.65rem', color: 'var(--text-muted)' }}>{expanded ? '▼' : '▶'}</td>
        <td><span className={`sev ${f.severity}`}>{f.severity}</span></td>
        <td>
          <strong>{vulnType}</strong>
          {f.cross_contract_flag && (
            <span style={{
              marginLeft: 5, fontSize: '.6rem', padding: '1px 4px', borderRadius: 3,
              background: 'rgba(255,0,0,0.15)', color: 'var(--red)', border: '1px solid var(--red)',
            }}>
              cross-contract
            </span>
          )}
        </td>
        <td className="mono" style={{ fontSize: '.72rem' }}>{f.affected_function || '—'}</td>
        <td>
          <span style={{
            fontSize: '.62rem', padding: '1px 5px', borderRadius: 3,
            background: 'var(--bg-panel)', color: meth.color, border: `1px solid ${meth.color}`,
          }} title={meth.hint}>
            {meth.label}
          </span>
        </td>
        <td>{f.confidence != null ? `${(f.confidence * 100).toFixed(0)}%` : '—'}</td>
      </tr>

      {expanded && (
        <tr>
          <td></td>
          <td colSpan={5} style={{
            padding: '8px 10px',
            background: 'var(--bg-panel)',
            borderRadius: 4,
            fontSize: '.72rem',
            color: 'var(--text-muted)',
            lineHeight: 1.5,
          }}>
            {description && (
              <div style={{ marginBottom: 8 }}>
                <strong style={{ color: 'var(--text)' }}>What it means:</strong>{' '}{description}
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '4px 10px', marginBottom: 8 }}>
              <div><strong style={{ color: 'var(--text)' }}>Detected by:</strong></div>
              <div style={{ color: meth.color }}>{meth.label} agent — {meth.hint}</div>

              {lineRange && lineRange[0] > 0 && (
                <>
                  <div><strong style={{ color: 'var(--text)' }}>Lines:</strong></div>
                  <div className="mono">{lineRange[0]}–{lineRange[1]}</div>
                </>
              )}

              <div><strong style={{ color: 'var(--text)' }}>Cross-contract:</strong></div>
              <div style={{ color: f.cross_contract_flag ? 'var(--red)' : 'var(--green)' }}>
                {f.cross_contract_flag ? 'Yes — patch must coordinate across multiple contracts' : 'No — patch is local to this contract'}
              </div>
            </div>

            {f.evidence && (
              <div style={{ marginBottom: 8 }}>
                <div><strong style={{ color: 'var(--text)' }}>Evidence:</strong></div>
                <pre style={{
                  margin: '4px 0 0',
                  padding: '6px 8px',
                  background: 'rgba(255,255,255,0.03)',
                  border: '1px solid var(--border)',
                  borderRadius: 3,
                  whiteSpace: 'pre-wrap',
                  fontFamily: 'monospace',
                  fontSize: '.7rem',
                  color: 'var(--text)',
                  maxHeight: 120,
                  overflowY: 'auto',
                }}>{f.evidence}</pre>
              </div>
            )}

            {(f.fix_recommendation || f.suggested_fix) && (
              <div>
                <div><strong style={{ color: 'var(--green)' }}>Recommended fix:</strong></div>
                <div style={{
                  padding: '6px 8px',
                  background: 'rgba(0,200,100,0.05)',
                  border: '1px solid rgba(0,200,100,0.2)',
                  borderRadius: 3,
                  marginTop: 4,
                  color: 'var(--text)',
                }}>
                  {f.fix_recommendation || f.suggested_fix}
                </div>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

export default function FindingsTable({ findings = [] }) {
  const [expanded, setExpanded] = useState(new Set())

  const sorted = [...findings].sort((a, b) =>
    (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  )

  const toggle = idx => {
    setExpanded(prev => {
      const n = new Set(prev)
      if (n.has(idx)) n.delete(idx); else n.add(idx)
      return n
    })
  }

  const toggleAll = () => {
    if (expanded.size === sorted.length) setExpanded(new Set())
    else setExpanded(new Set(sorted.map((_, i) => i)))
  }

  // Severity counts
  const counts = sorted.reduce((acc, f) => {
    const s = f.severity || 'Unknown'
    acc[s] = (acc[s] || 0) + 1
    return acc
  }, {})

  return (
    <div className="panel" style={{ flex: 1, overflowY: 'auto' }}>
      <div className="panel-header">
        <h2>Findings</h2>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {['Critical', 'High', 'Medium', 'Low'].map(s => counts[s] ? (
            <span key={s} className={`sev ${s}`} style={{ fontSize: '.62rem', padding: '1px 6px' }}>
              {counts[s]} {s}
            </span>
          ) : null)}
          {sorted.length > 0 && (
            <button
              className="btn"
              style={{ padding: '2px 8px', fontSize: '.7rem' }}
              onClick={toggleAll}
            >
              {expanded.size === sorted.length ? 'Collapse all' : 'Expand all'}
            </button>
          )}
        </div>
      </div>

      {sorted.length === 0 ? (
        <div className="empty">No findings yet</div>
      ) : (
        <div className="scroll-panel" style={{ maxHeight: 440 }}>
          <table className="findings-table">
            <thead>
              <tr>
                <th></th>
                <th>Severity</th>
                <th>Type</th>
                <th>Function</th>
                <th>Source</th>
                <th>Conf.</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((f, i) => (
                <FindingRow
                  key={i}
                  f={f}
                  idx={i}
                  expanded={expanded.has(i)}
                  onToggle={toggle}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
