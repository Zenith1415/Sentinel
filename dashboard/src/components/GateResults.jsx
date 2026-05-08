import React from 'react'

const GATES = [
  { id: 'gate1', label: 'Gate 1 — Vulnerability Removed', desc: 'Re-runs agents; original Critical/High must not reappear' },
  { id: 'gate2', label: 'Gate 2 — Compilation',           desc: 'Compiles cleanly with solcx' },
  { id: 'gate3', label: 'Gate 3 — Function Signatures',   desc: 'All original public/external functions preserved' },
  { id: 'gate4', label: 'Gate 4 — KB Bad-Fix Check',      desc: 'Cosine similarity to rejected patches < 0.85' },
  { id: 'gate5', label: 'Gate 5 — Fuzzing / Invariants',  desc: 'Echidna or static invariant simulation passes' },
]

export default function GateResults({ gateResults = {}, validationPassed }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>5-Gate Validator</h2>
        {validationPassed != null && (
          <span style={{ fontSize: '.8rem', color: validationPassed ? 'var(--green)' : 'var(--red)', fontWeight: 600 }}>
            {validationPassed ? '✓ PASSED' : '✗ FAILED'}
          </span>
        )}
      </div>

      <div className="gates-grid">
        {GATES.map(g => {
          const v = gateResults[g.id]
          const statusClass = v === true ? 'pass' : v === false ? 'fail' : ''
          return (
            <div key={g.id} className="gate-row">
              <div className={`gate-cb ${statusClass}`}>
                {v === true ? <span style={{ color: 'var(--green)', fontSize: '.75rem' }}>✓</span>
                  : v === false ? <span style={{ color: 'var(--red)', fontSize: '.75rem' }}>✗</span>
                    : null}
              </div>
              <div>
                <div className="gate-label">{g.label}</div>
                <div style={{ fontSize: '.72rem', color: 'var(--text-muted)' }}>{g.desc}</div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
