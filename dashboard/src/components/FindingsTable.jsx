import React from 'react'

const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 }

export default function FindingsTable({ findings = [] }) {
  const sorted = [...findings].sort((a, b) =>
    (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  )

  return (
    <div className="panel" style={{ flex: 1, overflowY: 'auto' }}>
      <div className="panel-header">
        <h2>Findings</h2>
        <span className="tag">{findings.length} total</span>
      </div>

      {sorted.length === 0 ? (
        <div className="empty">No findings yet</div>
      ) : (
        <div className="scroll-panel" style={{ maxHeight: 280 }}>
          <table className="findings-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>Function</th>
                <th>Confidence</th>
                <th>Fix</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((f, i) => (
                <tr key={i}>
                  <td><span className={`sev ${f.severity}`}>{f.severity}</span></td>
                  <td>{f.vuln_type || f.type || '—'}</td>
                  <td className="mono">{f.affected_function || f.location || '—'}</td>
                  <td>{f.confidence != null ? `${(f.confidence * 100).toFixed(0)}%` : '—'}</td>
                  <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {f.fix_recommendation || f.suggested_fix || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
