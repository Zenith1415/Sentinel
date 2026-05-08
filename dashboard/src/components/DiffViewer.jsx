import React, { useState } from 'react'

function computeDiff(original, patched) {
  if (!original || !patched) return []
  const aLines = original.split('\n')
  const bLines = patched.split('\n')

  // Simple LCS-based diff (fast enough for contract sizes)
  const lcs = buildLCS(aLines, bLines)
  const result = []
  let ai = 0, bi = 0, li = 0
  while (ai < aLines.length || bi < bLines.length) {
    if (ai < aLines.length && bi < bLines.length && li < lcs.length &&
        aLines[ai] === lcs[li] && bLines[bi] === lcs[li]) {
      result.push({ type: 'same', text: aLines[ai] })
      ai++; bi++; li++
    } else if (bi < bLines.length && (li >= lcs.length || bLines[bi] !== lcs[li])) {
      result.push({ type: 'added', text: bLines[bi] })
      bi++
    } else {
      result.push({ type: 'removed', text: aLines[ai] })
      ai++
    }
  }
  return result
}

function buildLCS(a, b) {
  // Limit to 200 lines each for performance
  const A = a.slice(0, 200), B = b.slice(0, 200)
  const m = A.length, n = B.length
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0))
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = A[i-1] === B[j-1] ? dp[i-1][j-1] + 1 : Math.max(dp[i-1][j], dp[i][j-1])
  const lcs = []
  let i = m, j = n
  while (i > 0 && j > 0) {
    if (A[i-1] === B[j-1]) { lcs.unshift(A[i-1]); i--; j-- }
    else if (dp[i-1][j] > dp[i][j-1]) i--
    else j--
  }
  return lcs
}

function DiffLines({ original, patched }) {
  const diff = computeDiff(original, patched)
  return (
    <div className="diff-lines">
      {diff.map((line, i) => (
        <div key={i} className={`diff-line ${line.type}`}>
          <span style={{ userSelect: 'none', color: 'var(--text-muted)', width: '2ch', display: 'inline-block', flexShrink: 0 }}>
            {line.type === 'added' ? '+' : line.type === 'removed' ? '-' : ' '}
          </span>
          <span>{line.text}</span>
        </div>
      ))}
    </div>
  )
}

export default function DiffViewer({ originalSource, candidates = [] }) {
  const [activeTab, setActiveTab] = useState(0)

  const candidate = candidates[activeTab]
  const patchSource = candidate?.patch_source || ''
  const gateResults = candidate?.gate_results || {}
  const gateNames = ['gate1', 'gate2', 'gate3', 'gate4', 'gate5']
  const gateLabels = ['Vuln Removed', 'Compiles', 'Signatures', 'KB Check', 'Fuzzing']

  return (
    <div className="panel right-top" style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
      <div className="panel-header">
        <h2>Candidate Diff Viewer</h2>
        {candidates.length > 0 && (
          <div className="diff-tabs">
            {candidates.map((c, i) => (
              <div key={i} className={`diff-tab${activeTab === i ? ' active' : ''}`} onClick={() => setActiveTab(i)}>
                {c.strategy || `Candidate ${i + 1}`}
                {c.all_gates_passed != null && (
                  <span style={{ marginLeft: '.3rem', color: c.all_gates_passed ? 'var(--green)' : 'var(--red)' }}>
                    {c.all_gates_passed ? '✓' : '✗'}
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {candidates.length === 0 ? (
        <div className="empty">No candidates yet</div>
      ) : (
        <>
          {/* Gate results for this candidate */}
          <div style={{ display: 'flex', gap: '.5rem', padding: '0 0 .5rem', flexWrap: 'wrap' }}>
            {gateNames.map((g, i) => {
              const v = gateResults[g]
              return (
                <span key={g} style={{
                  fontSize: '.72rem', padding: '.1rem .4rem', borderRadius: 4,
                  background: v === true ? '#0d2419' : v === false ? '#2d1010' : 'var(--surface2)',
                  color: v === true ? 'var(--green)' : v === false ? 'var(--red)' : 'var(--text-muted)',
                  border: `1px solid ${v === true ? 'var(--green)' : v === false ? 'var(--red)' : 'var(--border)'}`,
                }}>
                  G{i + 1} {gateLabels[i]} {v === true ? '✓' : v === false ? '✗' : '?'}
                </span>
              )
            })}
          </div>

          <div className="diff-scroller" style={{ flex: 1, overflow: 'auto' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1px', background: 'var(--border)' }}>
              <div>
                <div className="diff-col-header">Original</div>
                <div className="diff-lines">
                  {(originalSource || '').split('\n').map((l, i) => (
                    <div key={i} className="diff-line same"><span>{l}</span></div>
                  ))}
                </div>
              </div>
              <div>
                <div className="diff-col-header">
                  {candidate?.strategy || `Candidate ${activeTab + 1}`}
                  {candidate?.flagged_for_review && (
                    <span style={{ marginLeft: '.5rem', fontSize: '.7rem', color: 'var(--yellow)' }}>⚠ flagged</span>
                  )}
                </div>
                <DiffLines original={originalSource} patched={patchSource} />
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
