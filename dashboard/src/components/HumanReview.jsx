import React, { useState, useEffect } from 'react'

const API = ''

const SEV_COLOR = {
  Critical: 'var(--red)',
  High:     '#ff6b35',
  Medium:   'var(--yellow)',
  Low:      'var(--text-muted)',
}

export default function HumanReview({
  pipelineId,
  pipelineStatus,
  healingState,
  originalSource,
  onDeployed,
}) {
  const [open,        setOpen]        = useState(true)
  const [patch,       setPatch]       = useState('')
  const [explanation, setExplanation] = useState('')
  const [approver1,   setApprover1]   = useState('')
  const [approver2,   setApprover2]   = useState('')
  const [submitting,  setSubmitting]  = useState(false)
  const [error,       setError]       = useState(null)
  const [success,     setSuccess]     = useState(null)

  const findings = healingState?.all_findings || []
  const route    = healingState?.route || ''
  const isSlow   = route === 'slow' || (healingState?.retry_count || 0) >= 3
  const isComplete = pipelineStatus === 'complete' || pipelineStatus === 'error'
  const alreadyDeployed = healingState?.deployed === true

  // Pre-fill patch with original source when slow path triggers
  useEffect(() => {
    if (isSlow && isComplete && !patch) {
      setPatch(originalSource || '')
    }
  }, [isSlow, isComplete, originalSource])

  // Pre-fill explanation with the addressed vuln types
  useEffect(() => {
    if (isSlow && isComplete && !explanation && findings.length) {
      const types = [...new Set(findings.map(f => f.vuln_type))].slice(0, 6)
      setExplanation(`Manual patch addressing: ${types.join(', ')}.`)
    }
  }, [isSlow, isComplete, findings.length])

  if (!isSlow || !isComplete || alreadyDeployed) return null

  const submit = async () => {
    setError(null)
    setSuccess(null)
    if (!approver1.trim() || !approver2.trim()) {
      setError('Both approvers are required.')
      return
    }
    if (approver1.trim() === approver2.trim()) {
      setError('Approvers must be two different people.')
      return
    }
    if (!patch.trim() || !patch.includes('pragma solidity')) {
      setError('Patch must be a valid Solidity contract (must include pragma).')
      return
    }

    setSubmitting(true)
    try {
      const r = await fetch(`${API}/pipeline/${pipelineId}/manual-deploy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          patch_source:    patch,
          explanation:     explanation,
          approver_1:      approver1.trim(),
          approver_2:      approver2.trim(),
          addressed_vulns: [...new Set(findings.map(f => f.vuln_type))],
        }),
      })

      if (!r.ok) {
        const e = await r.json().catch(() => ({}))
        throw new Error(e.detail || `HTTP ${r.status}`)
      }

      const result = await r.json()
      setSuccess(`✓ Deployed manually. tx: ${result.tx_hash.slice(0, 24)}…`)
      onDeployed?.(result)
    } catch (e) {
      setError(e.message || 'Manual deploy failed.')
    } finally {
      setSubmitting(false)
    }
  }

  // Group findings by severity for the review checklist
  const grouped = findings.reduce((acc, f) => {
    const s = f.severity || 'Unknown'
    if (!acc[s]) acc[s] = []
    acc[s].push(f)
    return acc
  }, {})

  return (
    <div className="panel" style={{ borderLeft: '3px solid #ff6b35' }}>
      <div className="panel-header">
        <h2>👨‍💻 Human Review & Deploy</h2>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{
            fontSize: '.62rem', padding: '2px 8px', borderRadius: 8,
            background: '#ff6b35', color: '#000', fontWeight: 700,
          }}>
            SLOW PATH — REVIEW REQUIRED
          </span>
          <button
            className="btn"
            style={{ padding: '2px 8px', fontSize: '.7rem' }}
            onClick={() => setOpen(!open)}
          >
            {open ? '▼' : '▶'}
          </button>
        </div>
      </div>

      {open && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {/* Step 1: review findings */}
          <div>
            <div style={{ fontSize: '.78rem', fontWeight: 600, marginBottom: 4, color: 'var(--text)' }}>
              1. Review findings ({findings.length})
            </div>
            <div style={{
              maxHeight: 160, overflowY: 'auto',
              border: '1px solid var(--border)', borderRadius: 4,
              padding: '6px 8px', background: 'var(--bg-panel)',
            }}>
              {findings.length === 0 ? (
                <span className="empty">No findings recorded.</span>
              ) : (
                ['Critical', 'High', 'Medium', 'Low'].map(sev => (
                  grouped[sev] && (
                    <div key={sev} style={{ marginBottom: 6 }}>
                      <div style={{ fontSize: '.7rem', fontWeight: 700, color: SEV_COLOR[sev] }}>
                        {sev} ({grouped[sev].length})
                      </div>
                      {grouped[sev].map((f, i) => (
                        <div key={i} style={{
                          fontSize: '.7rem', color: 'var(--text-muted)',
                          paddingLeft: 8, marginBottom: 2,
                        }}>
                          • <strong style={{ color: 'var(--text)' }}>{f.vuln_type}</strong>
                          {' '}in <code>{f.affected_function}</code>
                          {f.cross_contract_flag && (
                            <span style={{ color: 'var(--red)', marginLeft: 4 }}>[cross-contract]</span>
                          )}
                          {' — '}{f.fix_recommendation || ''}
                        </div>
                      ))}
                    </div>
                  )
                ))
              )}
            </div>
          </div>

          {/* Step 2: write/paste patch */}
          <div>
            <div style={{ fontSize: '.78rem', fontWeight: 600, marginBottom: 4, color: 'var(--text)' }}>
              2. Write or paste the manual patch (Solidity)
            </div>
            <textarea
              value={patch}
              onChange={e => setPatch(e.target.value)}
              placeholder="// SPDX-License-Identifier: MIT&#10;pragma solidity ^0.8.22;&#10;&#10;contract PatchedVault { … }"
              style={{
                width: '100%',
                minHeight: 200,
                padding: 8,
                fontFamily: 'monospace',
                fontSize: '.72rem',
                background: 'var(--bg-panel)',
                color: 'var(--text)',
                border: '1px solid var(--border)',
                borderRadius: 4,
                resize: 'vertical',
              }}
            />
          </div>

          {/* Step 3: explanation */}
          <div>
            <div style={{ fontSize: '.78rem', fontWeight: 600, marginBottom: 4, color: 'var(--text)' }}>
              3. Explanation (what you changed and why)
            </div>
            <textarea
              value={explanation}
              onChange={e => setExplanation(e.target.value)}
              placeholder="Explain the fixes applied — e.g. 'CEI pattern in withdraw(), added nonReentrant on flashLoan(), redesigned governance with 2-day timelock + 2-of-3 multisig.'"
              style={{
                width: '100%',
                minHeight: 56,
                padding: 8,
                fontSize: '.72rem',
                background: 'var(--bg-panel)',
                color: 'var(--text)',
                border: '1px solid var(--border)',
                borderRadius: 4,
                resize: 'vertical',
              }}
            />
          </div>

          {/* Step 4: 2-of-2 approvers */}
          <div>
            <div style={{ fontSize: '.78rem', fontWeight: 600, marginBottom: 4, color: 'var(--text)' }}>
              4. Two distinct approvers (multi-sig)
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <input
                value={approver1}
                onChange={e => setApprover1(e.target.value)}
                placeholder="approver 1 (e.g. alice@team)"
                style={{ flex: 1, padding: 6, fontSize: '.72rem',
                         background: 'var(--bg-panel)', color: 'var(--text)',
                         border: '1px solid var(--border)', borderRadius: 4 }}
              />
              <input
                value={approver2}
                onChange={e => setApprover2(e.target.value)}
                placeholder="approver 2 (e.g. bob@team)"
                style={{ flex: 1, padding: 6, fontSize: '.72rem',
                         background: 'var(--bg-panel)', color: 'var(--text)',
                         border: '1px solid var(--border)', borderRadius: 4 }}
              />
            </div>
          </div>

          {/* Submit */}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <button
              className="btn"
              style={{
                background: '#ff6b35',
                color: '#000',
                border: '1px solid #ff6b35',
                fontWeight: 700,
                padding: '6px 14px',
                fontSize: '.78rem',
              }}
              onClick={submit}
              disabled={submitting}
            >
              {submitting ? '⟳ Deploying…' : '✓ Approve & Deploy Manual Patch'}
            </button>
            <button
              className="btn"
              style={{ padding: '6px 12px', fontSize: '.72rem' }}
              onClick={() => setPatch(originalSource || '')}
              disabled={submitting}
            >
              Reset patch
            </button>
            <span style={{ fontSize: '.65rem', color: 'var(--text-muted)' }}>
              Both approvers must be distinct. Patch must compile and address listed vulnerabilities.
            </span>
          </div>

          {error && (
            <div style={{
              fontSize: '.72rem', padding: '6px 8px', borderRadius: 4,
              border: '1px solid var(--red)', color: 'var(--red)',
              background: 'rgba(255,0,0,0.05)',
            }}>
              {error}
            </div>
          )}
          {success && (
            <div style={{
              fontSize: '.72rem', padding: '6px 8px', borderRadius: 4,
              border: '1px solid var(--green)', color: 'var(--green)',
              background: 'rgba(0,200,100,0.05)',
            }}>
              {success}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
