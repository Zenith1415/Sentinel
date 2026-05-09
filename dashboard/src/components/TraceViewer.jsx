import React, { useState, useEffect } from 'react'

const API = ''

const RUN_TYPE_COLOR = {
  llm:       'var(--blue)',
  chain:     'var(--green)',
  tool:      'var(--yellow)',
  retriever: 'var(--cyan)',
  embedding: 'var(--text-muted)',
}

const STATUS_ICON = {
  success: '✓',
  error:   '✗',
  running: '⟳',
}

function LatencyBar({ ms, maxMs }) {
  const pct = maxMs > 0 ? Math.min((ms / maxMs) * 100, 100) : 0
  const color = ms > 5000 ? 'var(--red)' : ms > 1500 ? 'var(--yellow)' : 'var(--green)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flex: 1, minWidth: 0 }}>
      <div style={{
        height: 6, borderRadius: 3, flex: 1,
        background: 'var(--border)',
        position: 'relative', overflow: 'hidden',
      }}>
        <div style={{ position: 'absolute', left: 0, top: 0, height: '100%', width: `${pct}%`, background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontSize: '.7rem', color: 'var(--text-muted)', whiteSpace: 'nowrap', minWidth: 44, textAlign: 'right' }}>
        {ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`}
      </span>
    </div>
  )
}

export default function TraceViewer({ pipelineId, pipelineStatus }) {
  const [trace,   setTrace]   = useState(null)
  const [error,   setError]   = useState(null)
  const [loading, setLoading] = useState(false)
  const [expanded, setExpanded] = useState({})

  const fetchTrace = async () => {
    if (!pipelineId) return
    setLoading(true)
    setError(null)
    try {
      const r = await fetch(`${API}/pipeline/${pipelineId}/trace`)
      if (!r.ok) {
        const e = await r.json().catch(() => ({}))
        throw new Error(e.detail || `HTTP ${r.status}`)
      }
      setTrace(await r.json())
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  // Live trace updates: poll every 2.5s while pipeline is running, then fetch once on completion
  useEffect(() => {
    if (!pipelineId) {
      setTrace(null)
      return
    }
    if (pipelineStatus === 'complete' || pipelineStatus === 'rolled_back' || pipelineStatus === 'error') {
      fetchTrace()
      return
    }
    if (pipelineStatus === 'running' || pipelineStatus === 'starting' || pipelineStatus === 'monitoring') {
      // Live polling — show prompts/responses + agent orchestration as they happen
      fetchTrace()
      const interval = setInterval(fetchTrace, 2500)
      return () => clearInterval(interval)
    }
  }, [pipelineStatus, pipelineId])

  const maxMs = trace
    ? Math.max(...(trace.spans || []).map(s => s.latency_ms), 1)
    : 1

  const toggle = id => setExpanded(p => ({ ...p, [id]: !p[id] }))

  // Group spans by run_type for the summary bar
  const grouped = (trace?.spans || []).reduce((acc, s) => {
    acc[s.run_type] = (acc[s.run_type] || 0) + 1
    return acc
  }, {})

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>LangSmith Trace</h2>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {(pipelineStatus === 'running' || pipelineStatus === 'starting' || pipelineStatus === 'monitoring') && (
            <span style={{
              fontSize: '.62rem',
              padding: '1px 6px',
              borderRadius: 8,
              background: 'var(--green)',
              color: '#000',
              fontWeight: 700,
              animation: 'pulse 1.5s ease-in-out infinite',
            }}>
              ● LIVE
            </span>
          )}
          {trace && (
            <a
              href={trace.langsmith_url}
              target="_blank"
              rel="noreferrer"
              style={{
                fontSize: '.72rem', padding: '2px 8px',
                background: 'var(--blue)', color: '#fff',
                borderRadius: 4, textDecoration: 'none',
                fontWeight: 600,
              }}
            >
              Open ↗
            </a>
          )}
          <button
            className="btn"
            style={{ padding: '2px 10px', fontSize: '.72rem' }}
            onClick={fetchTrace}
            disabled={loading || !pipelineId}
          >
            {loading ? '⟳' : '↻ Refresh'}
          </button>
        </div>
      </div>

      {!pipelineId && (
        <span className="empty">Start a pipeline to see traces.</span>
      )}

      {error && (
        <div style={{ color: 'var(--red)', fontSize: '.78rem', padding: '6px 0' }}>
          {error.includes('not configured') || error.includes('LANGCHAIN_API_KEY')
            ? <>Set <code>LANGCHAIN_API_KEY</code> and <code>LANGCHAIN_TRACING_V2=true</code> in your <code>.env</code>, then restart the server.</>
            : error.includes('invalid or expired') || error.includes('401')
            ? <>LangSmith key expired — <strong>smith.langchain.com → Settings → API Keys</strong> → create new key → update <code>.env</code> → restart server.</>
            : error.includes('not uploaded') || error.includes('404') || error.includes('not found')
            ? <>Trace not found — the pipeline ran before tracing was active. <strong>Run a new pipeline</strong> to generate a fresh trace.</>
            : error}
        </div>
      )}

      {trace && (
        <>
          {/* Summary chips */}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
            {Object.entries(grouped).map(([type, count]) => (
              <span key={type} style={{
                fontSize: '.68rem', padding: '1px 7px', borderRadius: 10,
                background: 'var(--bg-panel)', border: `1px solid ${RUN_TYPE_COLOR[type] || 'var(--border)'}`,
                color: RUN_TYPE_COLOR[type] || 'var(--text-muted)',
              }}>
                {type} × {count}
              </span>
            ))}
            {trace.total_tokens > 0 && (
              <span style={{ fontSize: '.68rem', padding: '1px 7px', borderRadius: 10, background: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-muted)' }}>
                {trace.total_tokens.toLocaleString()} tokens
              </span>
            )}
          </div>

          {/* Span rows */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {trace.spans.length === 0 && (
              <span className="empty">No child spans yet — pipeline may still be running.</span>
            )}
            {trace.spans.map((span, i) => {
              const typeColor = RUN_TYPE_COLOR[span.run_type] || 'var(--text-muted)'
              const icon      = STATUS_ICON[span.status] || '·'
              const isError   = span.status === 'error'
              const open      = expanded[span.run_id]
              return (
                <div key={span.run_id || i}>
                  <div
                    onClick={() => toggle(span.run_id)}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '14px 120px 1fr 80px',
                      alignItems: 'center',
                      gap: 8,
                      padding: '3px 4px',
                      borderRadius: 4,
                      cursor: 'pointer',
                      background: open ? 'var(--bg-panel)' : 'transparent',
                    }}
                  >
                    <span style={{ color: isError ? 'var(--red)' : 'var(--green)', fontSize: '.75rem' }}>{icon}</span>
                    <span style={{
                      fontSize: '.72rem',
                      color: typeColor,
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      fontFamily: 'monospace',
                    }} title={span.name}>
                      {span.name}
                    </span>
                    <LatencyBar ms={span.latency_ms} maxMs={maxMs} />
                    <span style={{ fontSize: '.65rem', color: 'var(--text-muted)', textAlign: 'right' }}>
                      {span.tokens_in + span.tokens_out > 0
                        ? `${span.tokens_in}↑ ${span.tokens_out}↓`
                        : span.run_type}
                    </span>
                  </div>

                  {open && (
                    <div style={{
                      margin: '2px 0 6px 22px',
                      padding: '8px 10px',
                      background: 'var(--bg-panel)',
                      borderRadius: 4,
                      fontSize: '.7rem',
                      color: 'var(--text-muted)',
                      fontFamily: 'monospace',
                    }}>
                      <div style={{ marginBottom: 4 }}>
                        <strong>type:</strong> {span.run_type} · <strong>status:</strong> {span.status}
                        {span.latency_ms > 0 && <> · <strong>latency:</strong> {span.latency_ms}ms</>}
                        {(span.tokens_in + span.tokens_out) > 0 && <> · <strong>tokens:</strong> {span.tokens_in}↑ {span.tokens_out}↓</>}
                      </div>
                      {span.start_time && <div style={{ marginBottom: 4 }}><strong>started:</strong> {new Date(span.start_time).toLocaleTimeString()}</div>}
                      {span.error && <div style={{ color: 'var(--red)', marginBottom: 4 }}><strong>error:</strong> {span.error}</div>}

                      {span.prompt && (
                        <div style={{ marginTop: 6 }}>
                          <div style={{ color: 'var(--blue)', marginBottom: 2 }}>▼ PROMPT</div>
                          <pre style={{
                            margin: 0, padding: '4px 6px',
                            background: 'rgba(0,128,255,0.06)',
                            border: '1px solid rgba(0,128,255,0.2)',
                            borderRadius: 3,
                            whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                            maxHeight: 240, overflowY: 'auto',
                            fontSize: '.68rem', color: 'var(--text)',
                          }}>{span.prompt}</pre>
                        </div>
                      )}
                      {span.response && (
                        <div style={{ marginTop: 6 }}>
                          <div style={{ color: 'var(--green)', marginBottom: 2 }}>▼ RESPONSE</div>
                          <pre style={{
                            margin: 0, padding: '4px 6px',
                            background: 'rgba(0,200,100,0.06)',
                            border: '1px solid rgba(0,200,100,0.2)',
                            borderRadius: 3,
                            whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                            maxHeight: 240, overflowY: 'auto',
                            fontSize: '.68rem', color: 'var(--text)',
                          }}>{span.response}</pre>
                        </div>
                      )}

                      <div style={{ marginTop: 6, opacity: 0.6 }}>
                        <strong>run_id:</strong> {span.run_id}
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}
