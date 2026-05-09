import React, { useEffect, useRef, useState } from 'react'

// Color palette matching the CLI demo_runner output
const COLORS = {
  detect:    '#85B7EB',   // blue
  correlate: '#9FE1CB',   // green
  route:     '#FAC775',   // yellow
  patch:     '#FAC775',   // yellow
  validate:  '#C0DD97',   // light green
  deploy:    '#9FE1CB',   // green
  monitor:   '#85B7EB',   // blue
  slow_path: '#F09595',   // red
  failed:    '#F09595',   // red
  ManualDeploy: '#ED93B1', // pink
  RollbackTriggered: '#F09595',
}

const RESET = 'var(--text)'
const MUTED = 'var(--text-muted)'
const RED   = '#F09595'
const GREEN = '#9FE1CB'
const YEL   = '#FAC775'
const BLU   = '#85B7EB'

const NODE_LABELS = {
  detect:    'detect    ',
  correlate: 'correlate ',
  route:     'route     ',
  patch:     'patch     ',
  validate:  'validate  ',
  deploy:    'deploy    ',
  monitor:   'monitor   ',
  slow_path: 'slow_path ',
  failed:    'failed    ',
  ManualDeploy: 'manual_deploy',
  RollbackTriggered: 'rollback  ',
}

function fmtTs(ts) {
  const d = new Date(ts)
  return d.toLocaleTimeString('en-GB', { hour12: false }) +
    '.' + String(d.getMilliseconds()).padStart(3, '0')
}

function Line({ children, color = RESET }) {
  return (
    <div style={{
      whiteSpace: 'pre-wrap',
      wordBreak: 'break-word',
      fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace',
      fontSize: '.7rem',
      lineHeight: 1.5,
      color,
    }}>
      {children}
    </div>
  )
}

function NodeBadge({ node }) {
  const color = COLORS[node] || MUTED
  const label = NODE_LABELS[node] || node.padEnd(10)
  return (
    <span style={{ color }}>[{label}]</span>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Render a single event as one or more CLI-style lines
// ─────────────────────────────────────────────────────────────────────────────

function renderEvent(event, index, prevState) {
  const { node, state = {}, ts } = event
  const time = fmtTs(ts)
  const lines = []

  if (node === 'detect') {
    const counts = {
      static:     (state.static_findings || []).length,
      symbolic:   (state.symbolic_findings || []).length,
      semantic:   (state.semantic_findings || []).length,
      governance: (state.governance_findings || []).length,
      threat:     (state.threat_findings || []).length,
    }
    // all_findings is populated AFTER correlate/dedup; at the detect event
    // boundary it may still be empty. Sum the per-agent counts so the header
    // never contradicts the per-agent breakdown printed below.
    const total = Object.values(counts).reduce((a, b) => a + b, 0)
    lines.push(
      <Line key={`${index}-h`}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <NodeBadge node={node} /> {total} total findings across 5 agents
      </Line>
    )
    Object.entries(counts).forEach(([agent, n], i) => {
      const color = n > 0 ? GREEN : MUTED
      lines.push(
        <Line key={`${index}-${i}`} color={color}>
          {'              '}↳ Agent {agent.padEnd(11)} {n} finding{n === 1 ? '' : 's'}
        </Line>
      )
    })
  }

  else if (node === 'correlate') {
    const route = state.route || '?'
    const conf  = state.confidence_score || 0
    const conflicts = (state.conflict_flags || []).length
    const routeColor = route === 'slow' ? RED : route === 'fast' ? GREEN : YEL
    lines.push(
      <Line key={`${index}-h`}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <NodeBadge node={node} /> route=<strong style={{ color: routeColor }}>{route.toUpperCase()}</strong>{'  '}
        confidence=<strong style={{ color: conf >= 0.65 ? GREEN : conf >= 0.30 ? YEL : RED }}>
          {(conf * 100).toFixed(1)}%
        </strong>{'  '}
        conflicts={conflicts}
      </Line>
    )
    if (route === 'slow') {
      lines.push(
        <Line key={`${index}-r`} color={RED}>
          {'              '}↳ Will escalate to slow path — auto-patch capability exceeded
        </Line>
      )
    } else if (route === 'fast') {
      lines.push(
        <Line key={`${index}-r`} color={GREEN}>
          {'              '}↳ Fast path — low-risk patch, full validation still runs
        </Line>
      )
    } else {
      lines.push(
        <Line key={`${index}-r`} color={YEL}>
          {'              '}↳ Medium path — Critical findings present, full validation gates required
        </Line>
      )
    }
  }

  else if (node === 'route') {
    lines.push(
      <Line key={`${index}-h`} color={MUTED}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <NodeBadge node={node} /> dispatching to <strong style={{ color: state.route === 'slow' ? RED : GREEN }}>{state.route}</strong> handler
      </Line>
    )
  }

  else if (node === 'patch') {
    const candidates = state.candidate_patches || []
    lines.push(
      <Line key={`${index}-h`}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <NodeBadge node={node} /> generated {candidates.length} candidate patch{candidates.length === 1 ? '' : 'es'} in parallel
      </Line>
    )
    candidates.forEach((c, i) => {
      const flagged = c.flagged_for_review
      const reasons = (c.flag_reasons || []).join(', ')
      const color = flagged ? RED : GREEN
      const icon  = flagged ? '✗' : '✓'
      lines.push(
        <Line key={`${index}-c-${i}`} color={color}>
          {'              '}{icon} candidate[{i + 1}] strategy=<strong>{c.strategy}</strong>
          {flagged && ` — flagged: ${reasons}`}
        </Line>
      )
    })
  }

  else if (node === 'validate') {
    // On success the validator copies the winning candidate's gates to
    // top-level `gate_results`. On failure it doesn't — fall back to the
    // first candidate's per-candidate gate_results so the breakdown is
    // visible in the failure case too.
    let gates = state.gate_results || {}
    if (Object.keys(gates).length === 0) {
      const cands = state.candidate_patches || []
      if (cands.length > 0) gates = cands[0].gate_results || {}
    }
    const passed = Object.values(gates).filter(Boolean).length
    const total  = Object.keys(gates).length
    const ok     = state.validation_passed
    const retry  = state.retry_count || 0
    const color  = ok ? GREEN : RED
    lines.push(
      <Line key={`${index}-h`}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <NodeBadge node={node} /> {passed}/{total} gates{' '}
        <strong style={{ color }}>{ok ? 'PASS' : 'FAIL'}</strong>
        {retry > 0 && <span style={{ color: YEL }}>{'  '}retry={retry}/3</span>}
      </Line>
    )
    const labels = {
      gate1: 'vuln removed',
      gate2: 'compiles',
      gate3: 'signatures preserved',
      gate4: 'KB bad-fix check',
      gate5: 'fuzzing (Echidna+Foundry)',
      manual_review: 'human approved',
    }
    Object.entries(gates).forEach(([g, v], i) => {
      const c = v ? GREEN : RED
      const ic = v ? '✓' : '✗'
      lines.push(
        <Line key={`${index}-g-${i}`} color={c}>
          {'              '}{ic} {(labels[g] || g).padEnd(28)}
        </Line>
      )
    })
  }

  else if (node === 'deploy') {
    const tx = state.tx_hash || ''
    const rb = state.rollback_target || ''
    lines.push(
      <Line key={`${index}-h`} color={GREEN}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <NodeBadge node={node} /> deployed via UUPS proxy upgrade
      </Line>
    )
    if (tx) lines.push(
      <Line key={`${index}-tx`} color={MUTED}>
        {'              '}↳ tx_hash:        <span style={{ color: BLU }}>{tx.slice(0, 24)}…</span>
      </Line>
    )
    if (rb) lines.push(
      <Line key={`${index}-rb`} color={MUTED}>
        {'              '}↳ rollback_target: <span style={{ color: BLU }}>{rb.slice(0, 24)}…</span>
      </Line>
    )
  }

  else if (node === 'monitor') {
    const rl = state.rl_reward || 0
    lines.push(
      <Line key={`${index}-h`}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <NodeBadge node={node} /> post-deploy watch — no anomalies detected{'  '}
        rl_reward=<strong style={{ color: rl >= 0 ? GREEN : RED }}>{rl >= 0 ? '+' : ''}{rl.toFixed(2)}</strong>
      </Line>
    )
  }

  else if (node === 'slow_path') {
    lines.push(
      <Line key={`${index}-h`} color={RED}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <NodeBadge node={node} /> ⛔ ESCALATED TO HUMAN REVIEW
      </Line>
    )
    if (state.error) lines.push(
      <Line key={`${index}-e`} color={RED}>
        {'              '}↳ {state.error.slice(0, 200)}{state.error.length > 200 ? '…' : ''}
      </Line>
    )
  }

  else if (node === 'failed') {
    lines.push(
      <Line key={`${index}-h`} color={RED}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <NodeBadge node={node} /> ✗ pipeline failed
      </Line>
    )
    if (state.error) lines.push(
      <Line key={`${index}-e`} color={RED}>
        {'              '}↳ {state.error}
      </Line>
    )
  }

  else if (node === 'ManualDeploy') {
    lines.push(
      <Line key={`${index}-h`} color={COLORS.ManualDeploy}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <NodeBadge node={node} /> human-approved deployment{state.tx_hash && ` — tx ${state.tx_hash.slice(0, 24)}…`}
      </Line>
    )
  }

  else if (node === 'RollbackTriggered') {
    lines.push(
      <Line key={`${index}-h`} color={RED}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <NodeBadge node={node} /> ⚠ AUTO-ROLLBACK fired
      </Line>
    )
    const anomalies = event.anomalies || []
    anomalies.forEach((a, i) => {
      lines.push(
        <Line key={`${index}-a-${i}`} color={RED}>
          {'              '}↳ {a.type || 'anomaly'} on {a.function || 'unknown'} ({a.severity || 'high'})
        </Line>
      )
    })
  }

  else if (node === '__done__') {
    const healed = state.healed
    const dep    = state.deployed
    if (healed) {
      lines.push(
        <Line key={`${index}-h`} color={GREEN}>
          <span style={{ color: MUTED }}>{time}</span>{' '}
          <strong>✓ HEALED</strong> — pipeline complete, contract patched & deployed
        </Line>
      )
    } else if (dep) {
      lines.push(
        <Line key={`${index}-h`} color={GREEN}>
          <span style={{ color: MUTED }}>{time}</span>{' '}
          <strong>✓ Pipeline complete</strong>
        </Line>
      )
    } else {
      lines.push(
        <Line key={`${index}-h`} color={YEL}>
          <span style={{ color: MUTED }}>{time}</span>{' '}
          <strong>⏸ Pipeline complete — escalated to human review (slow path)</strong>
        </Line>
      )
    }
  }

  else if (node === '__error__') {
    lines.push(
      <Line key={`${index}-h`} color={RED}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <strong>✗ Pipeline crashed:</strong> {event.error}
      </Line>
    )
  }

  else if (node === '__rollback__') {
    lines.push(
      <Line key={`${index}-h`} color={RED}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <strong>⚠ ROLLBACK COMPLETE</strong> — implementation reverted to {state.rollback_target?.slice(0, 24)}…
      </Line>
    )
  }

  else {
    lines.push(
      <Line key={`${index}-h`} color={MUTED}>
        <span style={{ color: MUTED }}>{time}</span>{' '}
        <NodeBadge node={node} /> {JSON.stringify(state).slice(0, 80)}
      </Line>
    )
  }

  return lines
}


export default function CliConsole({ events = [], pipelineId, pipelineStatus }) {
  const scrollRef = useRef(null)
  const [autoScroll, setAutoScroll] = useState(true)

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [events.length, autoScroll])

  const onScroll = () => {
    const el = scrollRef.current
    if (!el) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30
    setAutoScroll(atBottom)
  }

  const isLive = pipelineStatus === 'running' || pipelineStatus === 'starting' || pipelineStatus === 'monitoring'

  return (
    <div className="panel" style={{ flex: '1 1 auto', display: 'flex', flexDirection: 'column' }}>
      <div className="panel-header">
        <h2>📟 Live Pipeline Console</h2>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {isLive && (
            <span style={{
              fontSize: '.62rem', padding: '1px 6px', borderRadius: 8,
              background: '#9FE1CB', color: '#000', fontWeight: 700,
              animation: 'pulse 1.5s ease-in-out infinite',
            }}>
              ● STREAMING
            </span>
          )}
          <span className="tag">{events.length} events</span>
          <span style={{ fontSize: '.62rem', color: 'var(--text-muted)' }}>
            {autoScroll ? '↓ auto-scroll' : '⏸ paused'}
          </span>
        </div>
      </div>

      <div
        ref={scrollRef}
        onScroll={onScroll}
        style={{
          flex: '1 1 auto',
          minHeight: 280,
          maxHeight: 480,
          overflowY: 'auto',
          background: '#0a0a0e',
          border: '1px solid var(--border)',
          borderRadius: 4,
          padding: '8px 10px',
          fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace',
        }}
      >
        {events.length === 0 ? (
          <Line color={MUTED}>
            <span style={{ color: GREEN }}>$</span> awaiting pipeline submission… start a heal to see live agent activity, LLM calls, and gate results stream here
          </Line>
        ) : (
          events.flatMap((e, i) => renderEvent(e, i))
        )}
        {isLive && events.length > 0 && (
          <Line color={GREEN}>
            <span style={{ animation: 'pulse 1s ease-in-out infinite' }}>▌</span>
          </Line>
        )}
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50%      { opacity: 0.4; }
        }
      `}</style>
    </div>
  )
}
