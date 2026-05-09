import React, { useState, useEffect } from 'react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ReferenceLine, ResponsiveContainer, Legend,
} from 'recharts'

const API = ''

const PHASE_COLOR = {
  simulation: 'var(--yellow)',
  shadow:     'var(--blue)',
  live:       'var(--green)',
}

export default function RLLearningCurve() {
  const [data,    setData]    = useState([])
  const [loading, setLoading] = useState(false)

  const fetchCurve = async () => {
    setLoading(true)
    try {
      const r = await fetch(`${API}/rl/learning-curve`)
      if (r.ok) {
        const raw = await r.json()
        setData(raw.map((d, i) => ({
          ...d,
          index: i + 1,
          label: new Date(d.timestamp).toLocaleTimeString(),
        })))
      }
    } catch {}
    setLoading(false)
  }

  useEffect(() => { fetchCurve() }, [])

  // Find phase-change boundaries for reference lines
  const phaseChanges = []
  for (let i = 1; i < data.length; i++) {
    if (data[i].phase !== data[i - 1].phase) {
      phaseChanges.push({ index: data[i].index, phase: data[i].phase })
    }
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>RL Learning Curve</h2>
        <button
          className="btn"
          style={{ padding: '2px 10px', fontSize: '.72rem' }}
          onClick={fetchCurve}
          disabled={loading}
        >
          {loading ? '⟳' : '↻ Refresh'}
        </button>
      </div>

      {data.length === 0 ? (
        <span className="empty">No RL reward data yet — run a pipeline first.</span>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={data} margin={{ top: 4, right: 12, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis
              dataKey="index"
              tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
              label={{ value: 'Run #', position: 'insideBottomRight', offset: -4, fontSize: 10, fill: 'var(--text-muted)' }}
            />
            <YAxis
              tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
              label={{ value: 'Reward', angle: -90, position: 'insideLeft', fontSize: 10, fill: 'var(--text-muted)' }}
            />
            <Tooltip
              contentStyle={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 6, fontSize: '.75rem' }}
              labelFormatter={(i) => `Run ${i}`}
              formatter={(v, n) => [v.toFixed(3), 'Cumulative Reward']}
            />
            {phaseChanges.map(({ index, phase }) => (
              <ReferenceLine
                key={index}
                x={index}
                stroke={PHASE_COLOR[phase] || 'var(--text-muted)'}
                strokeDasharray="4 2"
                label={{ value: phase, position: 'top', fontSize: 9, fill: PHASE_COLOR[phase] || 'var(--text-muted)' }}
              />
            ))}
            <Line
              type="monotone"
              dataKey="cumulative_reward"
              stroke="var(--green)"
              strokeWidth={2}
              dot={false}
              name="Cumulative Reward"
            />
          </LineChart>
        </ResponsiveContainer>
      )}

      {/* Phase legend */}
      <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
        {Object.entries(PHASE_COLOR).map(([phase, color]) => (
          <span key={phase} style={{ fontSize: '.68rem', color }}>
            ── {phase}
          </span>
        ))}
      </div>
    </div>
  )
}
