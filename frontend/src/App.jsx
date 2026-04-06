import { useState, useRef, useEffect, useCallback } from 'react'
import './index.css'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000'
const WS_BASE  = API_BASE.replace(/^http/, 'ws')

function App() {
  // ---- State ----
  const [challengeText, setChallengeText]   = useState('')
  const [file, setFile]                     = useState(null)
  const [status, setStatus]                 = useState('idle')   // idle | processing | needs_human | solved
  const [logs, setLogs]                     = useState([])
  const [flag, setFlag]                     = useState('')
  const [challengeId, setChallengeId]       = useState(null)
  const [category, setCategory]             = useState('')
  const [wsConnected, setWsConnected]       = useState(false)
  const [categories, setCategories]         = useState([])

  const terminalEndRef = useRef(null)
  const wsRef          = useRef(null)
  const reconnectRef   = useRef(null)

  // ---- Scroll terminal ----
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  // ---- Fetch available categories on mount ----
  useEffect(() => {
    fetch(`${API_BASE}/api/categories`)
      .then(r => r.json())
      .then(data => setCategories(data.categories || []))
      .catch(() => setCategories(['forensics', 'crypto', 'osint', 'web', 'reversing', 'pwn', 'misc']))
  }, [])

  // ---- WebSocket connection ----
  const connectWs = useCallback((id) => {
    if (wsRef.current) {
      wsRef.current.close()
    }

    const ws = new WebSocket(`${WS_BASE}/ws/logs/${id}`)

    ws.onopen = () => setWsConnected(true)

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        setLogs(prev => [...prev, {
          role: data.role,
          message: data.message,
          time: data.time ? new Date(data.time).toLocaleTimeString() : new Date().toLocaleTimeString(),
        }])

        // Update local status based on log roles
        if (data.role === 'agent_success') {
          // Extract flag from the message
          const match = data.message.match(/(?:flag\{[^}]+\})/i)
          if (match) setFlag(match[0])
          setStatus('solved')
        } else if (data.role === 'agent_plan') {
          setStatus('needs_human')
        }
      } catch { /* ignore malformed messages */ }
    }

    ws.onclose = () => {
      setWsConnected(false)
      // Auto-reconnect after 3s if challenge is still active
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
      reconnectRef.current = setTimeout(() => {
        if (id && status !== 'idle' && status !== 'solved') {
          connectWs(id)
        }
      }, 3000)
    }

    ws.onerror = () => ws.close()
    wsRef.current = ws
  }, [status])

  // Clean up WS on unmount
  useEffect(() => {
    return () => {
      if (wsRef.current) wsRef.current.close()
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
    }
  }, [])

  // ---- Poll challenge status ----
  useEffect(() => {
    if (!challengeId || status === 'idle' || status === 'solved') return

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/challenge/${challengeId}`)
        const data = await res.json()
        const s = data.challenge?.status
        if (s === 'needs_human') setStatus('needs_human')
        else if (s === 'solved') {
          setStatus('solved')
          if (data.challenge.flag) setFlag(data.challenge.flag)
        }
        else if (s === 'idle') setStatus('idle')
        if (data.challenge?.category) setCategory(data.challenge.category)
      } catch { /* ignore polling errors */ }
    }, 2000)

    return () => clearInterval(interval)
  }, [challengeId, status])

  // ---- Submit Challenge ----
  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!challengeText.trim()) return

    setStatus('processing')
    setLogs([])
    setFlag('')
    setCategory('')

    const formData = new FormData()
    formData.append('question', challengeText)
    if (file) formData.append('file', file)

    try {
      const res = await fetch(`${API_BASE}/api/challenge`, {
        method: 'POST',
        body: formData,
      })
      const data = await res.json()
      setChallengeId(data.id)
      connectWs(data.id)
    } catch (err) {
      setLogs(prev => [...prev, {
        role: 'system',
        message: `Connection error: ${err.message}. Is the backend running?`,
        time: new Date().toLocaleTimeString(),
      }])
      setStatus('idle')
    }
  }

  // ---- Approve ----
  const handleApprove = async () => {
    setStatus('processing')
    try {
      await fetch(`${API_BASE}/api/challenge/${challengeId}/approve`, { method: 'POST' })
    } catch (err) {
      setLogs(prev => [...prev, {
        role: 'system',
        message: `Approval error: ${err.message}`,
        time: new Date().toLocaleTimeString(),
      }])
    }
  }

  // ---- Reject ----
  const handleReject = async () => {
    try {
      await fetch(`${API_BASE}/api/challenge/${challengeId}/reject`, { method: 'POST' })
      setStatus('idle')
    } catch (err) {
      setLogs(prev => [...prev, {
        role: 'system',
        message: `Rejection error: ${err.message}`,
        time: new Date().toLocaleTimeString(),
      }])
    }
  }

  // ---- Reset ----
  const handleReset = () => {
    if (wsRef.current) wsRef.current.close()
    setStatus('idle')
    setLogs([])
    setChallengeText('')
    setFile(null)
    setFlag('')
    setChallengeId(null)
    setCategory('')
  }

  // ---- Status badge class ----
  const statusClass = {
    idle: 'status-idle',
    processing: 'status-processing',
    needs_human: 'status-needs-human',
    solved: 'status-solved',
  }[status] || 'status-idle'

  // ---- Tag renderer ----
  const renderTag = (role) => {
    const tags = {
      system:        { cls: 'tag-system',   label: 'SYSTEM' },
      agent:         { cls: 'tag-agent',    label: 'SENTINEL-AI' },
      agent_plan:    { cls: 'tag-plan',     label: 'ATTACK PLAN' },
      agent_success: { cls: 'tag-success',  label: 'FLAG FOUND' },
      terminal:      { cls: 'tag-terminal', label: 'root@kali:~#' },
    }
    const t = tags[role] || { cls: 'tag-system', label: role.toUpperCase() }
    return <span className={`log-tag ${t.cls}`}>[{t.label}]</span>
  }

  const msgClass = (role) => {
    if (role === 'terminal')      return 'log-message msg-terminal'
    if (role === 'agent_plan')    return 'log-message msg-plan'
    if (role === 'agent_success') return 'log-message msg-success'
    return 'log-message'
  }

  return (
    <>
      <header>
        <div className="logo">
          <span className="logo-icon">⛨</span> SentinelCTF
        </div>
        <div className="header-right">
          <div className="ws-indicator">
            <span className={`ws-dot ${wsConnected ? 'connected' : 'disconnected'}`} />
            {wsConnected ? 'LIVE' : 'OFFLINE'}
          </div>
          <span className={`status-badge ${statusClass}`}>
            {status === 'needs_human' ? 'OVERRIDE REQUIRED' : status.toUpperCase()}
          </span>
        </div>
      </header>

      <main className="container grid">
        {/* ── Left: Mission Control ── */}
        <section className="mission-control">
          <div className="glass-panel">
            <h2 className="panel-title">
              <span className="panel-title-icon">◈</span> Mission Control
            </h2>

            <form className="challenge-form" onSubmit={handleSubmit}>
              <div>
                <label htmlFor="challenge-prompt">Challenge Prompt</label>
                <textarea
                  id="challenge-prompt"
                  rows="6"
                  placeholder="Paste the CTF question or hint here…"
                  value={challengeText}
                  onChange={(e) => setChallengeText(e.target.value)}
                  disabled={status !== 'idle'}
                />
              </div>

              <div>
                <label>Target File (Optional)</label>
                <div className={`upload-zone ${file ? 'has-file' : ''}`}>
                  <input
                    type="file"
                    onChange={(e) => setFile(e.target.files[0])}
                    disabled={status !== 'idle'}
                    style={{ display: 'none' }}
                    id="file-upload"
                  />
                  <label htmlFor="file-upload" className="upload-label">
                    {file ? (
                      <>
                        <span className="upload-icon">📎</span>
                        <span className="upload-filename">{file.name}</span>
                        <span style={{ fontSize: '0.75rem' }}>
                          {(file.size / 1024).toFixed(1)} KB
                        </span>
                      </>
                    ) : (
                      <>
                        <span className="upload-icon">⬆</span>
                        <span>Click to upload binary / image / pcap</span>
                      </>
                    )}
                  </label>
                </div>
              </div>

              {categories.length > 0 && (
                <div>
                  <label>Modules Available</label>
                  <div className="category-chips">
                    {categories.map(c => (
                      <span
                        key={c}
                        className={`category-chip ${category === c ? 'active' : ''}`}
                      >
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ marginTop: 'auto' }}>
                <button
                  type="submit"
                  className={`btn ${status === 'idle' ? 'animate-pulse-glow' : 'btn-secondary'}`}
                  disabled={status !== 'idle'}
                  style={{ width: '100%' }}
                  id="submit-challenge"
                >
                  {status === 'idle' ? '⚡ Initialize Solver' : 'Processing…'}
                </button>
              </div>
            </form>
          </div>
        </section>

        {/* ── Right: Live Telemetry ── */}
        <section className="terminal-viewer">
          <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
            <div className="telemetry-header">
              <h2 className="telemetry-title">
                <span style={{ fontSize: '1.1rem' }}>◉</span> Live Telemetry
              </h2>
              <span className="telemetry-subtitle">
                {category ? `${category.toUpperCase()} MODULE` : 'KALI SANDBOX'}
              </span>
            </div>

            <div className="terminal">
              {logs.length === 0 && (
                <span className="terminal-empty">&gt; Awaiting commands…</span>
              )}
              {logs.map((log, i) => (
                <div key={i} className="log-entry">
                  <span className="log-time">[{log.time}]</span>
                  {renderTag(log.role)}
                  <span className={msgClass(log.role)}> {log.message}</span>
                </div>
              ))}
              <div ref={terminalEndRef} />
            </div>

            {/* Human Override Panel */}
            {status === 'needs_human' && (
              <div className="override-panel override-error">
                <h3 className="override-title error">⚠️ Human Override Required</h3>
                <p className="override-text">
                  The AI has proposed commands that may modify files or interact with external services.
                  Review the attack plan above and decide whether to proceed.
                </p>
                <div className="override-actions">
                  <button
                    className="btn btn-approve"
                    onClick={handleApprove}
                    id="approve-action"
                  >
                    ✓ Approve &amp; Execute
                  </button>
                  <button
                    className="btn btn-danger"
                    onClick={handleReject}
                    id="reject-action"
                  >
                    ✗ Reject Plan
                  </button>
                </div>
              </div>
            )}

            {/* Solved Panel */}
            {status === 'solved' && (
              <div className="override-panel override-success">
                <h3 className="override-title success">🎉 Flag Captured!</h3>
                <div className="flag-display">{flag}</div>
                <button
                  className="btn"
                  onClick={handleReset}
                  style={{ marginTop: '12px' }}
                  id="reset-challenge"
                >
                  ↻ New Challenge
                </button>
              </div>
            )}
          </div>
        </section>
      </main>
    </>
  )
}

export default App
