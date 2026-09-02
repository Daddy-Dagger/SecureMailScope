import { useEffect, useState } from 'react'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

export default function App() {
  const [backendStatus, setBackendStatus] = useState('checking...')

  useEffect(() => {
    const controller = new AbortController()

    fetch(`${API_BASE_URL}/health`, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        return response.json()
      })
      .then((data) => {
        setBackendStatus(data.status === 'ok' ? 'connected' : 'unexpected response')
      })
      .catch((error) => {
        if (error.name !== 'AbortError') setBackendStatus('unavailable')
      })

    return () => controller.abort()
  }, [])

  return (
    <main className="page-shell">
      <section className="status-card" aria-labelledby="project-title">
        <p className="eyebrow">Passive Network Forensics</p>
        <h1 id="project-title">SecureMailScope</h1>
        <p className="subtitle">AI-Assisted Cryptographic Security Posture Assessment</p>
        <div className="status-row" role="status" aria-live="polite">
          <span className={`status-dot status-${backendStatus.replace(' ', '-')}`} />
          <span>Backend Status: {backendStatus}</span>
        </div>
      </section>
    </main>
  )
}

