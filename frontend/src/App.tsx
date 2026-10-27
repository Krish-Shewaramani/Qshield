import { useCallback, useEffect, useState } from 'react'
import { api, type HealthResponse, type KeyRecord } from './api'
import KeyManagement from './KeyManagement'
import FileExchange from './FileExchange'

type LoadState<T> = { value: T | null; error: string | null; loading: boolean }

const initialState = <T,>(): LoadState<T> => ({ value: null, error: null, loading: true })

function App() {
  const [page, setPage] = useState<'overview' | 'keys' | 'encrypt' | 'verify'>('overview')
  const [health, setHealth] = useState<LoadState<HealthResponse>>(initialState)
  const [keys, setKeys] = useState<LoadState<KeyRecord[]>>(initialState)

  const refresh = useCallback(async () => {
    setHealth((state) => ({ ...state, loading: true, error: null }))
    setKeys((state) => ({ ...state, loading: true, error: null }))
    const [healthResult, keyResult] = await Promise.allSettled([api.getHealth(), api.listKeys()])

    if (healthResult.status === 'fulfilled') {
      setHealth({ value: healthResult.value, error: null, loading: false })
    } else {
      setHealth({ value: null, error: safeMessage(healthResult.reason), loading: false })
    }
    if (keyResult.status === 'fulfilled') {
      setKeys({ value: keyResult.value, error: null, loading: false })
    } else {
      setKeys({ value: null, error: safeMessage(keyResult.reason), loading: false })
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const backendReady = health.value?.status === 'ok' && health.value.cryptography === 'ready'
  const algorithms = health.value?.algorithms ?? []
  const keyCount = keys.value?.length

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Main navigation">
        <a className="brand" href="#overview" aria-label="QuantumShield overview">
          <span className="brand-mark" aria-hidden="true">Q</span>
          <span>quantum<span className="brand-light">shield</span></span>
        </a>

        <div className="nav-label">Workspace</div>
        <nav className="nav-list">
          <button className={`nav-item nav-button ${page === 'overview' ? 'active' : ''}`} type="button" onClick={() => setPage('overview')} aria-current={page === 'overview' ? 'page' : undefined}>
            <span className="nav-icon" aria-hidden="true">◫</span> Overview
          </button>
          <button className={`nav-item nav-button ${page === 'keys' ? 'active' : ''}`} type="button" onClick={() => setPage('keys')} aria-current={page === 'keys' ? 'page' : undefined}>
            <span className="nav-icon" aria-hidden="true">⌘</span> Key management
          </button>
          <button className={`nav-item nav-button ${page === 'encrypt' ? 'active' : ''}`} type="button" onClick={() => setPage('encrypt')} aria-current={page === 'encrypt' ? 'page' : undefined}>
            <span className="nav-icon" aria-hidden="true">↗</span> Encrypt file
          </button>
          <button className={`nav-item nav-button ${page === 'verify' ? 'active' : ''}`} type="button" onClick={() => setPage('verify')} aria-current={page === 'verify' ? 'page' : undefined}>
            <span className="nav-icon" aria-hidden="true">✓</span> Verify &amp; decrypt
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="local-note">
            <span className="local-dot" />
            <span><strong>Local workspace</strong><small>Data stays on this device</small></span>
          </div>
          <div className="sidebar-version">ACADEMIC PROTOTYPE <span>·</span> PHASE 4</div>
        </div>
      </aside>

      <main id="overview" className="main-content">
        <header className="topbar">
          <div className="breadcrumb">QUANTUMSHIELD <span>/</span> {page === 'keys' ? 'KEY MANAGEMENT' : 'OVERVIEW'}</div>
          <div className={`connection ${backendReady ? 'is-ready' : health.loading ? 'is-loading' : 'is-down'}`}>
            <span className="connection-dot" />
            {health.loading ? 'Checking local backend' : backendReady ? 'Backend connected' : 'Backend unavailable'}
          </div>
        </header>

        {page === 'keys' ? <KeyManagement onKeysChanged={() => void refresh()} /> : page === 'encrypt' || page === 'verify' ? <FileExchange key={page} mode={page} /> : <>
        <section className="hero" aria-labelledby="hero-title">
          <div className="hero-copy">
            <p className="eyebrow"><span className="eyebrow-line" /> PRIVATE FILE EXCHANGE, REIMAGINED</p>
            <h1 id="hero-title">Security for<br /><em>what comes next.</em></h1>
            <p className="hero-description">A local workspace for preparing and verifying file exchanges with post-quantum cryptography.</p>
            <div className="hero-actions">
              <button className="button button-primary" type="button" onClick={() => setPage('encrypt')}>
                <span aria-hidden="true">＋</span> Start an exchange <span className="button-arrow" aria-hidden="true">↗</span>
              </button>
              <span className="action-note">Encrypted for a trusted recipient</span>
            </div>
          </div>
          <div className="hero-art" aria-hidden="true">
            <div className="orbit orbit-outer" />
            <div className="orbit orbit-inner" />
            <div className="orbit-cross cross-h" />
            <div className="orbit-cross cross-v" />
            <div className="core-symbol">Q<span>·</span></div>
            <div className="orbit-node node-top" />
            <div className="orbit-node node-right" />
            <div className="orbit-node node-bottom" />
            <span className="art-label art-label-top">FIPS 203</span>
            <span className="art-label art-label-right">LOCAL / 01</span>
            <span className="art-label art-label-bottom">POST-QUANTUM</span>
          </div>
          <div className="hero-index">01 <span>—</span> BUILT FOR THE LOCAL MACHINE</div>
        </section>

        <section className="overview-grid" aria-label="System overview">
          <div className="section-heading">
            <p className="eyebrow">THE WORKSPACE</p>
            <h2>Everything starts<br />with a trusted key.</h2>
          </div>

          <div className="status-panel">
            <div className="panel-topline"><span>LOCAL BACKEND</span><button className="refresh-button" type="button" onClick={() => void refresh()} disabled={health.loading || keys.loading} aria-label="Refresh backend status">↻</button></div>
            <div className="status-main">
              <span className={`status-indicator ${backendReady ? 'online' : health.loading ? 'pending' : 'offline'}`} />
              <div><strong>{health.loading ? 'Connecting…' : backendReady ? 'Ready for local use' : 'Connection needed'}</strong><small>{health.error ?? 'FastAPI · 127.0.0.1:8000'}</small></div>
            </div>
            {health.error && <p className="inline-error" role="status">{health.error}</p>}
            <div className="status-bottom"><span>YOUR KEY RECORDS</span><strong>{keys.loading ? '…' : keyCount ?? '—'} <small>{keyCount === 1 ? 'key' : 'keys'}</small></strong></div>
            {keys.error && <p className="inline-error" role="status">Key list unavailable: {keys.error}</p>}
          </div>

          <div className="workflow-panel">
            <p className="eyebrow">A SIMPLE EXCHANGE</p>
            <ol className="workflow-list">
              <li><span className="step-number">01</span><span><strong>Establish trust</strong><small>Confirm a contact’s public-key fingerprint out of band.</small></span><span className="step-mark">↗</span></li>
              <li><span className="step-number">02</span><span><strong>Encrypt &amp; sign</strong><small>Prepare a protected package for its recipient.</small></span><span className="step-mark">↗</span></li>
              <li><span className="step-number">03</span><span><strong>Verify &amp; decrypt</strong><small>Check the sender before recovering the file.</small></span><span className="step-mark">↗</span></li>
            </ol>
          </div>
        </section>

        <section className="algorithm-section" aria-label="Cryptographic algorithms">
          <div className="algorithm-heading"><p className="eyebrow">THE CRYPTOGRAPHY</p><p>Standards-based building blocks.<br />No classical public-key fallback.</p></div>
          <div className="algorithm-list">
            <Algorithm name="ML-KEM-768" standard="FIPS 203" role="Key establishment" ready={algorithms.includes('ML-KEM-768')} />
            <Algorithm name="ML-DSA-65" standard="FIPS 204" role="Digital signature" ready={algorithms.includes('ML-DSA-65')} />
            <Algorithm name="AES-256-GCM" standard="NIST SP 800-38D" role="Authenticated encryption" ready={algorithms.includes('AES-256-GCM')} />
            <Algorithm name="HKDF-SHA-256" standard="RFC 5869" role="Key derivation" ready={algorithms.includes('HKDF-SHA-256')} />
          </div>
        </section>
        </>}

        <footer className="page-footer"><span>QUANTUMSHIELD <span className="footer-dot">·</span> LOCAL BY DESIGN</span><span>ACADEMIC PROTOTYPE — NOT FOR PRODUCTION USE</span></footer>
      </main>
    </div>
  )
}

function Algorithm({ name, standard, role, ready }: { name: string; standard: string; role: string; ready: boolean }) {
  return <div className="algorithm-row"><span className={`algorithm-status ${ready ? 'ready' : ''}`} aria-label={ready ? 'Available' : 'Not confirmed'} /><div className="algorithm-name"><strong>{name}</strong><small>{standard}</small></div><span className="algorithm-role">{role}</span></div>
}

function safeMessage(reason: unknown): string {
  return reason instanceof Error ? reason.message : 'The local service could not be reached.'
}

export default App
