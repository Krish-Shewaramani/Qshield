import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, type KeyRecord, type PublicKeyPreview, type TrustedKeyRecord } from './api'

export function normalizeFingerprint(value: string): string {
  return value.replace(/\s/g, '')
}

export function fingerprintMatches(value: string, expected: string): boolean {
  const normalized = normalizeFingerprint(value)
  return /^[0-9a-fA-F]{64}$/.test(normalized) && normalized.toLowerCase() === expected.toLowerCase()
}

export default function KeyManagement({ onKeysChanged }: { onKeysChanged: () => void }) {
  const [keys, setKeys] = useState<KeyRecord[]>([])
  const [trusted, setTrusted] = useState<TrustedKeyRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [working, setWorking] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [label, setLabel] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [generationType, setGenerationType] = useState<'kem' | 'sig'>('kem')
  const [publicPem, setPublicPem] = useState('')
  const [preview, setPreview] = useState<PublicKeyPreview | null>(null)
  const [trustLabel, setTrustLabel] = useState('')
  const [confirmedFingerprint, setConfirmedFingerprint] = useState('')

  const refresh = useCallback(async () => {
    setLoading(true)
    setLoadError('')
    const [keyResult, trustResult] = await Promise.allSettled([api.listKeys(), api.listTrustedKeys()])
    const failures: string[] = []
    if (keyResult.status === 'fulfilled') setKeys(keyResult.value)
    else failures.push(`Your keys: ${safeMessage(keyResult.reason)}`)
    if (trustResult.status === 'fulfilled') setTrusted(trustResult.value)
    else failures.push(`Trusted keys: ${safeMessage(trustResult.reason)}`)
    setLoadError(failures.join(' '))
    setLoading(false)
  }, [])

  useEffect(() => { void refresh() }, [refresh])

  async function generate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setWorking(true); setError(''); setNotice('')
    const currentPassphrase = passphrase
    setPassphrase('')
    try {
      const result = generationType === 'kem'
        ? await api.generateKemKey({ label: label.trim(), passphrase: currentPassphrase })
        : await api.generateSignatureKey({ label: label.trim(), passphrase: currentPassphrase })
      if (result) setNotice(`${result.algorithm} key “${result.label}” created.`)
      setLabel('')
      await refresh()
      onKeysChanged()
    } catch (reason) {
      setError(safeMessage(reason))
    } finally {
      setWorking(false)
    }
  }

  async function exportKey(record: KeyRecord) {
    setWorking(true); setError(''); setNotice('')
    try {
      const blob = await api.exportPublicKey(record.key_id)
      downloadBlob(blob, `${safeFilename(record.label)}-${record.algorithm.toLowerCase()}-public.pem`)
      setNotice(`Public key exported for “${record.label}”.`)
    } catch (reason) { setError(safeMessage(reason)) }
    finally { setWorking(false) }
  }

  async function removeKey(record: KeyRecord) {
    if (!window.confirm(`Delete the encrypted private key “${record.label}”? This cannot be undone.`)) return
    setWorking(true); setError(''); setNotice('')
    try {
      await api.deleteKey(record.key_id)
      setNotice(`Key “${record.label}” deleted.`)
      await refresh(); onKeysChanged()
    } catch (reason) { setError(safeMessage(reason)) }
    finally { setWorking(false) }
  }

  async function previewKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setWorking(true); setError(''); setNotice(''); setPreview(null); setConfirmedFingerprint('')
    try {
      const result = await api.previewPublicKey(publicPem)
      if (result) setPreview(result)
    } catch (reason) { setError(safeMessage(reason)) }
    finally { setWorking(false) }
  }

  async function trustKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!preview || !fingerprintMatches(confirmedFingerprint, preview.key_id)) return
    setWorking(true); setError(''); setNotice('')
    try {
      const result = await api.importTrustedKey({
        public_key_pem: preview.public_key_pem,
        label: trustLabel.trim(),
        confirmed_fingerprint: normalizeFingerprint(confirmedFingerprint),
      })
      if (result) setNotice(`“${result.label}” is now in your local trusted-key store.`)
      setPreview(null); setPublicPem(''); setTrustLabel(''); setConfirmedFingerprint('')
      await refresh()
    } catch (reason) { setError(safeMessage(reason)) }
    finally { setWorking(false) }
  }

  async function removeTrusted(record: TrustedKeyRecord) {
    if (!window.confirm(`Remove “${record.label}” from the trusted-key store?`)) return
    setWorking(true); setError(''); setNotice('')
    try {
      await api.deleteTrustedKey(record.key_id)
      setNotice(`“${record.label}” removed from trusted keys.`)
      await refresh()
    } catch (reason) { setError(safeMessage(reason)) }
    finally { setWorking(false) }
  }

  return (
    <section className="key-page" aria-labelledby="keys-title">
      <div className="page-intro">
        <div><p className="eyebrow"><span className="eyebrow-line" /> KEY MANAGEMENT</p><h1 id="keys-title" className="page-title">Your keys,<br /><em>your control.</em></h1></div>
        <p className="page-description">Create local post-quantum key pairs and establish trust with contacts by comparing fingerprints through a channel you already trust.</p>
      </div>

      {(notice || error) && <div className={`operation-message ${error ? 'message-error' : 'message-success'}`} role="status">{error || notice}<button type="button" onClick={() => { setError(''); setNotice('') }} aria-label="Dismiss message">×</button></div>}

      <div className="key-columns">
        <div className="key-column">
          <section className="surface-panel" aria-labelledby="local-keys-heading">
            <div className="panel-heading"><div><p className="eyebrow">PRIVATE MATERIAL STAYS LOCAL</p><h2 id="local-keys-heading">Create a key pair</h2></div><span className="section-index">01</span></div>
            <form className="key-form" onSubmit={generate}>
              <label className="field-label" htmlFor="key-label">Key label</label>
              <input id="key-label" value={label} onChange={(event) => setLabel(event.target.value)} required minLength={1} maxLength={128} autoComplete="off" placeholder="e.g. Personal signing key" />
              <label className="field-label" htmlFor="key-type">Algorithm</label>
              <select id="key-type" value={generationType} onChange={(event) => setGenerationType(event.target.value as 'kem' | 'sig')}>
                <option value="kem">ML-KEM-768 · key establishment</option>
                <option value="sig">ML-DSA-65 · digital signature</option>
              </select>
              <label className="field-label" htmlFor="key-passphrase">Protect this private key</label>
              <input id="key-passphrase" type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} required minLength={1} maxLength={1024} autoComplete="new-password" placeholder="Choose a passphrase" />
              <p className="field-hint">The passphrase is sent only to the local backend for this operation and is not retained in browser storage.</p>
              <button className="button button-primary form-submit" type="submit" disabled={working}>{working ? 'Working…' : 'Generate key pair'} <span aria-hidden="true">↗</span></button>
            </form>
          </section>

          <section className="surface-panel key-list-panel" aria-labelledby="local-list-heading">
            <div className="panel-heading"><div><p className="eyebrow">ENCRYPTED LOCAL RECORDS</p><h2 id="local-list-heading">Your key pairs <span className="count-badge">{loading ? '…' : keys.length}</span></h2></div><button className="quiet-button" type="button" onClick={() => void refresh()} disabled={loading || working}>Refresh</button></div>
            {loadError && <p className="inline-error" role="alert">{loadError}</p>}
            {loading ? <p className="empty-state">Loading local key records…</p> : keys.length === 0 ? <p className="empty-state">No key pairs yet. Generate one to begin.</p> : <div className="record-list">{keys.map((record) => <KeyRecordView key={record.key_id} record={record} working={working} onExport={() => void exportKey(record)} onDelete={() => void removeKey(record)} />)}</div>}
          </section>
        </div>

        <div className="key-column">
          <section className="surface-panel" aria-labelledby="trust-heading">
            <div className="panel-heading"><div><p className="eyebrow">EXPLICIT TRUST, VERIFIED OUT OF BAND</p><h2 id="trust-heading">Add a trusted public key</h2></div><span className="section-index">02</span></div>
            <form className="key-form" onSubmit={previewKey}>
              <label className="field-label" htmlFor="public-pem">Public key · SPKI PEM</label>
              <textarea id="public-pem" value={publicPem} onChange={(event) => { setPublicPem(event.target.value); setPreview(null) }} required maxLength={10000} rows={6} spellCheck={false} autoComplete="off" placeholder="-----BEGIN PUBLIC KEY-----" />
              <button className="button button-secondary form-submit" type="submit" disabled={working || !publicPem.trim()}>Inspect public key <span aria-hidden="true">↗</span></button>
            </form>

            {preview && <form className="fingerprint-confirm" onSubmit={trustKey}>
              <div className="preview-meta"><span className="algorithm-pill">{preview.algorithm}</span><span>Backend-derived key fingerprint</span></div>
              <div className="fingerprint-box"><span>SHA-256 KEY ID</span><code>{formatFingerprint(preview.key_id)}</code></div>
              <p className="trust-warning">Compare this complete fingerprint with the key owner over a separate, trusted channel. Only continue if it matches exactly.</p>
              <label className="field-label" htmlFor="trust-label">Contact label</label>
              <input id="trust-label" value={trustLabel} onChange={(event) => setTrustLabel(event.target.value)} required minLength={1} maxLength={128} autoComplete="off" placeholder="Name or organization" />
              <label className="field-label" htmlFor="confirmed-fingerprint">Type the 64-character fingerprint (spaces optional)</label>
              <input id="confirmed-fingerprint" className="fingerprint-input" value={confirmedFingerprint} onChange={(event) => setConfirmedFingerprint(event.target.value)} required autoComplete="off" spellCheck={false} placeholder="64 hexadecimal characters; spaces optional" />
              <p className="field-hint">Spaces are optional. Enter exactly 64 hexadecimal characters after spaces are removed.</p>
              <button className="button button-primary form-submit" type="submit" disabled={working || !fingerprintMatches(confirmedFingerprint, preview.key_id)}>Trust this public key <span aria-hidden="true">✓</span></button>
            </form>}
          </section>

          <section className="surface-panel key-list-panel" aria-labelledby="trusted-list-heading">
            <div className="panel-heading"><div><p className="eyebrow">LOCAL TRUST STORE</p><h2 id="trusted-list-heading">Trusted contacts <span className="count-badge">{loading ? '…' : trusted.length}</span></h2></div></div>
            {loading ? <p className="empty-state">Loading trusted contacts…</p> : trusted.length === 0 ? <p className="empty-state">No contacts are trusted yet. Imported keys are never trusted automatically.</p> : <div className="record-list">{trusted.map((record) => <KeyRecordView key={record.key_id} record={record} trusted working={working} onExport={() => downloadBlob(new Blob([record.public_key_pem], { type: 'application/x-pem-file' }), `${safeFilename(record.label)}-${record.algorithm.toLowerCase()}-public.pem`)} onDelete={() => void removeTrusted(record)} />)}</div>}
          </section>
        </div>
      </div>
    </section>
  )
}

function KeyRecordView({ record, trusted = false, working, onExport, onDelete }: { record: KeyRecord; trusted?: boolean; working: boolean; onExport: () => void; onDelete: () => void }) {
  return <article className="key-record">
    <div className="record-leading"><span className="record-symbol" aria-hidden="true">{record.algorithm === 'ML-KEM-768' ? 'K' : 'S'}</span><div className="record-title"><strong>{record.label}</strong><small>{record.algorithm} {trusted ? '· trusted' : '· private key encrypted at rest'}</small></div></div>
    <div className="record-id"><span>KEY ID / FINGERPRINT</span><code>{formatFingerprint(record.key_id)}</code></div>
    <div className="record-actions"><button className="quiet-button" type="button" onClick={onExport} disabled={working}>Export public key</button><button className="text-danger" type="button" onClick={onDelete} disabled={working}>{trusted ? 'Remove trust' : 'Delete key'}</button></div>
  </article>
}

function formatFingerprint(value: string): string {
  return value.match(/.{1,4}/g)?.join(' ') ?? value
}

function safeFilename(value: string): string {
  const safe = value.normalize('NFKD').replace(/[^a-zA-Z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48)
  return safe || 'quantumshield'
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function safeMessage(reason: unknown): string {
  return reason instanceof Error ? reason.message : 'The local service could not complete the request.'
}
