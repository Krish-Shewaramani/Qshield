import { useCallback, useEffect, useState, type FormEvent } from 'react'
import Contacts from './Contacts'
import { api, type ContactBundlePreview, type KeyRecord, type PublicKeyPreview, type TrustedKeyRecord } from './api'

const MAX_CONTACT_BUNDLE_BYTES = 32 * 1024

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
  const [bundleLabel, setBundleLabel] = useState('')
  const [bundleSelection, setBundleSelection] = useState<string[]>([])
  const [bundlePreview, setBundlePreview] = useState<ContactBundlePreview | null>(null)
  const [bundleError, setBundleError] = useState('')
  const [contactStorageWarning, setContactStorageWarning] = useState('')
  const [reauthTyped, setReauthTyped] = useState<Record<string, string>>({})

  const refresh = useCallback(async () => {
    setLoading(true)
    setLoadError('')
    void api.getContactStorage().then((state) => setContactStorageWarning(state.state === 'ready' ? '' : (state.message ?? 'Contact storage is unavailable.'))).catch(() => setContactStorageWarning(''))
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

  function toggleBundleKey(keyId: string, selected: boolean) {
    setBundleSelection((current) => selected ? [...current.filter((id) => id !== keyId), keyId] : current.filter((id) => id !== keyId))
  }

  async function exportBundle(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    // Only IDs of existing local records are sent; the backend reads their public keys and re-derives fingerprints.
    const selected = keys.filter((record) => bundleSelection.includes(record.key_id)).map((record) => record.key_id)
    if (selected.length === 0) return
    setWorking(true); setError(''); setNotice('')
    try {
      const bundle = await api.exportContactBundle({ label: bundleLabel.trim(), key_ids: selected })
      if (bundle) {
        downloadBlob(new Blob([`${JSON.stringify(bundle, null, 2)}\n`], { type: 'application/json' }), `${safeFilename(bundle.label)}.qscontact.json`)
        setNotice(`Contact bundle exported with ${bundle.keys.length} public ${bundle.keys.length === 1 ? 'key' : 'keys'}. Private keys are never included.`)
      }
    } catch (reason) { setError(safeMessage(reason)) }
    finally { setWorking(false) }
  }

  async function previewBundle(file: File | undefined) {
    setBundlePreview(null); setBundleError(''); setError(''); setNotice('')
    if (!file) return
    if (file.size === 0 || file.size > MAX_CONTACT_BUNDLE_BYTES) {
      setBundleError('Choose a non-empty contact bundle no larger than 32 KiB.')
      return
    }
    setWorking(true)
    try {
      const result = await api.previewContactBundle(await file.text())
      if (result) setBundlePreview(result)
    } catch (reason) { setBundleError(safeMessage(reason)) }
    finally { setWorking(false) }
  }

  async function reauthorize(record: TrustedKeyRecord) {
    const typed = reauthTyped[record.key_id] ?? ''
    if (!fingerprintMatches(typed, record.key_id)) return
    setWorking(true); setError(''); setNotice('')
    try {
      await api.reauthorizeTrustedKey(record.key_id, normalizeFingerprint(typed))
      setReauthTyped((current) => ({ ...current, [record.key_id]: '' }))
      setNotice(`“${record.label}” can receive encrypted files again.`)
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

          <section className="surface-panel" aria-labelledby="bundle-export-heading">
            <div className="panel-heading"><div><p className="eyebrow">PUBLIC KEYS ONLY</p><h2 id="bundle-export-heading">Share a contact bundle</h2></div><span className="section-index">03</span></div>
            <form className="key-form" onSubmit={exportBundle}>
              <label className="field-label" htmlFor="bundle-label">Your display name in the bundle</label>
              <input id="bundle-label" value={bundleLabel} onChange={(event) => setBundleLabel(event.target.value)} required minLength={1} maxLength={128} autoComplete="off" placeholder="e.g. Alice, work laptop" />
              <fieldset className="bundle-key-options" disabled={loading || keys.length === 0}>
                <legend className="field-label">Public keys to include</legend>
                {keys.length === 0 ? <p className="field-hint">Generate a key pair first.</p> : keys.map((record) => <label className="bundle-key-option" key={record.key_id}>
                  <input type="checkbox" checked={bundleSelection.includes(record.key_id)} onChange={(event) => toggleBundleKey(record.key_id, event.target.checked)} />
                  <span>{record.label} · {record.algorithm === 'ML-KEM-768' ? 'encryption' : 'signing'} · {record.key_id.slice(0, 12)}…</span>
                </label>)}
              </fieldset>
              <p className="field-hint">The bundle contains a label, public keys, and full fingerprints. Private keys and passphrases are never exported.</p>
              <button className="button button-secondary form-submit" type="submit" disabled={working || !bundleLabel.trim() || !keys.some((record) => bundleSelection.includes(record.key_id))}>Export contact bundle <span aria-hidden="true">↓</span></button>
            </form>
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
            {contactStorageWarning && <p className="inline-error" role="alert">{contactStorageWarning} Contact links are not shown below until this is resolved.</p>}
            {!contactStorageWarning && trusted.some(awaitingReauthorization) && <p className="inline-error" role="status">{trusted.filter(awaitingReauthorization).length} encryption {trusted.filter(awaitingReauthorization).length === 1 ? 'key is' : 'keys are'} suspended and cannot receive files. Review each one, compare its full fingerprint with its owner, and re-confirm it below, or remove it.</p>}
            {loading ? <p className="empty-state">Loading trusted contacts…</p> : trusted.length === 0 ? <p className="empty-state">No contacts are trusted yet. Imported keys are never trusted automatically.</p> : <div className="record-list">{trusted.map((record) => <div key={record.key_id}>
              <KeyRecordView record={record} trusted trustNote={trustNote(record)} managed={Boolean(record.contact_id)} working={working} onExport={() => downloadBlob(new Blob([record.public_key_pem], { type: 'application/x-pem-file' }), `${safeFilename(record.label)}-${record.algorithm.toLowerCase()}-public.pem`)} onDelete={() => void removeTrusted(record)} />
              {awaitingReauthorization(record) && !contactStorageWarning && <form className="contact-verify" onSubmit={(event) => { event.preventDefault(); void reauthorize(record) }}>
                <label className="field-label" htmlFor={`reauth-${record.key_id}`}>Type the full fingerprint you compared with the owner to re-enable encryption</label>
                <input id={`reauth-${record.key_id}`} className="fingerprint-input" value={reauthTyped[record.key_id] ?? ''} onChange={(event) => setReauthTyped((current) => ({ ...current, [record.key_id]: event.target.value }))} autoComplete="off" spellCheck={false} placeholder="64 hexadecimal characters; spaces optional" disabled={working} />
                <button className="quiet-button" type="submit" disabled={working || !fingerprintMatches(reauthTyped[record.key_id] ?? '', record.key_id)}>Re-confirm and allow encryption</button>
              </form>}
            </div>)}</div>}
          </section>

          <section className="surface-panel" aria-labelledby="bundle-preview-heading">
            <div className="panel-heading"><div><p className="eyebrow">VALIDATE BEFORE TRUSTING</p><h2 id="bundle-preview-heading">Preview a contact bundle</h2></div><span className="section-index">04</span></div>
            <div className="key-form">
              <label className="field-label" htmlFor="bundle-file">Contact bundle · .qscontact.json</label>
              <input id="bundle-file" type="file" accept=".json,application/json" disabled={working} onChange={(event) => { const selected = event.target.files?.[0]; event.target.value = ''; void previewBundle(selected) }} />
              <p className="field-hint">The backend recomputes every fingerprint. Previewing never trusts or saves a key.</p>
            </div>
            {bundleError && <p className="inline-error" role="alert">{bundleError}</p>}
            {bundlePreview && <div className="bundle-preview" aria-live="polite">
              <div className="preview-meta"><span className="algorithm-pill">UNTRUSTED</span><span>Bundle from “{bundlePreview.label}” · {bundlePreview.keys.length} {bundlePreview.keys.length === 1 ? 'key' : 'keys'} · not saved</span></div>
              {bundlePreview.keys.map((entry) => <div className="fingerprint-box" key={entry.key_id}><span>{entry.algorithm} · {entry.purpose.toUpperCase()} · SHA-256 KEY ID</span><code>{formatFingerprint(entry.key_id)}</code></div>)}
              <p className="trust-warning">These keys are not trusted. Compare each full fingerprint with the owner over a separate, trusted channel before trusting any of them.</p>
              <button className="quiet-button" type="button" onClick={() => setBundlePreview(null)}>Clear preview</button>
            </div>}
          </section>
        </div>
      </div>

      <Contacts onTrustChanged={() => void refresh()} />
    </section>
  )
}

// A suspended ML-KEM key that no contact manages, e.g. after contact-storage recovery.
function awaitingReauthorization(record: TrustedKeyRecord): boolean {
  return record.algorithm === 'ML-KEM-768' && record.usage === 'suspended' && !record.contact_id
}

function trustNote(record: TrustedKeyRecord): string {
  if (record.usage === 'verify_only') return `· retired key of ${record.contact_label ?? 'a contact'} · verification of older packages only`
  if (awaitingReauthorization(record)) return '· suspended · needs review and fingerprint re-confirmation before encryption'
  if (record.usage === 'suspended') return `· suspended · retired by ${record.contact_label ?? 'a contact'} · not usable for encryption`
  if (record.contact_label) return `· trusted · managed by contact ${record.contact_label}`
  return '· trusted'
}

function KeyRecordView({ record, trusted = false, trustNote, managed = false, working, onExport, onDelete }: { record: KeyRecord; trusted?: boolean; trustNote?: string; managed?: boolean; working: boolean; onExport: () => void; onDelete: () => void }) {
  return <article className="key-record">
    <div className="record-leading"><span className="record-symbol" aria-hidden="true">{record.algorithm === 'ML-KEM-768' ? 'K' : 'S'}</span><div className="record-title"><strong>{record.label}</strong><small>{record.algorithm} {trusted ? (trustNote ?? '· trusted') : '· private key encrypted at rest'}</small></div></div>
    <div className="record-id"><span>KEY ID / FINGERPRINT</span><code>{formatFingerprint(record.key_id)}</code></div>
    <div className="record-actions"><button className="quiet-button" type="button" onClick={onExport} disabled={working}>Export public key</button>{managed ? <span className="field-hint">Managed in Contacts</span> : <button className="text-danger" type="button" onClick={onDelete} disabled={working}>{trusted ? 'Remove trust' : 'Delete key'}</button>}</div>
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
