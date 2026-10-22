import { useEffect, useRef, useState, type DragEvent, type FormEvent } from 'react'
import { api, type KeyRecord, type TrustedKeyRecord, type VerifyResponse } from './api'

const MAX_FILE_SIZE = 25 * 1024 * 1024
const MAX_PACKAGE_SIZE = MAX_FILE_SIZE + 64 * 1024
type VerificationStatus = 'idle' | 'checking' | 'verified' | 'failed'

export default function FileExchange({ mode }: { mode: 'encrypt' | 'verify' }) {
  const [keys, setKeys] = useState<KeyRecord[]>([])
  const [trusted, setTrusted] = useState<TrustedKeyRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState('')
  const [dragging, setDragging] = useState(false)
  const [recipientId, setRecipientId] = useState('')
  const [signingId, setSigningId] = useState('')
  const [senderId, setSenderId] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [verified, setVerified] = useState<VerifyResponse | null>(null)
  const [verificationStatus, setVerificationStatus] = useState<VerificationStatus>('idle')
  const [working, setWorking] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const verificationRequestRef = useRef(0)

  useEffect(() => {
    let active = true
    void Promise.allSettled([api.listKeys(), api.listTrustedKeys()]).then(([keyResult, trustResult]) => {
      if (!active) return
      const failures: string[] = []
      if (keyResult.status === 'fulfilled') setKeys(keyResult.value)
      else failures.push(`Local keys: ${safeMessage(keyResult.reason)}`)
      if (trustResult.status === 'fulfilled') setTrusted(trustResult.value)
      else failures.push(`Trusted keys: ${safeMessage(trustResult.reason)}`)
      setLoadError(failures.join(' '))
      setLoading(false)
    })
    return () => { active = false }
  }, [])

  function invalidateVerification() {
    verificationRequestRef.current += 1
    setVerified(null)
    setVerificationStatus('idle')
  }

  function chooseFile(candidate: File | undefined) {
    setFileError(''); setError(''); setNotice(''); invalidateVerification()
    if (!candidate) { setFile(null); return }
    const limit = mode === 'encrypt' ? MAX_FILE_SIZE : MAX_PACKAGE_SIZE
    if (candidate.size > limit) {
      setFile(null)
      setFileError(mode === 'encrypt' ? 'Choose a file no larger than 25 MiB.' : 'Choose a package no larger than 25 MiB plus 64 KiB.')
      if (inputRef.current) inputRef.current.value = ''
      return
    }
    if (mode === 'verify' && candidate.size === 0) {
      setFile(null); setFileError('The selected package is empty.')
      if (inputRef.current) inputRef.current.value = ''
      return
    }
    setFile(candidate)
  }

  function onDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault(); setDragging(false)
    if (event.dataTransfer.files.length > 1) { chooseFile(undefined); setFileError('Select one file at a time.'); return }
    chooseFile(event.dataTransfer.files.item(0) ?? undefined)
  }

  async function encrypt(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file) return
    setWorking(true); setError(''); setNotice('')
    const selected = file
    const secret = passphrase
    setPassphrase('')
    try {
      const packageBlob = await api.encryptFile({ file: selected, recipientKeyId: recipientId, signingKeyId: signingId, passphrase: secret })
      downloadBlob(packageBlob, 'package.qshield')
      setNotice('Your signed .qshield package was created and downloaded.')
    } catch (reason) {
      setError(safeMessage(reason))
    } finally {
      setFile(null); setPassphrase(''); setWorking(false)
      if (inputRef.current) inputRef.current.value = ''
    }
  }

  async function verifyPackage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file) return
    const requestId = ++verificationRequestRef.current
    setWorking(true); setError(''); setNotice(''); setVerified(null); setVerificationStatus('checking')
    try {
      const result = await api.verifyPackage({ file, senderKeyId: senderId })
      if (requestId !== verificationRequestRef.current) return
      if (!result.verified) throw new Error('The backend did not confirm this sender signature.')
      setVerified(result); setVerificationStatus('verified'); setNotice('Signature verified against the selected trusted sender key.')
    } catch (reason) {
      if (requestId === verificationRequestRef.current) {
        setVerificationStatus('failed')
        setError(safeMessage(reason))
      }
    } finally { setWorking(false) }
  }

  async function decryptPackage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file || !verified || verificationStatus !== 'verified') return
    setWorking(true); setError(''); setNotice('')
    const selected = file
    const secret = passphrase
    setPassphrase('')
    try {
      const result = await api.decryptPackage({ file: selected, recipientKeyId: recipientId, senderKeyId: senderId, passphrase: secret })
      downloadBlob(result.blob, safeDownloadName(result.filename))
      setNotice('Authenticated decryption succeeded. The recovered file was downloaded.')
      setFile(null); invalidateVerification()
      if (inputRef.current) inputRef.current.value = ''
    } catch (reason) {
      setError(safeMessage(reason))
    } finally { setPassphrase(''); setWorking(false) }
  }

  const kemTrusted = trusted.filter((record) => record.algorithm === 'ML-KEM-768' && record.trusted)
  const signatureKeys = keys.filter((record) => record.algorithm === 'ML-DSA-65')
  const kemKeys = keys.filter((record) => record.algorithm === 'ML-KEM-768')
  const signatureTrusted = trusted.filter((record) => record.algorithm === 'ML-DSA-65' && record.trusted)

  return <section className="exchange-page" aria-labelledby="exchange-title">
    <div className="page-intro">
      <div><p className="eyebrow"><span className="eyebrow-line" /> {mode === 'encrypt' ? 'PRIVATE FILE EXCHANGE' : 'PACKAGE AUTHENTICITY'}</p><h1 id="exchange-title" className="page-title">{mode === 'encrypt' ? <>Send with<br /><em>confidence.</em></> : <>Verify before<br /><em>you open.</em></>}</h1></div>
      <p className="page-description">{mode === 'encrypt' ? 'Choose a trusted recipient, sign with your ML-DSA key, and download a protected .qshield package.' : 'Check the sender’s signature using a trusted public key. Decryption is a separate step and runs only after verification.'}</p>
    </div>

    {(error || notice) && <div className={`operation-message ${error ? 'message-error' : 'message-success'}`} role="status">{error || notice}<button type="button" onClick={() => { setError(''); setNotice('') }} aria-label="Dismiss message">×</button></div>}
    {loadError && <p className="inline-error exchange-load-error" role="alert">Could not load required key records. {loadError}</p>}

    <div className="exchange-layout">
      <div className="surface-panel exchange-panel">
        <div className="panel-heading"><div><p className="eyebrow">{mode === 'encrypt' ? 'STEP 01 · SELECT A FILE' : 'STEP 01 · SELECT A PACKAGE'}</p><h2>{mode === 'encrypt' ? 'File to protect' : 'Package to inspect'}</h2></div><span className="section-index">01</span></div>
        <label className={`drop-zone ${dragging ? 'is-dragging' : ''} ${file ? 'has-file' : ''}`} onDragOver={(event) => { event.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={onDrop}>
          <input ref={inputRef} aria-label={mode === 'encrypt' ? 'Select a file to encrypt' : 'Select a .qshield package'} type="file" accept={mode === 'verify' ? '.qshield,application/octet-stream' : undefined} onChange={(event) => chooseFile(event.target.files?.[0])} />
          <span className="drop-icon" aria-hidden="true">{file ? '✓' : '↑'}</span>
          <strong>{file ? file.name : 'Drop a file here'}</strong>
          <span>{file ? `${formatBytes(file.size)} · ${mode === 'encrypt' ? 'ready to encrypt' : 'ready to verify'}` : <>or <span className="browse-link">browse your device</span></>}</span>
          <small>{mode === 'encrypt' ? 'Maximum file size · 25 MiB' : 'Select a .qshield package · Maximum 25 MiB + 64 KiB'}</small>
        </label>
        {fileError && <p className="inline-error" role="alert">{fileError}</p>}
        {file && <button className="remove-file" type="button" onClick={() => chooseFile(undefined)}>Remove selected file</button>}

        {mode === 'encrypt' ? <form className="exchange-form" onSubmit={encrypt}>
          <label className="field-label" htmlFor="recipient-key">Trusted recipient · ML-KEM-768</label>
          <select id="recipient-key" value={recipientId} onChange={(event) => setRecipientId(event.target.value)} required disabled={loading || kemTrusted.length === 0}><option value="">{loading ? 'Loading trusted keys…' : 'Choose a trusted recipient'}</option>{kemTrusted.map((record) => <option key={record.key_id} value={record.key_id}>{record.label} · {record.key_id.slice(0, 12)}…</option>)}</select>
          {kemTrusted.length === 0 && !loading && <p className="field-hint">Import and explicitly trust a recipient’s ML-KEM-768 public key in Key Management.</p>}
          <label className="field-label" htmlFor="signing-key">Your signing key · ML-DSA-65</label>
          <select id="signing-key" value={signingId} onChange={(event) => setSigningId(event.target.value)} required disabled={loading || signatureKeys.length === 0}><option value="">{loading ? 'Loading local keys…' : 'Choose your signing key'}</option>{signatureKeys.map((record) => <option key={record.key_id} value={record.key_id}>{record.label} · {record.key_id.slice(0, 12)}…</option>)}</select>
          <label className="field-label" htmlFor="signing-passphrase">Signing-key passphrase</label>
          <input id="signing-passphrase" type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} required autoComplete="current-password" maxLength={1024} placeholder="Enter passphrase for this operation" />
          <button className="button button-primary form-submit" type="submit" disabled={working || loading || !file || !kemTrusted.length || !signatureKeys.length}>{working ? 'Encrypting and signing…' : 'Create .qshield package'} <span aria-hidden="true">↗</span></button>
        </form> : <div className="exchange-form">
          <form onSubmit={verifyPackage}>
            <label className="field-label" htmlFor="sender-key">Trusted sender · ML-DSA-65</label>
            <select id="sender-key" value={senderId} onChange={(event) => { setSenderId(event.target.value); setError(''); setNotice(''); invalidateVerification() }} required disabled={loading || signatureTrusted.length === 0}><option value="">{loading ? 'Loading trusted keys…' : 'Choose a trusted sender'}</option>{signatureTrusted.map((record) => <option key={record.key_id} value={record.key_id}>{record.label} · {record.key_id.slice(0, 12)}…</option>)}</select>
            {signatureTrusted.length === 0 && !loading && <p className="field-hint">Import and explicitly trust the sender’s ML-DSA-65 public key in Key Management.</p>}
            <button className="button button-secondary form-submit" type="submit" disabled={working || loading || !file || !senderId}>{working ? 'Checking signature…' : 'Verify sender signature'} <span aria-hidden="true">✓</span></button>
          </form>

          {verificationStatus !== 'idle' && <div className={`verification-state ${verificationStatus === 'verified' ? 'verification-ok' : ''}`} aria-live="polite">
            <span className="verification-number">02</span><span className="verification-symbol">{verificationStatus === 'verified' ? '✓' : '○'}</span>
            <span><strong>{verificationStatus === 'verified' ? 'Signature verified' : verificationStatus === 'failed' ? 'Signature verification failed' : 'Checking signature…'}</strong><small>{verificationStatus === 'verified' ? `Sender confirmed · ${formatTimestamp(verified?.created_at ?? 0)}` : verificationStatus === 'failed' ? 'The selected package was not verified.' : 'Checking the package with the selected trusted sender key.'}</small></span>
          </div>}

          {verified && verificationStatus === 'verified' && <form className="decrypt-form" onSubmit={decryptPackage}>
            <div className="panel-heading decrypt-heading"><div><p className="eyebrow">STEP 03 · AUTHENTICATED DECRYPTION</p><h2>Recover the original file</h2></div></div>
            <label className="field-label" htmlFor="recipient-private-key">Your recipient key · ML-KEM-768</label>
            <select id="recipient-private-key" value={recipientId} onChange={(event) => setRecipientId(event.target.value)} required disabled={loading || kemKeys.length === 0}><option value="">{loading ? 'Loading local keys…' : 'Choose your recipient key'}</option>{kemKeys.map((record) => <option key={record.key_id} value={record.key_id}>{record.label} · {record.key_id.slice(0, 12)}…</option>)}</select>
            <label className="field-label" htmlFor="recipient-passphrase">Private-key passphrase</label>
            <input id="recipient-passphrase" type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} required autoComplete="current-password" maxLength={1024} placeholder="Enter passphrase for this operation" />
            <p className="field-hint">The backend verifies the signature and authenticates the encrypted content before it returns recovered bytes.</p>
            <button className="button button-primary form-submit" type="submit" disabled={working || loading || !file || verificationStatus !== 'verified' || !verified || !kemKeys.length}>{working ? 'Verifying and decrypting…' : 'Decrypt and download file'} <span aria-hidden="true">↓</span></button>
          </form>}
        </div>}
      </div>

      <aside className="exchange-aside">
        <div className="aside-note"><p className="eyebrow">{mode === 'encrypt' ? 'PROTECTED BY DESIGN' : 'CHECKS HAPPEN IN ORDER'}</p>
          {mode === 'encrypt' ? <><p className="aside-large">Your file is encrypted locally through the backend and packaged for one trusted recipient.</p><ul className="aside-list"><li>ML-KEM-768 establishes the shared secret.</li><li>ML-DSA-65 signs the package header and encrypted output.</li><li>The backend holds uploaded bytes in bounded memory.</li></ul></> : <><p className="aside-large">A trusted signature is the first gate. Only after it passes can you request decryption.</p><ol className="aside-list ordered"><li>Select a sender already in your trusted store.</li><li>Verify the signature against that public key.</li><li>Unlock your local ML-KEM-768 key to decrypt.</li></ol></>}
        </div>
        <div className="limit-note"><span className="limit-mark">i</span><p><strong>Local prototype limits</strong><br />No file is written to a backend temporary file. This academic prototype is not for production use.</p></div>
      </aside>
    </div>
  </section>
}

function formatBytes(bytes: number): string {
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`
}

function formatTimestamp(seconds: number): string {
  const date = new Date(seconds * 1000)
  return Number.isNaN(date.valueOf()) ? 'timestamp unavailable' : date.toLocaleString()
}

function safeDownloadName(value: string): string {
  const sanitized = value.replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').trim()
  return sanitized && sanitized !== '.' && sanitized !== '..' ? sanitized.slice(0, 255) : 'recovered-file'
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
