import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, type Contact, type ContactStorage, type ContactKey, type ContactTrustStatus, type PairingAnalysis, type PairingStatus } from './api'

const MAX_CONTACT_BUNDLE_BYTES = 32 * 1024

const STATUS_TEXT: Record<PairingStatus, string> = {
  new_key: 'New key · untrusted',
  new_purpose: 'New purpose · untrusted',
  pending_replacement: 'Pending replacement',
  already_present: 'Already present',
  conflict: 'Conflict',
  previously_retired: 'Previously retired',
  pending_conflict: 'Another key is waiting',
}

const STATE_TEXT: Record<ContactKey['state'], string> = {
  pending: 'Untrusted · fingerprint not verified',
  verified: 'Fingerprint verified · awaiting contact confirmation',
  active: 'Active',
  retired: 'Retired',
}

const TRUST_TEXT: Record<ContactTrustStatus, string> = {
  untrusted: '',
  trusted: 'Trusted',
  activation_pending: 'Activation incomplete · retry to finish',
  missing: 'Not usable: missing from your trusted keys',
  downgraded: 'Not usable: restricted in your trusted keys',
  retired: 'Not usable',
  verification_only: 'Verification of older packages only',
  suspended: 'Independent trust kept but suspended · not usable for encryption',
  cleanup_pending: 'Cleanup incomplete · still in trusted keys · retry cleanup',
  history_unavailable: 'Not available to verify older packages · retry cleanup to restore',
}

export default function Contacts({ onTrustChanged }: { onTrustChanged: () => void }) {
  const [contacts, setContacts] = useState<Contact[]>([])
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [bundleText, setBundleText] = useState('')
  const [bundleName, setBundleName] = useState('')
  const [targetId, setTargetId] = useState('')
  const [newLabel, setNewLabel] = useState('')
  const [analysis, setAnalysis] = useState<PairingAnalysis | null>(null)
  const [typed, setTyped] = useState<Record<string, string>>({})

  const [storage, setStorage] = useState<ContactStorage | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      // Checking storage never recreates a lost contacts folder on the backend.
      const state = await api.getContactStorage().catch(() => null)
      setStorage(state)
      if (state && state.state !== 'ready') { setContacts([]); return }
      setContacts(await api.listContacts())
    } catch (reason) { setError(safeMessage(reason)) }
    finally { setLoading(false) }
  }, [])

  function reinitializeStorage() {
    if (!window.confirm('Reinitialize contact storage?\n\n• If you have a backup of the contacts folder, restore it instead and reload.\n• Reinitializing starts with no contacts. Records of keys that contacts retired are lost.\n• To stay safe, every trusted ML-KEM-768 encryption key is suspended first. None can receive new encryption until you review it and re-confirm its full fingerprint in Key Management.\n• Signing keys are not changed.')) return
    void run(async () => {
      const result = await api.reinitializeContactStorage()
      const suspended = result?.suspended_encryption_keys ?? 0
      setNotice(`Contact storage was reinitialized with no contacts. ${suspended} encryption ${suspended === 1 ? 'key was' : 'keys were'} suspended. Re-confirm each one under Trusted contacts before using it.`)
      await refresh(); onTrustChanged()
    })
  }

  useEffect(() => { void refresh() }, [refresh])

  async function run(action: () => Promise<void>) {
    setWorking(true); setError(''); setNotice('')
    try { await action() } catch (reason) { setError(safeMessage(reason)) }
    finally { setWorking(false) }
  }

  async function chooseBundle(file: File | undefined) {
    setAnalysis(null); setBundleText(''); setBundleName(''); setError(''); setNotice('')
    if (!file) return
    if (file.size === 0 || file.size > MAX_CONTACT_BUNDLE_BYTES) { setError('Choose a non-empty contact bundle no larger than 32 KiB.'); return }
    setBundleText(await file.text()); setBundleName(file.name)
  }

  function analyze(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!bundleText) return
    void run(async () => {
      const result = await api.analyzePairing({ bundle_json: bundleText, contact_id: targetId || null })
      if (result) setAnalysis(result)
    })
  }

  function stage() {
    if (!analysis) return
    void run(async () => {
      const result = await api.stagePairing({ bundle_json: bundleText, contact_id: targetId || null, label: targetId ? null : newLabel.trim() })
      if (!result) return
      setNotice(result.staged_fingerprints.length
        ? `${result.staged_fingerprints.length} untrusted ${result.staged_fingerprints.length === 1 ? 'key' : 'keys'} added. Verify each full fingerprint, then confirm the contact.`
        : 'Every key in this bundle is already present. Nothing was changed.')
      setAnalysis(null); setBundleText(''); setBundleName(''); setNewLabel('')
      await refresh()
    })
  }

  function verify(contact: Contact, key: ContactKey) {
    void run(async () => {
      await api.verifyContactKey(contact.contact_id, key.fingerprint, typed[key.fingerprint] ?? '')
      setTyped((current) => ({ ...current, [key.fingerprint]: '' }))
      setNotice('Fingerprint verified. The key stays untrusted until you confirm the contact.')
      await refresh()
    })
  }

  function confirmContact(contact: Contact) {
    if (!window.confirm(`Trust the verified keys for “${contact.label}”? Any key they replace will be retired.`)) return
    void run(async () => {
      const result = await api.confirmContact(contact.contact_id)
      if (result) {
        const parts = [`${result.activated.length} ${result.activated.length === 1 ? 'key is' : 'keys are'} now trusted for “${contact.label}”.`]
        if (result.retired.length) parts.push(`${result.retired.length} replaced ${result.retired.length === 1 ? 'key was' : 'keys were'} retired.`)
        if (result.activation_pending.length) parts.push('Warning: activation did not finish for some keys. Use “Retry cleanup” on this contact.')
        setNotice(parts.join(' '))
      }
      await refresh(); onTrustChanged()
    })
  }

  function restore(contact: Contact, key: ContactKey) {
    void run(async () => {
      await api.restoreContactKey(contact.contact_id, key.fingerprint, typed[key.fingerprint] ?? '')
      setTyped((current) => ({ ...current, [key.fingerprint]: '' }))
      setNotice('Fingerprint re-verified. The key is trusted again.')
      await refresh(); onTrustChanged()
    })
  }

  function reconcile(contact: Contact) {
    void run(async () => {
      const result = await api.reconcileContact(contact.contact_id)
      setNotice(result && result.failed.length ? 'Some keys still could not be updated. Try again later.' : 'Trusted keys are consistent with this contact.')
      await refresh(); onTrustChanged()
    })
  }

  function discard(contact: Contact, key: ContactKey) {
    if (!window.confirm('Discard this unconfirmed key?')) return
    void run(async () => { await api.discardContactKey(contact.contact_id, key.fingerprint); setNotice('Unconfirmed key discarded.'); await refresh() })
  }

  function removeContact(contact: Contact) {
    const hasAmbiguous = contact.keys.some((key) => key.trust_origin === 'ambiguous')
    const ambiguousNote = hasAmbiguous ? '\n• Older keys from before origin tracking may have been trusted independently, so they are left unchanged. They stay as standalone trusted keys, which you can remove afterward in Key Management.' : ''
    if (!window.confirm(`Delete “${contact.label}”?\n\n• Keys trusted through this contact are removed from your trusted keys, including retired signing keys kept for verifying older packages. Older packages from this contact will no longer verify.\n• Keys you trusted independently before pairing go back to normal standalone trust.${ambiguousNote}`)) return
    void run(async () => { await api.deleteContact(contact.contact_id); setNotice(`“${contact.label}” deleted.`); await refresh(); onTrustChanged() })
  }

  const stageBlocked = !analysis?.can_stage || (!targetId && !newLabel.trim())

  const storageBlocked = storage !== null && storage.state !== 'ready'

  return <div className="contacts-area">
    {storageBlocked && <div className="operation-message message-error" role="alert">{storage?.message ?? 'Contact storage is unavailable.'}{storage?.state === 'missing' && <button className="quiet-button" type="button" onClick={reinitializeStorage} disabled={working}>Reinitialize contact storage</button>}</div>}
    {(notice || error) && <div className={`operation-message ${error ? 'message-error' : 'message-success'}`} role="status">{error || notice}<button type="button" onClick={() => { setError(''); setNotice('') }} aria-label="Dismiss message">×</button></div>}
    <div className="key-columns">
      <section className="surface-panel" aria-labelledby="pairing-heading">
        <div className="panel-heading"><div><p className="eyebrow">PAIR BY FINGERPRINT, NOT BY NAME</p><h2 id="pairing-heading">Pair a contact</h2></div><span className="section-index">05</span></div>
        <form className="key-form" onSubmit={analyze}>
          <label className="field-label" htmlFor="pairing-file">Contact bundle · .qscontact.json</label>
          <input id="pairing-file" type="file" accept=".json,application/json" disabled={working} onChange={(event) => { const selected = event.target.files?.[0]; event.target.value = ''; void chooseBundle(selected) }} />
          {bundleName && <p className="field-hint">Selected: {bundleName}</p>}
          <label className="field-label" htmlFor="pairing-target">Add these keys to</label>
          <select id="pairing-target" value={targetId} onChange={(event) => { setTargetId(event.target.value); setAnalysis(null) }} disabled={working || loading}>
            <option value="">A new contact</option>
            {contacts.map((contact) => <option key={contact.contact_id} value={contact.contact_id}>{contact.label}</option>)}
          </select>
          {!targetId && <>
            <label className="field-label" htmlFor="pairing-label">Your label for this new contact</label>
            <input id="pairing-label" value={newLabel} onChange={(event) => setNewLabel(event.target.value)} maxLength={128} autoComplete="off" placeholder="Name you know this person by" />
          </>}
          <p className="field-hint">The name inside a bundle is self-asserted. It never selects or proves a contact.</p>
          <button className="button button-secondary form-submit" type="submit" disabled={working || !bundleText}>Check bundle <span aria-hidden="true">↗</span></button>
        </form>

        {analysis && <div className="bundle-preview" aria-live="polite">
          <div className="preview-meta"><span className="algorithm-pill">UNTRUSTED</span><span>Bundle claims to be from “{analysis.claimed_label}” (self-asserted)</span></div>
          {analysis.matching_contacts.length > 0 && <p className="field-hint">Keys in this bundle already belong to: {analysis.matching_contacts.map((match) => match.label).join(', ')}.</p>}
          {analysis.keys.map((item) => <div className={`fingerprint-box pairing-status-${item.status}`} key={item.fingerprint}>
            <span>{STATUS_TEXT[item.status]} · {item.algorithm} · {item.purpose.toUpperCase()}</span>
            <code>{formatFingerprint(item.fingerprint)}</code>
            <small className="pairing-detail">{item.detail}{item.conflicting_contact_label ? `: “${item.conflicting_contact_label}”` : ''}{item.current_fingerprint ? ` · current ${item.current_key_version ? `v${item.current_key_version} ` : ''}${formatFingerprint(item.current_fingerprint)}` : ''}</small>
          </div>)}
          <button className="button button-primary form-submit" type="button" onClick={stage} disabled={working || stageBlocked}>Add as untrusted keys <span aria-hidden="true">+</span></button>
          {!analysis.can_stage && <p className="field-hint">Nothing can be added: resolve flagged keys, or every key is already present.</p>}
        </div>}
      </section>

      <section className="surface-panel key-list-panel" aria-labelledby="contacts-heading">
        <div className="panel-heading"><div><p className="eyebrow">VERIFIED OUT OF BAND</p><h2 id="contacts-heading">Contacts <span className="count-badge">{loading ? '…' : contacts.length}</span></h2></div><span className="section-index">06</span></div>
        {loading ? <p className="empty-state">Loading contacts…</p> : contacts.length === 0 ? <p className="empty-state">No contacts yet. Import a contact bundle to begin pairing.</p> : <div className="record-list">
          {contacts.map((contact) => <ContactView key={contact.contact_id} contact={contact} working={working} typed={typed} onType={(fingerprint, value) => setTyped((current) => ({ ...current, [fingerprint]: value }))} onVerify={(key) => verify(contact, key)} onRestore={(key) => restore(contact, key)} onReconcile={() => reconcile(contact)} onDiscard={(key) => discard(contact, key)} onConfirm={() => confirmContact(contact)} onDelete={() => removeContact(contact)} />)}
        </div>}
      </section>
    </div>
  </div>
}

function ContactView({ contact, working, typed, onType, onVerify, onRestore, onReconcile, onDiscard, onConfirm, onDelete }: {
  contact: Contact
  working: boolean
  typed: Record<string, string>
  onType: (fingerprint: string, value: string) => void
  onVerify: (key: ContactKey) => void
  onRestore: (key: ContactKey) => void
  onReconcile: () => void
  onDiscard: (key: ContactKey) => void
  onConfirm: () => void
  onDelete: () => void
}) {
  const current = contact.keys.filter((key) => key.state !== 'retired')
  const retired = contact.keys.filter((key) => key.state === 'retired')
  const hasVerified = contact.keys.some((key) => key.state === 'verified')
  const locked = working || contact.deletion_pending
  return <article className="key-record contact-record">
    <div className="record-title"><strong>{contact.label}</strong><small>{contact.confirmed ? 'Confirmed contact' : 'Not confirmed'} · bundle name “{contact.claimed_label}” (self-asserted)</small></div>
    {contact.deletion_pending && <p className="inline-error" role="alert">Deletion did not finish. Some keys could not be updated in your trusted keys. Retry deleting this contact.</p>}
    {contact.needs_reconcile && !contact.deletion_pending && <p className="inline-error" role="alert">Trusted keys are not fully consistent with this contact. Retry cleanup to finish the last change.</p>}
    {current.map((key) => {
      const replaces = key.state !== 'active' ? contact.keys.find((other) => other.state === 'active' && other.purpose === key.purpose) : undefined
      const value = typed[key.fingerprint] ?? ''
      const needsRestore = key.trust_status === 'missing' || key.trust_status === 'downgraded'
      const status = TRUST_TEXT[key.trust_status]
      return <div className="fingerprint-box contact-key" key={key.fingerprint}>
        <span>{key.algorithm} · {key.purpose.toUpperCase()}{key.key_version ? ` · v${key.key_version}` : ''} · {STATE_TEXT[key.state]}{status ? ` · ${status}` : ''}</span>
        <code>{formatFingerprint(key.fingerprint)}</code>
        {replaces && <small className="pairing-detail">Pending replacement for v{replaces.key_version} {formatFingerprint(replaces.fingerprint)}, which stays active until this key is verified and confirmed.</small>}
        {key.trust_origin === 'independent' && <small className="pairing-detail">You trusted this key independently before pairing. Deleting this contact keeps that trust.</small>}
        {key.trust_origin === 'ambiguous' && <small className="pairing-detail">Older key: it is unknown whether you trusted it before pairing. Deleting this contact leaves it as a standalone trusted key, which you can remove afterward in Key Management.</small>}
        {(key.state === 'pending' || needsRestore) && <div className="contact-verify">
          <label className="field-label" htmlFor={`verify-${key.fingerprint}`}>{needsRestore ? 'Re-verify the full fingerprint with this contact to restore trust' : 'Type the full fingerprint you compared with this contact'}</label>
          <input id={`verify-${key.fingerprint}`} className="fingerprint-input" value={value} onChange={(event) => onType(key.fingerprint, event.target.value)} autoComplete="off" spellCheck={false} placeholder="64 hexadecimal characters; spaces optional" disabled={locked} />
          <button className="quiet-button" type="button" onClick={() => needsRestore ? onRestore(key) : onVerify(key)} disabled={locked || !fingerprintMatches(value, key.fingerprint)}>{needsRestore ? 'Restore trust' : 'Verify fingerprint'}</button>
        </div>}
        {(key.state === 'pending' || key.state === 'verified') && <button className="text-danger" type="button" onClick={() => onDiscard(key)} disabled={locked}>Discard key</button>}
      </div>
    })}
    {retired.length > 0 && <details className="contact-history"><summary>Retired keys ({retired.length})</summary>
      {retired.map((key) => <div className="fingerprint-box" key={key.fingerprint}><span>{key.algorithm} · {key.purpose.toUpperCase()} · v{key.key_version} · {TRUST_TEXT[key.trust_status]}</span><code>{formatFingerprint(key.fingerprint)}</code></div>)}
    </details>}
    <div className="record-actions">
      <button className="button button-primary" type="button" onClick={onConfirm} disabled={locked || !hasVerified}>Confirm contact and trust verified keys</button>
      {contact.needs_reconcile && !contact.deletion_pending && <button className="quiet-button" type="button" onClick={onReconcile} disabled={working}>Retry cleanup</button>}
      <button className="text-danger" type="button" onClick={onDelete} disabled={working}>{contact.deletion_pending ? 'Retry deleting contact' : 'Delete contact'}</button>
    </div>
  </article>
}

function fingerprintMatches(value: string, expected: string): boolean {
  const normalized = value.replace(/\s/g, '')
  return /^[0-9a-fA-F]{64}$/.test(normalized) && normalized.toLowerCase() === expected.toLowerCase()
}

function formatFingerprint(value: string): string {
  return value.match(/.{1,4}/g)?.join(' ') ?? value
}

function safeMessage(reason: unknown): string {
  return reason instanceof Error ? reason.message : 'The local service could not complete the request.'
}
