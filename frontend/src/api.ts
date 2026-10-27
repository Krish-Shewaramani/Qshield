export type HealthResponse = {
  status: string
  cryptography: string
  algorithms: string[]
}

export type KeyRecord = {
  algorithm: string
  key_id: string
  label: string
  public_key_pem: string
}

export type TrustUsage = 'full' | 'verify_only' | 'suspended'
export type TrustedKeyRecord = KeyRecord & {
  trusted: boolean
  // Optional for compatibility with responses that predate contact lifecycle fields.
  usage?: TrustUsage
  contact_id?: string | null
  contact_label?: string | null
  contact_key_state?: string | null
  trust_origin?: string | null
}
export const fullyTrusted = (record: TrustedKeyRecord) => record.trusted && (record.usage ?? 'full') === 'full'
export type PublicKeyPreview = Pick<KeyRecord, 'algorithm' | 'key_id' | 'public_key_pem'>
export type VerifyResponse = {
  verified: boolean
  sender_key_id: string
  recipient_key_id: string
  created_at: number
}

export type ContactBundleKey = {
  purpose: 'encryption' | 'signing'
  algorithm: string
  public_key_pem: string
  fingerprint: string
}
export type ContactBundle = {
  format: 'quantumshield-contact-bundle'
  version: 1
  label: string
  keys: ContactBundleKey[]
}
export type ContactBundlePreview = {
  label: string
  keys: { purpose: string; algorithm: string; key_id: string; public_key_pem: string }[]
  trusted: false
}

export type PairingStatus = 'new_key' | 'new_purpose' | 'pending_replacement' | 'already_present' | 'conflict' | 'previously_retired' | 'pending_conflict'
export type KeyAssessment = {
  fingerprint: string
  algorithm: string
  purpose: string
  status: PairingStatus
  detail: string
  in_trusted_keys: boolean
  current_fingerprint: string | null
  current_key_version: number | null
  conflicting_contact_id: string | null
  conflicting_contact_label: string | null
}
export type PairingAnalysis = {
  claimed_label: string
  target_contact_id: string | null
  keys: KeyAssessment[]
  matching_contacts: { contact_id: string; label: string }[]
  can_stage: boolean
}
export type ContactKeyState = 'pending' | 'verified' | 'active' | 'retired'
export type ContactKey = {
  fingerprint: string
  algorithm: string
  purpose: string
  public_key_pem: string
  state: ContactKeyState
  key_version: number | null
  // 'ambiguous': legacy key whose pre-pairing trust was never recorded.
  trust_origin: 'independent' | 'contact' | 'ambiguous' | null
  trust_status: ContactTrustStatus
  trust_usage: TrustUsage | null
  added_at: number
  verified_at: number | null
  activated_at: number | null
  retired_at: number | null
  in_trusted_keys: boolean
  usable_for_exchange: boolean
  usable_for_encryption: boolean
  usable_for_verification: boolean
}
export type ContactTrustStatus = 'untrusted' | 'trusted' | 'activation_pending' | 'missing' | 'downgraded' | 'retired'
  | 'verification_only' | 'suspended' | 'cleanup_pending' | 'history_unavailable'
export type Contact = {
  contact_id: string
  label: string
  claimed_label: string
  confirmed: boolean
  deletion_pending: boolean
  needs_reconcile: boolean
  created_at: number
  keys: ContactKey[]
}
export type StageResult = { analysis: PairingAnalysis; contact: Contact | null; staged_fingerprints: string[] }
export type ConfirmResult = { contact: Contact; activated: string[]; retired: string[]; activation_pending: string[] }
export type ReconcileResult = { contact: Contact; failed: string[] }
export type ContactStorage = { state: 'ready' | 'missing' | 'invalid'; message: string | null; suspended_encryption_keys?: number }

type GenerateKeyInput = { label: string; passphrase: string }
type ImportTrustedKeyInput = {
  label: string
  public_key_pem: string
  confirmed_fingerprint: string
}

const apiBase = resolveApiBase(import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000')

function resolveApiBase(value: string): string | null {
  try {
    const url = new URL(value)
    if (
      url.protocol !== 'http:' ||
      !['127.0.0.1', 'localhost'].includes(url.hostname) ||
      url.port !== '8000' ||
      (url.pathname !== '/' && url.pathname !== '') ||
      url.username || url.password || url.search || url.hash
    ) return null
    return url.origin
  } catch {
    return null
  }
}

function apiUrl(path: string): string {
  if (!apiBase) throw new Error('VITE_API_BASE_URL must use the local backend at http://127.0.0.1:8000 or http://localhost:8000.')
  return `${apiBase}${path}`
}

async function getJson<T>(path: string): Promise<T> {
  const url = apiUrl(path)
  let response: Response
  try {
    response = await fetch(url, {
      headers: { Accept: 'application/json' },
      credentials: 'omit',
    })
  } catch {
    throw new Error('Could not reach the local QuantumShield backend.')
  }

  if (!response.ok) throw await responseError(response)
  return (await response.json()) as T
}

async function sendJson<T>(path: string, method: 'POST' | 'DELETE', body?: unknown): Promise<T | undefined> {
  const url = apiUrl(path)
  let response: Response
  try {
    response = await fetch(url, {
      method,
      headers: body === undefined ? { Accept: 'application/json' } : { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'omit',
    })
  } catch {
    throw new Error('Could not reach the local QuantumShield backend.')
  }

  if (!response.ok) throw await responseError(response)
  if (response.status === 204) return undefined
  return (await response.json()) as T
}

async function responseError(response: Response): Promise<Error> {
  let detail = ''
  try {
    const result: unknown = await response.json()
    if (typeof result === 'object' && result !== null && 'detail' in result) {
      const value = result.detail
      if (typeof value === 'string') detail = value
      else if (Array.isArray(value)) detail = value.map((item) => typeof item === 'object' && item !== null && 'msg' in item ? String(item.msg) : 'Invalid input').join('; ')
    }
  } catch {
    // Do not surface an unstructured response body to the interface.
  }
  return new Error(detail || `The backend returned HTTP ${response.status}.`)
}

export const api = {
  getHealth: () => getJson<HealthResponse>('/api/health'),
  listKeys: () => getJson<KeyRecord[]>('/api/keys'),
  listTrustedKeys: () => getJson<TrustedKeyRecord[]>('/api/trusted-keys'),
  generateKemKey: (input: GenerateKeyInput) => sendJson<KeyRecord>('/api/keys/kem', 'POST', input),
  generateSignatureKey: (input: GenerateKeyInput) => sendJson<KeyRecord>('/api/keys/sig', 'POST', input),
  exportPublicKey: async (keyId: string) => {
    const url = apiUrl(`/api/keys/${encodeURIComponent(keyId)}/public`)
    let response: Response
    try {
      response = await fetch(url, { credentials: 'omit' })
    } catch {
      throw new Error('Could not reach the local QuantumShield backend.')
    }
    if (!response.ok) throw await responseError(response)
    return response.blob()
  },
  deleteKey: (keyId: string) => sendJson<void>(`/api/keys/${encodeURIComponent(keyId)}`, 'DELETE'),
  previewPublicKey: (public_key_pem: string) => sendJson<PublicKeyPreview>('/api/trusted-keys/preview', 'POST', { public_key_pem }),
  importTrustedKey: (input: ImportTrustedKeyInput) => sendJson<TrustedKeyRecord>('/api/trusted-keys', 'POST', input),
  reauthorizeTrustedKey: (keyId: string, confirmed_fingerprint: string) =>
    sendJson<TrustedKeyRecord>(`/api/trusted-keys/${encodeURIComponent(keyId)}/reauthorize`, 'POST', { confirmed_fingerprint }),
  deleteTrustedKey: (keyId: string) => sendJson<void>(`/api/trusted-keys/${encodeURIComponent(keyId)}`, 'DELETE'),
  exportContactBundle: (input: { label: string; key_ids: string[] }) =>
    sendJson<ContactBundle>('/api/contact-bundles/export', 'POST', input),
  previewContactBundle: (bundle_json: string) =>
    sendJson<ContactBundlePreview>('/api/contact-bundles/preview', 'POST', { bundle_json }),
  listContacts: () => getJson<Contact[]>('/api/contacts'),
  getContactStorage: () => getJson<ContactStorage>('/api/contacts/storage'),
  reinitializeContactStorage: () =>
    sendJson<ContactStorage>('/api/contacts/storage/reinitialize', 'POST', { acknowledge_lost_history: true }),
  analyzePairing: (input: { bundle_json: string; contact_id: string | null }) =>
    sendJson<PairingAnalysis>('/api/contacts/pairing/analyze', 'POST', input),
  stagePairing: (input: { bundle_json: string; contact_id: string | null; label: string | null }) =>
    sendJson<StageResult>('/api/contacts/pairing/stage', 'POST', input),
  verifyContactKey: (contactId: string, fingerprint: string, confirmed_fingerprint: string) =>
    sendJson<Contact>(`/api/contacts/${encodeURIComponent(contactId)}/keys/${encodeURIComponent(fingerprint)}/verify`, 'POST', { confirmed_fingerprint }),
  restoreContactKey: (contactId: string, fingerprint: string, confirmed_fingerprint: string) =>
    sendJson<Contact>(`/api/contacts/${encodeURIComponent(contactId)}/keys/${encodeURIComponent(fingerprint)}/restore`, 'POST', { confirmed_fingerprint }),
  reconcileContact: (contactId: string) =>
    sendJson<ReconcileResult>(`/api/contacts/${encodeURIComponent(contactId)}/reconcile`, 'POST'),
  confirmContact: (contactId: string) =>
    sendJson<ConfirmResult>(`/api/contacts/${encodeURIComponent(contactId)}/confirm`, 'POST'),
  discardContactKey: (contactId: string, fingerprint: string) =>
    sendJson<void>(`/api/contacts/${encodeURIComponent(contactId)}/keys/${encodeURIComponent(fingerprint)}`, 'DELETE'),
  deleteContact: (contactId: string) => sendJson<void>(`/api/contacts/${encodeURIComponent(contactId)}`, 'DELETE'),
  encryptFile: (fields: { file: File; recipientKeyId: string; signingKeyId: string; passphrase: string }) =>
    sendMultipart<Blob>('/api/encrypt', fields, true),
  verifyPackage: (fields: { file: File; senderKeyId: string }) =>
    sendMultipart<VerifyResponse>('/api/verify', fields, false),
  decryptPackage: (fields: { file: File; recipientKeyId: string; senderKeyId: string; passphrase: string }) =>
    sendMultipart<{ blob: Blob; filename: string }>('/api/decrypt', fields, true),
}

async function sendMultipart<T>(
  path: string,
  fields: { file: File; recipientKeyId?: string; signingKeyId?: string; senderKeyId?: string; passphrase?: string },
  binary: boolean,
): Promise<T> {
  const url = apiUrl(path)
  const body = new FormData()
  body.append('file', fields.file, fields.file.name)
  if (fields.recipientKeyId) body.append('recipient_key_id', fields.recipientKeyId)
  if (fields.signingKeyId) body.append('signing_key_id', fields.signingKeyId)
  if (fields.senderKeyId) body.append('sender_key_id', fields.senderKeyId)
  if (fields.passphrase !== undefined) body.append('passphrase', fields.passphrase)

  let response: Response
  try {
    response = await fetch(url, { method: 'POST', body, credentials: 'omit', headers: { Accept: binary ? 'application/octet-stream' : 'application/json' } })
  } catch {
    throw new Error('Could not reach the local QuantumShield backend.')
  }
  if (!response.ok) throw await responseError(response)
  if (path === '/api/decrypt') {
    const disposition = response.headers.get('content-disposition') ?? ''
    const encodedName = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1]
    let filename = 'recovered-file'
    if (encodedName) {
      try { filename = decodeURIComponent(encodedName) } catch { /* Keep the safe fallback. */ }
    }
    return { blob: await response.blob(), filename } as T
  }
  return (binary ? await response.blob() : await response.json()) as T
}
