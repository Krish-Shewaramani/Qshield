import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from './App'
import type { KeyRecord, TrustedKeyRecord } from './api'
import { fingerprintMatches, normalizeFingerprint } from './KeyManagement'

const localKem: KeyRecord = { algorithm: 'ML-KEM-768', key_id: 'a'.repeat(64), label: 'My recipient key', public_key_pem: '-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----\n' }
const localSignature: KeyRecord = { algorithm: 'ML-DSA-65', key_id: 'b'.repeat(64), label: 'My signing key', public_key_pem: '-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----\n' }
const contactKem: TrustedKeyRecord = { algorithm: 'ML-KEM-768', key_id: 'c'.repeat(64), label: 'Remote recipient', public_key_pem: '-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----\n', trusted: true }
const contactSignature: TrustedKeyRecord = { algorithm: 'ML-DSA-65', key_id: 'd'.repeat(64), label: 'Remote sender', public_key_pem: '-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----\n', trusted: true }
const otherContactSignature: TrustedKeyRecord = { algorithm: 'ML-DSA-65', key_id: '1'.repeat(64), label: 'Other sender', public_key_pem: '-----BEGIN PUBLIC KEY-----\nother\n-----END PUBLIC KEY-----\n', trusted: true }

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })

function installApiFetch(verifyStatus = 200, verificationSucceeded = true) {
  let keys = [localKem, localSignature]
  let trusted = [contactKem, contactSignature, otherContactSignature]
  const calls: Array<{ url: string; init: RequestInit }> = []
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input)
    calls.push({ url, init })
    if (url.endsWith('/api/health')) return json({ status: 'ok', cryptography: 'ready', algorithms: ['ML-KEM-768', 'ML-DSA-65', 'AES-256-GCM', 'HKDF-SHA-256'] })
    if (url.endsWith('/api/keys') && init.method === undefined) return json(keys)
    if (url.endsWith('/api/trusted-keys') && init.method === undefined) return json(trusted)
    if (url.endsWith('/api/keys/kem') && init.method === 'POST') {
      const input = JSON.parse(String(init.body)) as { label: string }
      const created = { ...localKem, key_id: 'e'.repeat(64), label: input.label }
      keys = [...keys, created]
      return json(created, 201)
    }
    if (url.endsWith('/api/trusted-keys/preview') && init.method === 'POST') {
      return json({ algorithm: 'ML-DSA-65', key_id: 'f'.repeat(64), public_key_pem: '-----BEGIN PUBLIC KEY-----\ncanonical\n-----END PUBLIC KEY-----\n' })
    }
    if (url.endsWith('/api/trusted-keys') && init.method === 'POST') {
      const input = JSON.parse(String(init.body)) as { label: string; confirmed_fingerprint: string }
      const created = { ...contactSignature, key_id: 'f'.repeat(64), label: input.label }
      trusted = [...trusted, created]
      return json(created, 201)
    }
    if (url.endsWith('/api/encrypt') && init.method === 'POST') return new Response(new Uint8Array([81, 83, 72]), { status: 200 })
    if (url.endsWith('/api/verify') && init.method === 'POST') return json({ verified: verificationSucceeded, sender_key_id: 'd'.repeat(64), recipient_key_id: 'a'.repeat(64), created_at: 1781913600 }, verifyStatus)
    if (url.endsWith('/api/decrypt') && init.method === 'POST') {
      return new Response(new Uint8Array([112, 108, 97, 105, 110]), { status: 200, headers: { 'Content-Disposition': "attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.txt" } })
    }
    return json({ detail: 'Not found' }, 404)
  })
  vi.stubGlobal('fetch', fetchMock)
  return { fetchMock, calls }
}

beforeEach(() => {
  installApiFetch()
  vi.stubGlobal('URL', Object.assign(window.URL, {
    createObjectURL: vi.fn(() => 'blob:quantumshield-test'),
    revokeObjectURL: vi.fn(),
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('QuantumShield frontend workflows', () => {
  it('normalizes fingerprints and requires exactly 64 hexadecimal characters', () => {
    const expected = 'f'.repeat(64)
    expect(normalizeFingerprint(expected)).toBe(expected)
    expect(fingerprintMatches(expected, expected)).toBe(true)
    expect(fingerprintMatches(expected.match(/.{1,4}/g)?.join(' ') ?? '', expected)).toBe(true)
    expect(fingerprintMatches('e'.repeat(64), expected)).toBe(false)
    expect(fingerprintMatches(`${'f'.repeat(63)}g`, expected)).toBe(false)
    expect(fingerprintMatches('f'.repeat(63), expected)).toBe(false)
    expect(fingerprintMatches('f'.repeat(65), expected)).toBe(false)
  })

  it('renders live backend status and the returned key count', async () => {
    render(<App />)
    expect(await screen.findByText('Ready for local use')).toBeTruthy()
    await waitFor(() => expect(document.querySelector('.status-bottom strong')?.textContent).toContain('2'))
  })

  it('sends key generation to the actual route contract and clears the passphrase field', async () => {
    const user = userEvent.setup()
    const { calls } = installApiFetch()
    render(<App />)
    await user.click(await screen.findByRole('button', { name: /Key management/ }))
    await user.type(screen.getByLabelText('Key label'), 'New local recipient')
    await user.type(screen.getByLabelText('Protect this private key'), 'temporary passphrase')
    await user.click(screen.getByRole('button', { name: /Generate key pair/ }))
    expect(await screen.findByText(/ML-KEM-768 key “New local recipient” created/)).toBeTruthy()
    const request = calls.find((call) => call.url.endsWith('/api/keys/kem') && call.init.method === 'POST')
    expect(request).toBeTruthy()
    expect(JSON.parse(String(request?.init.body))).toEqual({ label: 'New local recipient', passphrase: 'temporary passphrase' })
    expect((screen.getByLabelText('Protect this private key') as HTMLInputElement).value).toBe('')
  })

  it('requires matching out-of-band fingerprint confirmation before trusting a key', async () => {
    const user = userEvent.setup()
    const { calls } = installApiFetch()
    render(<App />)
    await user.click(await screen.findByRole('button', { name: /Key management/ }))
    await user.type(screen.getByLabelText('Public key · SPKI PEM'), '-----BEGIN PUBLIC KEY-----\nexample\n-----END PUBLIC KEY-----')
    await user.click(screen.getByRole('button', { name: /Inspect public key/ }))
    await screen.findByText('Backend-derived key fingerprint')
    await user.type(screen.getByLabelText('Contact label'), 'New contact')
    const confirmation = screen.getByLabelText(/Type the 64-character fingerprint/) as HTMLInputElement
    await user.type(confirmation, '0'.repeat(64))
    const trustButton = screen.getByRole('button', { name: /Trust this public key/ }) as HTMLButtonElement
    expect(trustButton.disabled).toBe(true)
    expect(calls.some((call) => call.url.endsWith('/api/trusted-keys') && call.init.method === 'POST')).toBe(false)
    await user.clear(confirmation)
    await user.type(confirmation, 'f'.repeat(64).match(/.{1,4}/g)?.join(' ') ?? '')
    await user.click(trustButton)
    expect(await screen.findByText(/“New contact” is now in your local trusted-key store/)).toBeTruthy()
    const trustRequest = calls.find((call) => call.url.endsWith('/api/trusted-keys') && call.init.method === 'POST')
    expect(JSON.parse(String(trustRequest?.init.body))).toEqual({
      public_key_pem: '-----BEGIN PUBLIC KEY-----\ncanonical\n-----END PUBLIC KEY-----\n',
      label: 'New contact',
      confirmed_fingerprint: 'f'.repeat(64),
    })
  })

  it('submits the documented encrypt multipart fields and downloads the returned package', async () => {
    const user = userEvent.setup()
    const { calls } = installApiFetch()
    const downloaded: string[] = []
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { downloaded.push(this.download) })
    render(<App />)
    await user.click(await screen.findByRole('button', { name: /Encrypt file/ }))
    const file = new File(['file bytes'], 'notes.txt', { type: 'text/plain' })
    fireEvent.change(screen.getByLabelText('Select a file to encrypt'), { target: { files: [file] } })
    await user.selectOptions(screen.getByLabelText('Trusted recipient · ML-KEM-768'), contactKem.key_id)
    await user.selectOptions(screen.getByLabelText('Your signing key · ML-DSA-65'), localSignature.key_id)
    await user.type(screen.getByLabelText('Signing-key passphrase'), 'signing passphrase')
    await user.click(screen.getByRole('button', { name: /Create .qshield package/ }))
    expect(await screen.findByText('Your signed .qshield package was created and downloaded.')).toBeTruthy()
    const upload = calls.find((call) => call.url.endsWith('/api/encrypt') && call.init.method === 'POST')
    expect(upload?.init.body).toBeInstanceOf(FormData)
    const fields = upload?.init.body as FormData
    expect(fields.get('file')).toMatchObject({ name: 'notes.txt', type: 'text/plain', size: 10 })
    expect(fields.get('recipient_key_id')).toBe(contactKem.key_id)
    expect(fields.get('signing_key_id')).toBe(localSignature.key_id)
    expect(fields.get('passphrase')).toBe('signing passphrase')
    expect(downloaded).toContain('package.qshield')
    expect((screen.getByLabelText('Signing-key passphrase') as HTMLInputElement).value).toBe('')
  })

  it('shows no initial failure state and requires successful signature verification before decrypt', async () => {
    const user = userEvent.setup()
    const { calls } = installApiFetch()
    const downloaded: string[] = []
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { downloaded.push(this.download) })
    render(<App />)
    await user.click(await screen.findByRole('button', { name: /Verify & decrypt/ }))
    expect(screen.queryByText('Signature not verified')).toBeNull()
    expect(screen.queryByText('Signature verification failed')).toBeNull()
    const packageFile = new File(['package'], 'message.qshield', { type: 'application/octet-stream' })
    fireEvent.change(screen.getByLabelText('Select a .qshield package'), { target: { files: [packageFile] } })
    await user.selectOptions(screen.getByLabelText('Trusted sender · ML-DSA-65'), contactSignature.key_id)
    expect(screen.queryByRole('button', { name: /Decrypt and download file/ })).toBeNull()
    await user.click(screen.getByRole('button', { name: /Verify sender signature/ }))
    expect(await screen.findByText('Signature verified')).toBeTruthy()
    await user.selectOptions(screen.getByLabelText('Your recipient key · ML-KEM-768'), localKem.key_id)
    await user.type(screen.getByLabelText('Private-key passphrase'), 'recipient passphrase')
    await user.click(screen.getByRole('button', { name: /Decrypt and download file/ }))
    expect(await screen.findByText('Authenticated decryption succeeded. The recovered file was downloaded.')).toBeTruthy()
    expect(downloaded).toContain('résumé.txt')
    const verifyRequest = calls.find((call) => call.url.endsWith('/api/verify'))
    expect((verifyRequest?.init.body as FormData).get('sender_key_id')).toBe(contactSignature.key_id)
    const decryptRequest = calls.find((call) => call.url.endsWith('/api/decrypt'))
    const fields = decryptRequest?.init.body as FormData
    expect(fields.get('file')).toMatchObject({ name: 'message.qshield', type: 'application/octet-stream', size: 7 })
    expect(fields.get('recipient_key_id')).toBe(localKem.key_id)
    expect(fields.get('sender_key_id')).toBe(contactSignature.key_id)
    expect(fields.get('passphrase')).toBe('recipient passphrase')
    expect(screen.queryByLabelText('Private-key passphrase')).toBeNull()
  })

  it('shows failure only after a verification request fails and keeps decryption unavailable', async () => {
    const user = userEvent.setup()
    installApiFetch(400, false)
    render(<App />)
    await user.click(await screen.findByRole('button', { name: /Verify & decrypt/ }))
    fireEvent.change(screen.getByLabelText('Select a .qshield package'), { target: { files: [new File(['package'], 'message.qshield')] } })
    await user.selectOptions(screen.getByLabelText('Trusted sender · ML-DSA-65'), contactSignature.key_id)
    expect(screen.queryByText('Signature verification failed')).toBeNull()
    await user.click(screen.getByRole('button', { name: /Verify sender signature/ }))
    expect(await screen.findByText('Signature verification failed')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Decrypt and download file/ })).toBeNull()
  })

  it('clears verification when the selected sender or package changes', async () => {
    const user = userEvent.setup()
    render(<App />)
    await user.click(await screen.findByRole('button', { name: /Verify & decrypt/ }))
    const fileInput = screen.getByLabelText('Select a .qshield package')
    fireEvent.change(fileInput, { target: { files: [new File(['package'], 'message.qshield')] } })
    const senderSelect = screen.getByLabelText('Trusted sender · ML-DSA-65')
    await user.selectOptions(senderSelect, contactSignature.key_id)
    await user.click(screen.getByRole('button', { name: /Verify sender signature/ }))
    expect(await screen.findByText('Signature verified')).toBeTruthy()
    expect(screen.getByRole('button', { name: /Decrypt and download file/ })).toBeTruthy()

    await user.selectOptions(senderSelect, otherContactSignature.key_id)
    expect(screen.queryByText('Signature verified')).toBeNull()
    expect(screen.queryByRole('button', { name: /Decrypt and download file/ })).toBeNull()

    await user.selectOptions(senderSelect, contactSignature.key_id)
    await user.click(screen.getByRole('button', { name: /Verify sender signature/ }))
    expect(await screen.findByText('Signature verified')).toBeTruthy()
    fireEvent.change(fileInput, { target: { files: [new File(['different package'], 'different.qshield')] } })
    expect(screen.queryByText('Signature verified')).toBeNull()
    expect(screen.queryByRole('button', { name: /Decrypt and download file/ })).toBeNull()
  })
})
