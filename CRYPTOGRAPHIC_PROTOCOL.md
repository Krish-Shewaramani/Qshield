# QuantumShield — Cryptographic Protocol (v1 design)

**Status:** Phase 2B design update based on the reported Phase 2A proof of concept. The `.qshield` protocol remains a proposed design; no application integration has occurred. The custom envelope is provisionally selected for the academic prototype only.
No new primitives are invented: the protocol only composes standardized algorithms.

---

## 1. Algorithms and identifiers

| ID byte | Field | Value | Standard | PQC |
|---|---|---|---|---|
| `kem_alg = 0x01` | Key encapsulation | ML-KEM-768 | FIPS 203 | Yes |
| `sig_alg = 0x01` | Signature | ML-DSA-65 | FIPS 204 | Yes |
| `aead_alg = 0x01` | Authenticated encryption | AES-256-GCM | SP 800-38D | No |
| `kdf_alg = 0x01` | Key derivation | HKDF-SHA-256 | RFC 5869 | No |

A parser must reject any other value. There is no algorithm negotiation and no fallback.

These identifiers are only for `.qshield` file exchange. The separate D4
private-key storage envelope uses scrypt (RFC 7914) for local passphrase-based
key wrapping; it does not change the package identifiers or file-exchange
algorithm scope.

## 2. Keys and identity

- **Recipient** owns an ML-KEM-768 key pair (encryption key).
- **Sender** owns an ML-DSA-65 key pair (signing key).
- A user may own both, but the two key types are always kept and displayed separately.
- **Key identifier:** `key_id = SHA-256( alg_name ‖ 0x00 ‖ raw_public_key )` (32 bytes), where `alg_name` is the ASCII string `ML-KEM-768` or `ML-DSA-65`. The algorithm name is included so an ID can never be confused across key types. The UI shows it as grouped hex, e.g. the first 16 hex characters for short display and the full 64 for confirmation.
- **Public-key export:** SPKI PEM (confirmed working for ML-KEM-768; ML-DSA-65 to be confirmed in Phase 2).
- **Private keys** never leave the backend and are proposed to be stored in the versioned envelope in §2.2 (Decision D4 in `PROJECT_BRIEF.md`).

### 2.1 Trust mechanism

A signature only proves "whoever holds the private key matching this public key signed it". It says nothing about who that person is. QuantumShield therefore uses an explicit **local trust store**:

1. A user imports another party's public key (PEM) and gives it a label.
2. The app displays the key's full fingerprint (`key_id`).
3. The user confirms it **out-of-band** (in person, phone call, or another channel they already trust) and ticks an explicit confirmation. Only then is the key stored as trusted.
4. Encryption only accepts a recipient key from the trust store; decryption only accepts a sender key from the trust store.
5. Packages contain only `sender_key_id` and `recipient_key_id`, **never the public keys**. A key found inside an uploaded package is never trusted.

This is deliberately simple, comparable to confirming a fingerprint in an SSH/PGP workflow. There is no certificate authority, no revocation, and no key expiry. These are documented limitations (see `THREAT_MODEL.md`).

### 2.2 Private-key storage envelope (provisional academic-prototype design)

The private-key object is serialized as unencrypted PKCS#8 DER in process
memory, then the DER bytes are encrypted. The design does not extract, store,
or depend on raw ML-KEM or ML-DSA key seeds. The reported Windows Phase 2A
experiment used `cryptography==50.0.2` with Python 3.14.2; its isolated suite
passed 10 tests. These results do not constitute an independent audit or a
production-security finding.

The `QSKS` envelope has its own versioning, independent of the `.qshield`
package version. Version 1 uses this 42-byte fixed header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | Magic: ASCII `QSKS` |
| 4 | 1 | Envelope version: `1`; reject other versions |
| 5 | 1 | Scrypt `log_n`; accepted range 12–17, default 17 (`N=131072`) |
| 6 | 4 | Scrypt `r`, unsigned big-endian; must equal 8 |
| 10 | 4 | Scrypt `p`, unsigned big-endian; must equal 1 |
| 14 | 16 | Random scrypt salt |
| 30 | 12 | Random AES-256-GCM nonce |

The complete header is AES-256-GCM associated data. Scrypt derives a 32-byte
AES key using `r=8`, `p=1`; the envelope uses `maxmem=160 MiB`. The bytes after
the header are AES-256-GCM ciphertext followed by a 16-byte authentication
tag. The parser validates magic, version, minimum envelope length, and all scrypt
parameter bounds before running scrypt; it rejects rather than reducing
unsupported or failing parameters.

An incorrect passphrase or modified authenticated envelope data fails GCM
authentication; no private key is loaded or returned. The application should
map these cases to a generic key-unlock failure. Passphrases are supplied for
each operation, sent only to the localhost backend, and never persisted or
logged. Python cannot guarantee secure zeroization of PKCS#8 DER, passphrases,
or library-managed copies.

On Windows, runtime keys, trusted public keys, and logs are proposed to live
outside the repository under `%LOCALAPPDATA%\QuantumShield\keys`,
`%LOCALAPPDATA%\QuantumShield\trust`, and
`%LOCALAPPDATA%\QuantumShield\logs`, respectively. The encrypted private-key
envelope is stored in `keys/`; the trust store and logs remain separate.

The Phase 2A report measured a median scrypt runtime of approximately 314.6 ms
at `N=131072`, `r=8`, `p=1`. Dominant scrypt memory is estimated as
`128*N*r = 128 MiB`; this is not measured peak process memory. These local
measurements do not establish a security level against passphrase guessing.

## 3. `.qshield` package format, version 1

All integers are **big-endian**. Field sizes are fixed by the algorithm IDs, so no field is variable except the ciphertext.

```
HEADER  (1196 bytes, fixed)
  offset  size  field
  0       8     magic             = 51 53 48 49 45 4C 44 00   ("QSHIELD\0")
  8       2     version           = 0x0001
  10      1     kem_alg           = 0x01
  11      1     sig_alg           = 0x01
  12      1     aead_alg          = 0x01
  13      1     kdf_alg           = 0x01
  14      2     flags             = 0x0000   (reserved; must be zero)
  16      8     created_at        Unix seconds, informational
  24      32    sender_key_id
  56      32    recipient_key_id
  88      1088  kem_ciphertext    ML-KEM-768 encapsulation
  1176    12    nonce             AES-GCM nonce
  1188    8     ciphertext_len    length of the AEAD output below, in bytes

BODY
  1196    ciphertext_len   aead_output = AES-256-GCM ciphertext ‖ 16-byte tag

TRAILER
  ...     3309  signature         ML-DSA-65 signature
```

**AEAD plaintext layout** (encrypted, so the filename is not exposed):

```
  2 bytes   filename_len (u16, 1..255)
  N bytes   filename (UTF-8)
  rest      file contents
```

**Fixed overhead** by construction: 1196 (header) + 2 (filename length) + 16 (tag) + 3309 (signature) = **4523 bytes**, plus the filename. This is calculated from the layout, not measured; Phase 2 tests will confirm it.

### 3.1 Strict parsing rules

The parser treats the package as untrusted and rejects (with one generic "malformed package" class of error):

- total size above the limit, or shorter than the fixed minimum;
- wrong magic, `version != 1`, any unknown algorithm ID, `flags != 0`;
- `ciphertext_len` smaller than 16 + 2 + 1 (tag + filename length + at least a 1-byte name), or `total_size != 1196 + ciphertext_len + 3309` (this rejects trailing bytes and truncation);
- (after decryption) `filename_len` of 0 or above 255, filename that is not valid UTF-8, or whose sanitized form is empty.

Because the layout is fixed and every field is length-checked, **there is exactly one valid byte encoding for a given package**. This avoids the canonicalization pitfalls of JSON or similar text formats.

## 4. Signed representation

```
signed_message = header_bytes ‖ aead_output          (exact bytes as stored in the file)
signature      = ML-DSA-65.Sign( sender_private_key, signed_message, context = "QuantumShield/v1/package" )
```

- The signature covers every security-relevant field: magic, version, all algorithm IDs, flags, timestamp, sender ID, recipient ID, KEM ciphertext, nonce, ciphertext length, and the ciphertext+tag itself.
- The ML-DSA `context` string provides domain separation, so a signature made for QuantumShield packages cannot be reinterpreted as a signature for anything else. (Context parameter confirmed working in the sandbox.)
- This is **encrypt-then-sign**: the recipient can reject a bad package by checking the signature *before* any private-key operation or decryption.

### 4.1 Why `sender_key_id` is also bound into encryption

With a plain encrypt-then-sign design, an attacker who intercepts a package could strip the sender's signature and add their own, so the package appears to come from the attacker. QuantumShield prevents this by binding `sender_key_id` into the AES key derivation (§5) and the GCM AAD. Changing it breaks decryption, and re-signing a modified header fails the AES-GCM check. The attacker cannot repair this because they do not know the shared secret.

## 5. Key derivation and encryption

```
(ss, kem_ciphertext) = ML-KEM-768.Encaps( recipient_public_key )      # fresh every package; ss = 32 bytes
header_hash          = SHA-256( header_bytes )
aes_key              = HKDF-SHA-256( IKM = ss,
                                     salt = none,
                                     info = "QuantumShield/v1/aes-256-gcm-key" ‖ header_hash,
                                     L = 32 )
nonce                = 12 random bytes from the operating-system CSPRNG
aead_output          = AES-256-GCM.Encrypt( aes_key, nonce, plaintext, AAD = header_bytes )
```

- `header_hash` in `info` binds the version, algorithm IDs, both key IDs, the KEM ciphertext, the nonce and the length into the key itself. The same header bytes are also the GCM AAD, which is a deliberate second layer.
- **Salt:** omitted. The ML-KEM shared secret is already a uniformly random 32-byte value, which RFC 5869 treats as suitable key material without a salt. This is a documented design choice.
- **Nonce:** every package uses a freshly derived one-time key (new encapsulation each time), so nonce reuse under one key cannot occur in normal operation. A random nonce is still used, and tests will check that nonces differ across repeated encryptions.
- **Length limit:** inputs are capped far below AES-GCM's per-message limit.
- The shared secret, derived key and plaintext are never logged and never returned by any API.

## 6. Sender procedure

| Step | Action |
|---|---|
| S1 | Validate file: non-empty allowed, size ≤ limit, filename sanitized (no path separators, control characters) |
| S2 | Load recipient public key **from the trust store**; load sender signing key (passphrase unlocks it) |
| S3 | Encapsulate → `ss`, `kem_ciphertext` |
| S4 | Build header (with random nonce, current time, both key IDs) |
| S5 | Derive `aes_key` via HKDF |
| S6 | Encrypt `filename_len ‖ filename ‖ file` with AAD = header |
| S7 | Sign `header ‖ aead_output` with ML-DSA-65 and the context string |
| S8 | Assemble header ‖ aead_output ‖ signature; release temporary references where practical, without claiming secure zeroization |
| S9 | Return package; log a non-sensitive event (key IDs, size, outcome) |

## 7. Recipient verification order

The order is fixed and tested. **No plaintext is produced or returned before step V9 succeeds.**

| Step | Check | On failure |
|---|---|---|
| V1 | Upload size ≤ package limit | Reject: too large |
| V2 | Strict structural parse (§3.1) | Reject: malformed or unsupported version |
| V3 | `recipient_key_id` equals the selected recipient key's ID | Reject: not addressed to this key (this is public information, not an oracle) |
| V4 | `sender_key_id` equals the selected **trusted** sender key's ID | Reject: sender not trusted |
| V5 | Verify ML-DSA-65 signature over `header ‖ aead_output` | Reject: invalid signature |
| V6 | Unlock recipient private key with passphrase using the D4 envelope | Reject generically: could not unlock key (rate-limited); wrong passphrase fails GCM authentication |
| V7 | ML-KEM-768 decapsulate → `ss` | (Never reports failure; see note) |
| V8 | HKDF derivation as in §5 | n/a |
| V9 | AES-256-GCM decrypt with AAD = header | Reject: authentication failed (wrong key or tampered data); discard buffers |
| V10 | Parse and sanitize filename; return file | Reject: malformed content |

**Note on V7/V9:** ML-KEM decapsulation uses implicit rejection. A wrong key or damaged encapsulation yields a different secret instead of an error (observed in the sandbox), so the failure surfaces at V9 as a GCM authentication failure. The UI treats V9 failure as "wrong key or tampered data" without distinguishing them, which also avoids giving an attacker an oracle.

**Verify-only mode:** V1–V5 can run without any private key, to answer "was this package signed by this trusted sender and unmodified?" (used by the Verify screen).

## 8. Plaintext handling

- Decrypted bytes live in memory only and are returned in the HTTP response after V10. The backend writes no plaintext temp files (Decision D7).
- Downloaded file names are the sanitized, decrypted filename, never a path.

## 9. What the protocol does and does not provide

| Property | Provided? | Notes |
|---|---|---|
| Confidentiality of file and filename against anyone without the recipient's ML-KEM private key | Yes | Within the assumptions of AES-256-GCM and ML-KEM-768 |
| Integrity of file and metadata | Yes | Signature plus GCM tag |
| Sender authenticity | Yes, relative to the trust store | Depends on the user confirming the fingerprint correctly |
| Resistance to attack by large quantum computers on the public-key parts | Intended | ML-KEM and ML-DSA are designed for this; this is a design goal, not a proof or certification |
| Forward secrecy | **No** | If the recipient's long-term ML-KEM private key is later compromised, past packages can be decrypted |
| Replay protection | **No** | A valid package can be re-submitted; `created_at` is informational |
| Metadata confidentiality | **No** | Key IDs, timestamp and approximate size are visible |
| Revocation / expiry | **No** | Out of scope for the prototype |
| Non-repudiation guarantees | Not claimed | |

The system is a teaching prototype. It has not been audited or formally certified, and nothing in this document should be read as a claim that it is unbreakable.

## 10. Open items to confirm in Phase 2

1. ML-DSA-65 SPKI public-key export and reload.
2. Application integration and adversarial testing of the D4 envelope; the Phase 2A experiment is isolated and is not an independent audit.
3. Whether the measured scrypt setting gives an acceptable usability and passphrase-guessing tradeoff; the benchmark reports runtime and estimated memory only, not a security level.
4. Measured package overhead vs. the 4523-byte calculation.
