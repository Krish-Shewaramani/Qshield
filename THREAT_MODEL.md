# QuantumShield — Threat Model (Phase 2B design update)

**Status:** Proposed academic-prototype threat model, updated in Phase 2B with reported Phase 2A storage evidence. It must be refined against application code in Phase 5; the isolated envelope has not been independently audited.
**Scope:** a local academic prototype, run on the user's own machine and not exposed to the internet.

---

## 1. Assets

| Asset | Why it matters |
|---|---|
| Recipient ML-KEM private key | Compromise reveals every package addressed to that key |
| Sender ML-DSA private key | Compromise lets an attacker sign as that sender |
| Key passphrases | Protect private keys at rest |
| Plaintext files | The thing being protected |
| Trust store (trusted public keys) | Tampering can swap in an attacker's key |
| Derived AES keys and KEM shared secrets | Short-lived; compromise reveals one package |
| Activity log | Should not leak secrets or contents |

## 2. Adversaries

| Adversary | Capabilities considered |
|---|---|
| **A1 Network eavesdropper / archiver** | Records `.qshield` packages in transit or from storage and may decrypt them later with a quantum computer ("harvest now, decrypt later") — the motivating threat |
| **A2 Active tamperer** | Modifies, truncates, replays or crafts packages, including re-signing with their own key |
| **A3 Impersonator** | Sends a package claiming to be from a trusted sender, or tricks the user into trusting the wrong public key |
| **A4 Malicious local web page** | A website open in the user's browser tries to call the localhost API (CSRF, DNS rebinding) |
| **A5 Curious local user / stolen disk** | Reads files from the key store while the app is not running |

## 3. Trust assumptions

1. The user's machine and OS are **not compromised** (no malware, keyloggers or memory scraping). This is out of scope; the envelope does not protect keys while unlocked in process memory.
2. The user confirms public-key fingerprints correctly over a channel the attacker does not control.
3. ML-KEM-768, ML-DSA-65, AES-256-GCM and HKDF-SHA-256 are secure as standardized.
4. The `cryptography` library implements them correctly. This has **not** been independently verified here, including constant-time behaviour.
5. The OS random-number generator is secure.
6. The backend is bound to localhost and only the local user can reach it.

## 4. Trust boundaries

Browser UI ⟷ localhost API ⟷ crypto engine ⟷ per-user local data. Private keys, shared secrets, derived keys and plaintext must never cross the browser boundary except for the final recovered file. On Windows, runtime key, trust-store, and log data are proposed for `%LOCALAPPDATA%\QuantumShield\keys`, `%LOCALAPPDATA%\QuantumShield\trust`, and `%LOCALAPPDATA%\QuantumShield\logs`, outside the repository and served folders. See the security boundary diagram in `ARCHITECTURE.md` §7.

## 5. Threats and planned mitigations

| ID | Threat | Mitigation | Planned test |
|---|---|---|---|
| T1 | Eavesdropper reads file contents (A1) | ML-KEM-768 + HKDF + AES-256-GCM | End-to-end test; ciphertext does not contain plaintext |
| T2 | Ciphertext modified | GCM tag + signature | Modified-ciphertext test |
| T3 | Nonce or KEM ciphertext modified | Both are in the signed message, AAD and HKDF info | Modified-nonce / modified-encapsulation tests |
| T4 | Header fields modified (version, algorithm IDs, key IDs) | Covered by signature and AAD; strict parser | Header-field tampering tests |
| T5 | Invalid or forged signature | Verified before decryption; rejection is fatal | Invalid-signature test |
| T6 | Signature stripped and replaced by attacker's (A2) | `sender_key_id` bound into HKDF and AAD | Re-signing test |
| T7 | Package from an untrusted sender key (A3) | Only trust-store keys accepted; embedded keys never used | Untrusted-sender test |
| T8 | User trusts a wrong public key (A3) | Mandatory fingerprint confirmation at import | Documented; UI test; residual risk (§6) |
| T9 | Wrong recipient key | Key-ID check (V3); GCM failure otherwise (implicit rejection) | Wrong-key test |
| T10 | Malformed or oversized package (A2) | Strict parser, length checks, size limits before parsing | Malformed-package, size-boundary tests |
| T11 | Unverified plaintext released | Fixed verification order; response built only after V10 | Failure-path tests assert no plaintext in output |
| T12 | Path traversal via filename | Filename lives inside encrypted payload; sanitized; never used as a path | Filename tests |
| T13 | Private key stolen from disk (A5) | Provisional D4 envelope: in-memory PKCS#8 DER encrypted with scrypt-derived AES-256-GCM; the complete header is AAD; no raw PQC seed export. Wrong passphrases or well-formed tampering fail authentication and yield no loaded key; malformed headers are rejected before scrypt. | Isolated Phase 2A tests passed as reported; application key-storage tests remain required |
| T14 | Offline passphrase guessing | scrypt `N=131072` (`log_n=17`), `r=8`, `p=1`, `maxmem=160 MiB`, instead of the observed native PKCS#8 PBKDF2-HMAC-SHA256 setting of 2,048 iterations | Isolated parameter-bound tests; benchmark reported median 314.6 ms and estimated dominant memory 128 MiB (`128*N*r`), not measured peak memory |
| T15 | Malicious web page calls the API (A4) | Bind to `127.0.0.1`; strict CORS allow-list; `Host` header check; custom request header to force preflight; passphrase required per operation | API tests for rejected origins |
| T16 | Secrets in logs or error messages | Safe logging module; generic errors; allow-list of logged fields | Log-content test |
| T17 | Resource exhaustion (large uploads, repeated key unlocks) | Size limits; rate-limit unlock attempts | Boundary tests |
| T18 | Wrong algorithm silently used | Startup self-check; no fallback; unknown IDs rejected | Unsupported-version/algorithm tests |
| T19 | Nonce reuse | Fresh key per package, random 96-bit nonce | Repeated-encryption uniqueness test |
| T20 | Dependency compromise or drift | Pinned versions, hash-checked install where practical | Dependency review in Phase 5 |

## 6. Limitations and residual risks

- **No forward secrecy:** later compromise of a recipient's private KEM key exposes past packages.
- **No replay protection** and no freshness guarantee.
- **No revocation or expiry:** a leaked key remains trusted until the user removes it.
- **Metadata is visible:** key IDs, timestamp, approximate size.
- **Trust depends on the user:** a wrongly confirmed fingerprint defeats sender authentication.
- **Host compromise is out of scope:** malware can read memory, keys and plaintext.
- **Memory hygiene is best-effort:** Python cannot guarantee secure zeroization of PKCS#8 DER, passphrases, or library-managed copies.
- **Windows file permissions** are weaker than POSIX modes; proposed runtime data lives under the per-user `%LOCALAPPDATA%\QuantumShield\` directory, outside the repository, and private keys are encrypted at rest.
- **Custom-envelope risk remains:** the versioned format and its composition have only isolated proof-of-concept tests; they have not been independently audited and are not production-ready. The measured runtime and estimated memory do not prove a particular security level against passphrase guessing.
- **Side channels** (timing, power) are outside the project's analysis.
- **The demonstration audit log is not tamper-evident** and must not be described as production auditing.
- **Not audited, not certified, and not "unbreakable".** PQC algorithms are designed to resist known quantum attacks, but their long-term security cannot be guaranteed.

## 7. Out of scope

Quantum key distribution and any quantum-communication hardware; network deployment; multi-user authentication; side-channel analysis; formal verification.
