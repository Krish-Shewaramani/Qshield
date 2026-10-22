# QuantumShield — Project Brief

**Status:** Phase 2B design update based on the reported Phase 2A proof of concept; D4 is provisionally selected for the academic prototype. The envelope is not integrated into application code.
**Project:** QuantumShield — Post-Quantum Cryptographic File Exchange System
**Context:** University course on Quantum Communication and Cryptography; professor approved a PQC-only scope.

---

## 1. Objective

A local, educational web application that lets a **sender** encrypt and sign a file for a **recipient**, and lets the recipient **verify and decrypt** it, using NIST-standardized post-quantum algorithms for key establishment and signatures.

| Component | Algorithm | Standard | PQC? | Role |
|---|---|---|---|---|
| Key establishment | ML-KEM-768 | FIPS 203 | Yes | Shared secret between sender and recipient |
| Digital signature | ML-DSA-65 | FIPS 204 | Yes | Sender authenticity + package integrity |
| Key derivation | HKDF-SHA-256 | RFC 5869 | No | Derive AES key from the ML-KEM secret, with context |
| File encryption | AES-256-GCM | NIST SP 800-38D | No | Authenticated encryption of file contents |

## 2. Scope

**In scope:** React/TS frontend, FastAPI backend, real cryptography (no mocks), key management, `.qshield` package format, automated tests, benchmark script, academic documentation.

**Out of scope:** quantum key distribution / quantum communication, custom cryptographic primitives, classical fallback (RSA/ECC), databases, public deployment, multi-user accounts, formal certification.

## 3. Current state of the repository

No existing project was provided (the upload folder was empty). This is a greenfield build. An isolated Phase 2A experiment exists under `experiments/phase2a_serialization/`; no production application code exists yet.

## 4. Dependency compatibility findings

The primitive checks in §§4.1–4.2 were run in a Linux sandbox (x86_64, Python 3.12.3). The separate Phase 2A Windows serialization results are summarized in §4.3.

### 4.1 Selected cryptography library: `cryptography==50.0.2`

One maintained library covers all four primitives, so the project needs a single cryptographic dependency.

| Check | Result | How verified |
|---|---|---|
| `MLKEM768PrivateKey` / `MLKEM768PublicKey` exist | Yes | Imported and inspected |
| `MLDSA65PrivateKey` / `MLDSA65PublicKey` exist | Yes | Imported and inspected |
| ML-KEM-768 encapsulate/decapsulate round trip | Shared secrets match | Executed |
| ML-KEM-768 sizes | public key 1184 B, ciphertext 1088 B, shared secret 32 B | Executed; these match the FIPS 203 parameter set for ML-KEM-768 |
| ML-DSA-65 sign/verify round trip | Valid signature accepted | Executed |
| ML-DSA-65 sizes | public key 1952 B, signature 3309 B | Executed; these match the FIPS 204 parameter set for ML-DSA-65 |
| Modified signed data | Rejected with `InvalidSignature` | Executed |
| ML-DSA `context` parameter | Supported on `sign`/`verify` | Executed (used for domain separation) |
| HKDF-SHA-256 (32-byte output) | Works | Executed |
| AES-256-GCM round trip; tampered AAD | Works; `InvalidTag` raised on tamper | Executed |
| Windows wheel | `cryptography-50.0.2-cp311-abi3-win_amd64.whl` exists on PyPI | The Phase 2A experiment reportedly ran with Python 3.14.2 on Windows 11. Requires Python ≥ 3.11 |

The checks above were ad-hoc primitive checks, not the project's test suite. The separate Phase 2A experiment suite is reported in §4.3; it does not test production application code.

### 4.2 Behaviours that affect the design

1. **ML-KEM uses implicit rejection.** Decapsulating with the wrong private key, or with a tampered KEM ciphertext, raised **no error** — it silently returned a different shared secret (executed and confirmed for both cases). A wrong key or tampered encapsulation therefore only becomes visible when AES-GCM authentication fails. The protocol and UI must not assume decapsulation signals failure.
2. **Passphrase-encrypted PKCS#8 is weak by default.** `BestAvailableEncryption` produced PBES2 with PBKDF2-HMAC-SHA256 at **2048 iterations** and AES-256-CBC (read directly from the generated key's ASN.1 structure). That is low by current guidance against offline passphrase guessing. See Decision D4.
3. **Public keys serialize as SPKI PEM** for ML-KEM-768 (executed). ML-DSA-65 SPKI export is still to be confirmed in Phase 2.

### 4.3 Phase 2A Windows serialization and storage experiment

The reported Phase 2A run used Windows 11, Python 3.14.2, and `cryptography==50.0.2`; its isolated experiment suite passed 10 tests. The tests exercised ML-KEM-768 and ML-DSA-65 PKCS#8 DER serialization and reload, native encrypted PKCS#8 behavior, and the experimental envelope. These are proof-of-concept results, not application integration or an independent security review.

The provisionally selected academic-prototype format serializes the private-key object as unencrypted PKCS#8 DER in memory, then encrypts those DER bytes. It does not export or depend on raw PQC key seeds. The version-1 `QSKS` binary envelope (versioning independent of `.qshield`) has a 42-byte fixed header: magic (4 bytes), format version (1 byte), `log_n` (1 byte), big-endian `r` and `p` (4 bytes each), random salt (16 bytes), and random AES-GCM nonce (12 bytes). The complete header is AES-256-GCM associated data. The ciphertext is followed by the 16-byte tag. Accepted scrypt values are `log_n=12..17`, `r=8`, `p=1`; the default is `N=131072` (`log_n=17`), and `maxmem` is 160 MiB. Unsupported versions and parameter values are rejected before scrypt.

At the default, the reported median scrypt runtime was approximately 314.6 ms. The dominant memory estimate is 128 MiB (`128*N*r`); this is an estimate, not a measured process peak. Wrong passphrases and modified authenticated envelope data fail AES-GCM authentication and do not yield a loaded private key. The passphrase is supplied per operation and is not stored or logged. Python does not guarantee secure zeroization of PKCS#8 DER, passphrases, or other secret buffers.

### 4.4 Other backend packages

`fastapi==0.143.0`, `uvicorn==0.54.0`, `python-multipart==0.0.32`, `pytest==9.1.1`, `httpx==0.28.1` installed together without dependency conflicts (transitives seen: `pydantic 2.14.1`, `starlette 1.8.0`). No application code has run against them yet. Full transitive pins will be generated and committed in Phase 2.

### 4.5 Frontend toolchain (not yet installed or tested)

Latest published versions seen on npm today: React 19.3.0, TypeScript 7.0.2, Tailwind CSS 4.3.3, Vitest 5.0.4. Vite declares Node `^20.19.0 || >=22.12.0`. Exact pins will be chosen and install-tested at the start of Phase 4. TypeScript 7 is a major release, so compatibility with the Vite/Vitest/React plugin versions needs to be verified then rather than assumed.

### 4.6 Alternatives considered

| Option | Decision | Reason |
|---|---|---|
| `liboqs-python` 0.16.0.1 | Not selected | The package is a ~14 kB pure-Python wheel, so it contains no native code and depends on a separately built `liboqs` library. Building that on Windows needs CMake and a C compiler, which is a fragile setup for a course project. (Native-library requirement is my understanding of the project; not tested here.) |
| `kyber-py` / `dilithium-py` | Not selected | Pure-Python educational implementations. From my knowledge their authors do not recommend them for production use; not tested here. |
| `mlkem` 0.2.0, `pqcrypto` 1.0.0 | Not evaluated | `cryptography` already satisfies every requirement. |

No fallback to classical algorithms exists anywhere in the design. If the library fails the startup self-check, the backend refuses to start.

## 5. Adjustments to the proposed file structure (§7A)

The structure is kept almost intact. Changes, with reasons:

| Change | Reason |
|---|---|
| **Add** `api/routes/logs.py`, `api/schemas/logs.py`, `core/activity_log.py`, frontend `services/logService.ts` | The required Activity and Security Logs screen has no endpoint in the original tree |
| **Add** `key_management/trust_store.py` | The trust mechanism for sender and recipient public keys is a core requirement and deserves its own module |
| **Add** `backend/tests/conftest.py` and `unit/test_package_format.py` | Shared fixtures; parser/format tests separate from adversarial tests |
| **Use** `%LOCALAPPDATA%\QuantumShield\` for runtime data on Windows | Store encrypted private keys in `keys/`, trusted public keys in `trust/`, and non-sensitive logs in `logs/`; keep all runtime data outside the repository and served directories |
| **Role split:** `pyproject.toml` holds tool config only (pytest); `requirements.txt` holds all pins | Avoids two files declaring dependencies that can drift apart |
| **Drop** `AGENTS.md`, `CLAUDE.md`, `LICENSE` for now | Not needed for the build; `LICENSE` can be added when you decide how to publish |
| **Defer** `docs/diagrams/*.mmd` | Diagrams are embedded in `docs/ARCHITECTURE.md` for review now and exported to `.mmd` files in Phase 6, once they match the real code |
| **Defer** `PassphraseDialog.tsx` (new component) | Needed for unlocking private keys; created in Phase 4 |

Per your instruction, files are created only when their phase needs them.

## 6. Decision register

D4 is provisionally selected for the academic prototype based on the isolated Phase 2A experiment. Other decisions remain subject to the approvals recorded in their rows; no application integration is implied.

| # | Decision | Recommendation |
|---|---|---|
| **D1** | Use `cryptography==50.0.2` as the only cryptographic library | Approve |
| **D2** | Binary `.qshield` package v1 with fixed-layout header, signing `header ‖ ciphertext` with the ML-DSA context string, and the header also used as AES-GCM AAD (see `CRYPTOGRAPHIC_PROTOCOL.md`) | Approve |
| **D3** | Trust model: a local store of public keys whose fingerprints the user confirms out-of-band. No CA/PKI. Packages never carry the sender's public key | Approve |
| **D4** | Private-key storage at rest. **A:** native encrypted PKCS#8 (observed PBES2, PBKDF2-HMAC-SHA256, 2,048 iterations, AES-256-CBC). **B:** versioned binary envelope encrypting in-memory unencrypted PKCS#8 DER with scrypt + AES-256-GCM; no raw PQC seed export. **C:** Windows DPAPI (not portable) | **B selected provisionally for the academic prototype** based on the Phase 2A experiment: `N=131072` (`log_n=17`), `r=8`, `p=1`, `maxmem=160 MiB`; reported median 314.6 ms and estimated dominant memory 128 MiB (`128*N*r`), not measured peak. Custom format remains unaudited and not production-ready; it is not yet integrated. |
| **D5** | Passphrase is sent per operation to a localhost-only backend, never stored, never logged; no persistent "unlocked" session | Approve |
| **D6** | Limits: 25 MiB maximum input file; package limit = file limit + 64 KiB | Approve, or give me another figure |
| **D7** | Backend never writes plaintext to disk: decrypted bytes are held in memory and returned in the HTTP response only after every check passes | Approve |
| **D8** | Recommended runtime: Python 3.12 on Windows (3.11 is the floor implied by the wheel) and Node ≥ 22.12 | Confirm what is installed on your machine |

## 7. Milestone summary

Full file-by-file mapping is in `ARCHITECTURE.md` §8.

| Phase | Goal | Exit criteria |
|---|---|---|
| 1 | Design, protocol, threat model | **This deliverable**; your approval |
| 2 | Crypto proof of concept | Phase 2A Windows serialization/envelope test results and the `N=131072` scrypt benchmark are reported; production backend integration remains future work |
| 3 | Secure backend | Key management, packaging, encrypt/decrypt/verify, all adversarial tests pass |
| 4 | Frontend + integration | All six screens work against the real backend |
| 5 | Hardening + evaluation | Full test run, dependency review, benchmark script run with real results |
| 6 | Documentation + demo | Remaining docs, exported diagrams, demo plan |

## 8. Known limitations at this stage

- The isolated serialization proof of concept was reportedly run on Windows 11 with Python 3.14.2 and `cryptography==50.0.2`; production code has not been implemented or tested.
- The selected envelope parameters and measured runtime do not establish an adequate security level against offline passphrase guessing; the envelope has not been independently audited.
- Mermaid diagrams have not been rendered; syntax is unvalidated.
- Package-size figures in the protocol document are computed from the layout, not measured.
- Side-channel resistance of the library has not been independently assessed.
