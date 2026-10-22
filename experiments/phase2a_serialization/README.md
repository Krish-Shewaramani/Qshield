# Phase 2A Windows serialization experiment

This directory contains an isolated proof of concept. It is not imported by or
connected to application code. The design documents record its envelope as a
provisional academic-prototype choice; the envelope is not integrated.

The experiment checks unencrypted DER PKCS#8 and native
`BestAvailableEncryption` PKCS#8 for ML-KEM-768 and ML-DSA-65, using
`cryptography`'s generic DER private-key loader. It then wraps the in-memory
unencrypted PKCS#8 bytes with scrypt and AES-256-GCM.

The experimental envelope is binary:

| Field | Encoding |
|---|---|
| Magic | 4 bytes: `QSKS` |
| Format version | 1 byte: `1` |
| Scrypt `log_n` | 1 byte |
| Scrypt `r` | 4-byte big-endian integer |
| Scrypt `p` | 4-byte big-endian integer |
| Salt | 16 bytes |
| Nonce | 12 bytes |
| Authenticated ciphertext | AES-GCM ciphertext followed by its 16-byte tag |

The complete fixed header is AES-GCM additional authenticated data. The
experiment accepts `log_n` 12 through 17, with a default of 17 and fixed
`r=8`, `p=1`. At the default, the dominant scrypt memory estimate is 128 MiB.
The envelope sets an explicit `maxmem` of 160 MiB, leaving 32 MiB above that
estimate; it does not silently lower parameters if scrypt fails. The benchmark
separately probes `log_n` 12, 14, 15, 16, and 17.
Each setting uses an explicit `maxmem` equal to `128 * N * r` plus 16 MiB, with a
192 MiB per-run cap. Before each setting and repeat, it checks Windows available
memory and memory load. It stops when memory load is at least 90%, available
memory is less than `maxmem` plus a 512 MiB OS reserve, memory status is
unavailable, or scrypt fails. It does not reduce parameters after a failure.

The estimate `128 * N * r` describes the dominant scrypt memory requirement; it
is not a measured process peak-memory value. The benchmark takes three samples
per setting and reports median, minimum, and maximum runtime.

The reported Windows 11 run used Python 3.14.2 and `cryptography` 50.0.2; its
experiment suite passed 10 tests. The reported median at `N=131072`, `r=8`,
`p=1` was approximately 314.6 ms, with 128 MiB estimated dominant memory (not
measured peak memory). These measurements do not establish a security level.

Neither keys nor passphrases are printed. Private key DER is used in memory and
is never written to a file. Python buffer overwriting is not claimed to provide
secure memory erasure; garbage collection and library copies may retain data.

Run the suite from this directory with:

```powershell
..\..\.venv\Scripts\python.exe -m unittest -v
```

Run the benchmark separately with:

```powershell
..\..\.venv\Scripts\python.exe benchmark_scrypt.py
```

The native encrypted PKCS#8 output is inspected as DER. The report describes
only the parameters actually encoded by this installed version and backend.
