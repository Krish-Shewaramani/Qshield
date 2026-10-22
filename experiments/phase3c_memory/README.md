# Phase 3C upload-memory evaluation

`benchmark_upload_memory.py` starts an isolated Uvicorn child process for each
scenario. Its `LOCALAPPDATA` points to a fresh temporary directory; the probe
does not create or unlock keys and does not save plaintext. It posts deliberately
invalid package bytes to `/api/verify`, so the middleware and multipart parser
process the body but package verification stops before signature or KEM work.

The default command is conservative:

```powershell
.\.venv\Scripts\python.exe experiments\phase3c_memory\benchmark_upload_memory.py
```

It runs 64 KiB and 1 MiB uploads, two concurrent 1 MiB uploads, and a request
rejected using an oversized `Content-Length` before sending a body. A 25 MiB
run requires `--max-size`; an actual over-limit streamed body requires both
`--max-size --oversized-body`. That opt-in runs both an exact overall body-limit
request and a request one byte over. Each scenario uses three fresh child runs
by default; `--runs` changes that count. Concurrency above four requires
`--allow-high-concurrency`. Do not run the large-size opt-ins without checking
available memory and system load first.

## Recorded default run

Environment: Python 3.14.2, 64-bit; Windows 11 build 10.0.26200; Intel64 Family
6 Model 183 Stepping 1. The configured file limit is 25 MiB, package limit is
25 MiB + 64 KiB, multipart allowance is 64 KiB, and `/api/verify` request-body
limit is 26,345,472 bytes.

Memory was measured from inside the backend child with Windows
`GetProcessMemoryInfo`: `PeakPagefileUsage` (peak process private commit) and
`PeakWorkingSetSize`. The reported increase is the scenario's peak private
commit minus its post-warmup baseline peak. These are process-level Windows
counters, not Python-allocation-only measurements and not total system memory.
The data include Python, imported libraries, middleware/parser allocations,
and runtime overhead. High-water counters cannot attribute bytes to one
function, and allocator reuse can conceal later transient allocations.

| Scenario | File payload each | Multipart body each | Concurrent requests | HTTP result | Increase over baseline peak private commit | Peak working set |
|---|---:|---:|---:|---:|---:|---:|
| Small | 65,536 B | 65,844 B | 1 | 400 (expected malformed-package rejection) | 692,224 B (0.66 MiB) | 64,774,144 B (61.77 MiB) |
| Representative large | 1,048,576 B | 1,048,884 B | 1 | 400 (expected malformed-package rejection) | 16,723,968 B (15.95 MiB) | 80,207,872 B (76.49 MiB) |
| Concurrent large | 1,048,576 B | 1,048,884 B | 2 | 400, 400 (expected malformed-package rejection) | 18,071,552 B (17.23 MiB) | 81,383,424 B (77.61 MiB) |
| Oversized declared length | 0 B sent; declared length 26,345,473 B | 0 B sent | 1 | 413 | 0 B above baseline peak | 63,643,648 B (60.70 MiB) |

The 1 MiB upload increased peak private commit by about 15.95 MiB in this run;
the two-request run increased it by about 17.23 MiB. These single-run values
are machine- and allocator-specific; they do not establish a stable multiplier
or a safe concurrency limit. In that default-only run, the actual over-limit
streamed-body and 25 MiB opt-in scenarios were not run. No total-machine memory
pressure measurement was collected for that run.

## Historical controlled opt-in run before bounded callback parsing - 2026-10-18

Command:

```powershell
.\.venv\Scripts\python.exe experiments\phase3c_memory\benchmark_upload_memory.py --max-size --oversized-body --concurrency 2
```

Environment reported by the benchmark: Python 3.14.2, 64-bit; Windows 11
10.0.26200; Intel64 Family 6 Model 183 Stepping 1. Before running, Windows
reported 16,454,352 KiB visible physical memory and 2,662,296 KiB free. A later
stable five-sample check showed 2,082-2,118 MiB available, 8-12% CPU use, and
mostly near-zero paging after a brief spike. There was a short earlier CPU
spike (about 26-53%) and declining available memory; the run started only after
the readings stabilized. The configured limits were 26,214,400 bytes (25 MiB)
per file, 26,279,936 bytes per package, 65,536 bytes multipart overhead, and
26,345,472 bytes for `/api/verify` request bodies.
After the benchmark, three samples showed 2,419-2,439 MiB available and
17-20% CPU utilization; no retry or additional stress run was made.

At that time, `--max-size` added one 25 MiB file upload and `--oversized-body`
sent a file part larger than the verify request limit. The results below are
historical measurements from the prior parser and benchmark behavior. They are
retained for comparison; the current `--oversized-body` behavior is documented
in the following section.

HTTP results (body sizes are measured entity bytes, excluding HTTP chunk
framing):

| Scenario | File payload | Request body | Concurrency | HTTP status(es) | Transport errors |
|---|---:|---:|---:|---|---|
| Small | 65,536 B | 65,844 B | 1 | 400 | None |
| Representative large | 1,048,576 B | 1,048,884 B | 1 | 400 | None |
| Concurrent large | 1,048,576 B each | 1,048,884 B each | 2 | 400, 400 | None |
| Oversized declared length | 0 B sent | 0 B sent | 1 | 413 | None |
| Maximum file size | 26,214,400 B | 26,214,708 B | 1 | 400 | None |
| Streamed over limit | 26,345,473 B | 26,345,778 B | 1 | 413 | None |

Windows `GetProcessMemoryInfo` results from each isolated backend child:

| Scenario | Baseline private commit | Baseline peak private commit | Peak private commit | Increase over baseline peak | Baseline peak working set | Peak working set |
|---|---:|---:|---:|---:|---:|---:|
| Small | 48,934,912 B | 49,049,600 B | 49,967,104 B | 917,504 B | 63,610,880 B | 64,745,472 B |
| Representative large | 49,299,456 B | 49,410,048 B | 67,936,256 B | 18,526,208 B | 63,938,560 B | 82,018,304 B |
| Concurrent large | 49,221,632 B | 49,336,320 B | 67,424,256 B | 18,087,936 B | 63,668,224 B | 81,498,112 B |
| Oversized declared length | 49,213,440 B | 49,332,224 B | 49,332,224 B | 0 B | 63,643,648 B | 63,721,472 B |
| Maximum file size | 49,209,344 B | 49,324,032 B | 469,721,088 B | 420,397,056 B | 63,811,584 B | 471,236,608 B |
| Streamed over limit | 49,106,944 B | 49,221,632 B | 75,710,464 B | 26,488,832 B | 63,778,816 B | 90,345,472 B |

For the maximum-size request, the measured increase was about 400.92 MiB of
peak private commit, with a 449.41 MiB peak working set. The streamed rejection
increased peak private commit by about 25.26 MiB and reached an 86.16 MiB peak
working set. MiB values are conversions from the measured byte counters. These
counters cover only the backend child, not the benchmark client or total system
memory. The 25 MiB request caused substantial process memory growth, consistent
with buffering and parser copies; this single run does not establish a general
memory multiplier or safe concurrency level. No concurrency above two was
tested.

## Bounded streaming parser results - 2026-10-18

Command:

```powershell
.\.venv\Scripts\python.exe experiments\phase3c_memory\benchmark_upload_memory.py --max-size --oversized-body --concurrency 2 --runs 3
```

Environment: Python 3.14.2 x64, Windows 11 build 10.0.26200, Intel64 Family 6
Model 183 Stepping 1; FastAPI 0.143.0, Starlette 1.8.0,
`python-multipart==0.0.32`, and `cryptography==50.0.2`. The verify request-body
limit was 26,345,472 bytes. Immediately before the run, Windows reported about
3,741 MiB available physical memory and 20.3% total CPU load. The benchmark ran
three fresh isolated backend children per scenario and concurrency did not
exceed two.

The parser now uses `MultipartParser` callbacks and bounded in-memory field
buffers. Its accepted upload/package payload is capped at 25 MiB / 25 MiB +
64 KiB; text fields are separately capped. It does not call `request.body()`,
construct a synthetic full MIME message, use `request.form()`, or use
disk-backed spooling. The bytearray-to-bytes conversion at the service boundary
can briefly hold two bounded copies of a large field.

The application requires the closing delimiter marker `--boundary--` to be
followed immediately by CRLF. After that delimiter line, an optional MIME
epilogue is accepted and consumed without being retained or parsed. This
adapter checks the closing-marker offset because `python-multipart==0.0.32`
signals `on_end` at the second closing hyphen and discards the rest of that
parser write. The ASGI chunk is still forwarded to the parser once; the offset
check retains only a short delimiter tail across chunks.

The exact-limit streamed entity kept the package field at its permitted maximum
and used a MIME epilogue to reach exactly 26,345,472 bytes. It returned HTTP
400 with `package is invalid`, as expected for the benchmark's invalid package
bytes; this shows the exact overall body size was accepted by middleware. The
one-byte-over entity was exactly 26,345,473 bytes and returned HTTP 413 with
`request body is too large`. The maximum-file scenario returned HTTP 400 after
the deliberately invalid package reached package validation. The declared
oversize request returned 413 before sending a body. There were no transport
errors.

For each scenario, values below are median (minimum–maximum) across the three
fresh child processes. Private-commit increase is the process peak minus its
post-warmup baseline peak; peak counters are process-level Windows high-water
measurements, not Python allocation tracing or total system memory.

| Scenario | HTTP result | Increase in peak private commit (B) | Peak private commit (B) | Peak working set (B) |
|---|---|---:|---:|---:|
| Small, 64 KiB | 400 × 3 | 0 (0–24,576) | 49,258,496 (49,201,152–49,442,816) | 64,323,584 (64,126,976–64,417,792) |
| 1 MiB upload | 400 × 3 | 2,478,080 (2,326,528–3,665,920) | 51,654,656 (51,548,160–52,822,016) | 66,605,056 (66,396,160–67,264,512) |
| Two concurrent 1 MiB uploads | 400, 400 × 3 | 3,198,976 (2,416,640–4,665,344) | 52,453,376 (51,806,208–53,858,304) | 67,194,880 (66,719,744–68,526,080) |
| Oversized `Content-Length` | 413 × 3 | 0 (0–0) | 49,360,896 (49,307,648–49,369,088) | 64,241,664 (64,135,168–64,319,488) |
| Maximum 25 MiB file | 400 × 3 | 55,980,032 (55,881,728–56,262,656) | 105,267,200 (105,050,112–105,381,888) | 116,867,072 (116,785,152–117,198,848) |
| Chunked exact overall limit | 400, `package is invalid` × 3 | 56,008,704 (55,832,576–56,012,800) | 105,435,136 (105,287,680–105,529,344) | 117,321,728 (117,321,728–117,420,032) |
| Chunked one byte over | 413, `request body is too large` × 3 | 56,098,816 (55,476,224–56,135,680) | 105,201,664 (104,644,608–105,418,752) | 117,039,104 (116,314,112–117,239,808) |

The maximum-file median increase is about 53.39 MiB of peak private commit,
compared with the earlier 211.83 MiB measured after the `BytesFeedParser`
change and 376.36 MiB before that change. The one-byte-over scenario still
retains the permitted maximum package part while it consumes the legal epilogue
that crosses the overall limit; it does not retain the entire accepted request
prefix as a second parsed body. These high-water readings cannot attribute
memory to individual functions. The run does not measure all concurrent maximum
uploads and does not establish a safe concurrency limit or production readiness.

## Shared unlock throttling

All private-key unlocks go through `KeyStore.load_private_key()` via
`KeyService.load_private_key()`: signing-key unlock for `/api/encrypt` and
recipient-key unlock for `/api/decrypt`. The guard is enforced before record
lookup and is shared by default across `KeyStore` instances.

The implemented policy uses a process-wide token bucket with capacity four and
one refill every two seconds; at most one unlock operation can proceed, with
excess work rejected immediately; and a per-key counter of five QSKS AEAD
authentication failures in ten minutes followed by a fixed 30-second cooldown.
Cooldown requests do not extend the cooldown; successful QSKS authentication
clears that key's failure state, and cooldown expiry clears it. Every request
that reaches unlock admission consumes a global token before per-key cooldown
and concurrency checks. Missing keys, wrong algorithms, and malformed records
do not increment per-key failures. State is capped at
512 key IDs; expired entries are pruned first, active cooldowns are never
evicted, and when full, new per-key failures are not tracked beyond global
admission control. Missing private keys, wrong passphrases, malformed key
records, and per-key cooldowns return the same generic API status and detail;
global admission rejection returns a generic 429.

This limiter is temporary throttling, not permanent lockout. Its state is
in-memory, resets on process restart, and is not coordinated across multiple
worker processes. It can still delay legitimate local operations and does not
protect against a local caller who can repeatedly exhaust the global bucket.

## Rate-limiter tests

- `backend/tests/unit/test_unlock_rate_limiter.py`: injectable monotonic clock;
  failure window, cooldown expiry, success reset, independent key IDs, bounded
  state, global token refill, and nonblocking single-KDF concurrency using
  barriers/events rather than sleeps.
- `backend/tests/unit/test_key_management.py`: wrong QSKS passphrases count as
  failures; malformed envelope/type/fingerprint errors do not; a successful
  unlock resets only that key's failures.
- `backend/tests/integration/test_file_exchange_api.py` and
  `test_key_management_api.py`: both encrypt-signing and decrypt-recipient
  paths share the same limiter; repeated failures and generic responses; a
  correct passphrase succeeds after clock-advanced cooldown; independent keys
  remain usable; existing successful key operations stay successful.

Tests use injected clocks and temporary stores so they do not change runtime
key data, sleep for cooldown periods, or make the suite timing-sensitive.
