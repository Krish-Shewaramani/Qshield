"""Small local scrypt timing run; no key or benchmark passphrase is printed."""

from __future__ import annotations

import hashlib
import platform
import statistics
import time
import ctypes
from ctypes import wintypes

import cryptography


PASSPHRASE = b"phase2a benchmark input"
R = 8
P = 1
REPEATS = 3
MIB = 1024 * 1024
MAXMEM_EXTRA = 16 * MIB
MAX_PER_RUN_MAXMEM = 192 * MIB
REQUIRED_OS_RESERVE = 512 * MIB
MAX_MEMORY_LOAD_PERCENT = 90
LOG_N_SETTINGS = (12, 14, 15, 16, 17)


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def memory_status() -> tuple[int, int, int]:
    if platform.system() != "Windows":
        raise OSError("Windows memory status is required for this guarded benchmark")
    status = _MemoryStatusEx()
    status.dwLength = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise ctypes.WinError()
    return status.ullTotalPhys, status.ullAvailPhys, status.dwMemoryLoad


def setting_maxmem(estimated_memory: int) -> int:
    # Explicit slack for implementation overhead; this is a library ceiling,
    # not a measured peak-memory value.
    maxmem = estimated_memory + MAXMEM_EXTRA
    if maxmem > MAX_PER_RUN_MAXMEM:
        raise MemoryError(
            f"maxmem {maxmem / MIB:.1f} MiB exceeds configured "
            f"per-run cap {MAX_PER_RUN_MAXMEM / MIB:.1f} MiB"
        )
    return maxmem


def safe_to_run(maxmem: int) -> tuple[bool, str, int, int, int]:
    try:
        total, available, load = memory_status()
    except (OSError, AttributeError) as exc:
        return False, f"memory status unavailable ({type(exc).__name__}: {exc})", 0, 0, 0
    if load >= MAX_MEMORY_LOAD_PERCENT:
        return (
            False,
            f"memory load {load}% meets/exceeds {MAX_MEMORY_LOAD_PERCENT}% stop threshold",
            total,
            available,
            load,
        )
    if available < maxmem + REQUIRED_OS_RESERVE:
        return (
            False,
            f"available memory {available / MIB:.1f} MiB is below maxmem plus "
            f"{REQUIRED_OS_RESERVE / MIB:.0f} MiB OS reserve",
            total,
            available,
            load,
        )
    return True, "within memory guard", total, available, load


def main() -> None:
    print(f"Python: {platform.python_version()} ({platform.platform()})")
    print(f"cryptography: {cryptography.__version__}")
    print(f"scrypt benchmark: r={R}, p={P}, repeats={REPEATS}")
    print(
        f"Safety guard: maxmem=estimate+{MAXMEM_EXTRA // MIB} MiB, "
        f"per-run maxmem cap={MAX_PER_RUN_MAXMEM // MIB} MiB, "
        f"OS reserve={REQUIRED_OS_RESERVE // MIB} MiB, "
        f"stop at memory load >= {MAX_MEMORY_LOAD_PERCENT}%"
    )
    for log_n in LOG_N_SETTINGS:
        n = 1 << log_n
        estimated_memory = 128 * n * R
        try:
            maxmem = setting_maxmem(estimated_memory)
        except MemoryError as exc:
            print(
                f"STOP: log_n={log_n} N={n}, estimated_memory="
                f"{estimated_memory / MIB:.1f} MiB: {exc}; this and higher settings not run"
            )
            break
        allowed, reason, total, available, load = safe_to_run(maxmem)
        if total:
            print(
                f"Memory check: total={total / MIB:.0f} MiB, "
                f"available={available / MIB:.0f} MiB, load={load}%"
            )
        if not allowed:
            print(
                f"STOP before log_n={log_n} N={n}: {reason}; "
                f"estimate={estimated_memory / MIB:.1f} MiB, "
                f"maxmem={maxmem / MIB:.1f} MiB; this and higher settings not run"
            )
            break
        samples = []
        for counter in range(REPEATS):
            allowed, reason, total, available, load = safe_to_run(maxmem)
            if not allowed:
                print(
                    f"STOP during log_n={log_n} after {len(samples)}/{REPEATS} "
                    f"samples: {reason}; remaining samples and higher settings not run"
                )
                break
            salt = bytes([counter + 1]) * 16
            started = time.perf_counter()
            try:
                hashlib.scrypt(
                    PASSPHRASE,
                    salt=salt,
                    n=n,
                    r=R,
                    p=P,
                    dklen=32,
                    maxmem=maxmem,
                )
            except (ValueError, MemoryError, OSError) as exc:
                print(
                    f"FAILED log_n={log_n} N={n}, maxmem={maxmem / MIB:.1f} MiB: "
                    f"{type(exc).__name__}: {exc}; higher settings not run"
                )
                break
            samples.append(time.perf_counter() - started)
        if len(samples) != REPEATS:
            if samples:
                print(
                    f"PARTIAL log_n={log_n} N={n} r={R} p={P}: "
                    f"samples={len(samples)}/{REPEATS}, "
                    f"median={statistics.median(samples):.6f}s, "
                    f"min={min(samples):.6f}s, max={max(samples):.6f}s, "
                    f"estimated_memory={estimated_memory / MIB:.1f} MiB "
                    f"({estimated_memory:,} bytes; 128*N*r estimate), "
                    f"maxmem={maxmem / MIB:.1f} MiB"
                )
            break
        print(
            f"log_n={log_n} N={n} r={R} p={P}: "
            f"median={statistics.median(samples):.6f}s, "
            f"min={min(samples):.6f}s, max={max(samples):.6f}s, "
            f"estimated_memory={estimated_memory / MIB:.1f} MiB "
            f"({estimated_memory:,} bytes; 128*N*r estimate), "
            f"maxmem={maxmem / MIB:.1f} MiB"
        )


if __name__ == "__main__":
    main()
