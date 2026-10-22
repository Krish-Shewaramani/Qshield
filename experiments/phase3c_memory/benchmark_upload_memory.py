"""Measure Windows backend process memory for bounded multipart requests.

Default runs are intentionally modest: 64 KiB, 1 MiB, two concurrent 1 MiB
requests, and a Content-Length-only rejection. Maximum-size and larger
concurrency/body runs require explicit command-line opt-ins.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ctypes
import http.client
import json
import os
import platform
import statistics
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from ctypes import wintypes

ROOT = Path(__file__).resolve().parents[2]
MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_PACKAGE_SIZE = MAX_FILE_SIZE + 64 * 1024
MULTIPART_OVERHEAD = 64 * 1024
VERIFY_BODY_LIMIT = MAX_PACKAGE_SIZE + MULTIPART_OVERHEAD
HOST_HEADER = "127.0.0.1:8000"  # Accepted API Host; socket uses an ephemeral port.


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


def _windows_memory_counters(pid: int) -> PROCESS_MEMORY_COUNTERS_EX:
    if os.name != "nt":
        raise RuntimeError("this process-memory measurement currently requires Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY_INFORMATION | VM_READ
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        counters = PROCESS_MEMORY_COUNTERS_EX()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return counters
    finally:
        kernel32.CloseHandle(handle)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _multipart(payload: bytes, boundary: bytes) -> bytes:
    return b"".join(
        (
            b"--" + boundary + b"\r\n",
            b'Content-Disposition: form-data; name="sender_key_id"\r\n\r\n',
            b"0" * 64 + b"\r\n",
            b"--" + boundary + b"\r\n",
            b'Content-Disposition: form-data; name="file"; filename="memory.bin"\r\n',
            b"Content-Type: application/octet-stream\r\n\r\n",
            payload,
            b"\r\n--" + boundary + b"--\r\n",
        )
    )


def _post(url: str, body: bytes, boundary: bytes) -> int:
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Host": HOST_HEADER,
            "Content-Type": f"multipart/form-data; boundary={boundary.decode('ascii')}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code


def _reject_declared_oversize(port: int) -> int:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        connection.putrequest("POST", "/api/verify", skip_host=True)
        connection.putheader("Host", HOST_HEADER)
        connection.putheader(
            "Content-Type", "multipart/form-data; boundary=QShieldMemoryProbe"
        )
        connection.putheader("Content-Length", str(VERIFY_BODY_LIMIT + 1))
        connection.endheaders()
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def _post_chunked_body(port: int, target_body_size: int) -> dict[str, object]:
    """Send an exact-size multipart entity without Content-Length."""
    boundary = b"QShieldMemoryStream"
    prefix = b"".join(
        (
            b"--" + boundary + b"\r\n",
            b'Content-Disposition: form-data; name="sender_key_id"\r\n\r\n',
            b"0" * 64 + b"\r\n",
            b"--" + boundary + b"\r\n",
            b'Content-Disposition: form-data; name="file"; filename="memory.bin"\r\n',
            b"Content-Type: application/octet-stream\r\n\r\n",
        )
    )
    suffix = b"\r\n--" + boundary + b"--\r\n"
    # Keep the uploaded package part at its exact permitted size, then use a
    # legal MIME epilogue to reach the overall request-body boundary. This
    # separates the middleware limit from the stricter file/package limit.
    payload_size = MAX_PACKAGE_SIZE
    fixed_size = len(prefix) + payload_size + len(suffix)
    if target_body_size < fixed_size:
        raise ValueError("target body size is smaller than the maximum package form")
    epilogue_size = target_body_size - fixed_size
    body_bytes = fixed_size + epilogue_size
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    send_error: str | None = None
    response_error: str | None = None
    status: int | None = None
    response_detail: str | None = None

    def send_chunk(data: bytes) -> None:
        connection.send(f"{len(data):X}\r\n".encode("ascii"))
        connection.send(data)
        connection.send(b"\r\n")

    try:
        connection.putrequest("POST", "/api/verify", skip_host=True)
        connection.putheader("Host", HOST_HEADER)
        connection.putheader(
            "Content-Type", f"multipart/form-data; boundary={boundary.decode('ascii')}"
        )
        connection.putheader("Transfer-Encoding", "chunked")
        connection.endheaders()
        try:
            send_chunk(prefix)
            chunk = b"x" * min(64 * 1024, payload_size)
            remaining = payload_size
            while remaining:
                next_size = min(len(chunk), remaining)
                send_chunk(chunk[:next_size])
                remaining -= next_size
            send_chunk(suffix)
            remaining = epilogue_size
            while remaining:
                next_size = min(len(chunk), remaining)
                send_chunk(chunk[:next_size])
                remaining -= next_size
            connection.send(b"0\r\n\r\n")
        except (OSError, http.client.HTTPException) as exc:
            # The server may close the request once the body limit is crossed.
            # Preserve this transport detail and still try to read its response.
            send_error = f"{type(exc).__name__}: {exc}"
        try:
            response = connection.getresponse()
            status = response.status
            response_data = response.read()
            try:
                response_detail = json.loads(response_data).get("detail")
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                response_detail = None
        except (OSError, http.client.HTTPException) as exc:
            response_error = f"{type(exc).__name__}: {exc}"
    finally:
        connection.close()

    errors = [error for error in (send_error, response_error) if error is not None]
    return {
        "http_status": status,
        "request_body_bytes": body_bytes,
        "payload_bytes": payload_size,
        "response_detail": response_detail if status is not None else None,
        "transfer_encoding": "chunked; Content-Length omitted",
        "errors": errors,
    }


def _wait_ready(process: subprocess.Popen, port: int) -> str:
    url = f"http://127.0.0.1:{port}/api/health"
    deadline = time.monotonic() + 45
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"backend exited early with code {process.returncode}")
        try:
            request = urllib.request.Request(url, headers={"Host": HOST_HEADER})
            with urllib.request.urlopen(request, timeout=2) as response:
                response.read()
                return url
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
            time.sleep(0.2)
    raise RuntimeError(f"backend did not become ready: {last_error}")


def _probe_memory(port: int, endpoint: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/__qshield_memory/{endpoint}",
        headers={"Host": HOST_HEADER},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def _run_scenario(
    name: str,
    payload_size: int,
    concurrency: int,
    *,
    declared_oversize: bool = False,
    streamed_body_size: int | None = None,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="qshield-memory-") as temp_root:
        local_app_data = Path(temp_root) / "LocalAppData"
        local_app_data.mkdir()
        port = _free_port()
        environment = os.environ.copy()
        environment["LOCALAPPDATA"] = str(local_app_data)
        command = [
            sys.executable,
            "-m",
            "uvicorn",
            "experiments.phase3c_memory.memory_worker:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-access-log",
            "--log-level",
            "error",
        ]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        try:
            _wait_ready(process, port)
            # Warm dependency construction and ACL checks, then take the baseline.
            warm_body = _multipart(b"x", b"QShieldWarmup")
            _post(f"http://127.0.0.1:{port}/api/verify", warm_body, b"QShieldWarmup")
            baseline_result = _probe_memory(port, "baseline")
            baseline = baseline_result["current"]

            scenario_errors: list[str] = []
            response_details: list[str | None] = []
            if declared_oversize:
                status_codes = [_reject_declared_oversize(port)]
                request_body_bytes = 0
            elif streamed_body_size is not None:
                result = _post_chunked_body(port, streamed_body_size)
                status_codes = [result["http_status"]]
                request_body_bytes = int(result["request_body_bytes"])
                payload_size = int(result["payload_bytes"])
                response_details = [result.get("response_detail")]
                scenario_errors = result["errors"]
            else:
                payload = b"x" * payload_size
                boundary = b"QShieldMemoryPayload"
                body = _multipart(payload, boundary)
                url = f"http://127.0.0.1:{port}/api/verify"
                with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                    futures = [pool.submit(_post, url, body, boundary) for _ in range(concurrency)]
                    status_codes = [future.result(timeout=90) for future in futures]
                request_body_bytes = len(body)

            measured_result = _probe_memory(port, "stats")
            measured = measured_result["current"]
            return {
                "scenario": name,
                "payload_bytes_each": payload_size,
                "request_body_bytes_each": request_body_bytes,
                "concurrency": concurrency,
                "http_statuses": status_codes,
                "response_details": response_details,
                "errors": scenario_errors,
                "baseline_private_commit_bytes": int(baseline["private_commit_bytes"]),
                "baseline_peak_private_commit_bytes": int(baseline["peak_private_commit_bytes"]),
                "peak_private_commit_bytes": int(measured["peak_private_commit_bytes"]),
                "peak_private_commit_increase_over_baseline_bytes": max(
                    0,
                    int(measured["peak_private_commit_bytes"])
                    - int(baseline["peak_private_commit_bytes"]),
                ),
                "baseline_peak_working_set_bytes": int(baseline["peak_working_set_bytes"]),
                "peak_working_set_bytes": int(measured["peak_working_set_bytes"]),
                "measurement": "Windows GetProcessMemoryInfo; process-level peak commit and peak working set",
            }
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-size", action="store_true", help="opt in to one 25 MiB upload scenario")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=2,
        help="concurrent requests for the 1 MiB scenario (default: 2; values above 4 require --allow-high-concurrency)",
    )
    parser.add_argument("--allow-high-concurrency", action="store_true", help="permit concurrency above 4")
    parser.add_argument(
        "--oversized-body",
        action="store_true",
        help="opt in to exact-limit and one-byte-over streamed verify bodies",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="fresh isolated-child trials per scenario (default: 3)",
    )
    args = parser.parse_args()
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    if args.runs < 1 or args.runs > 10:
        parser.error("--runs must be between 1 and 10")
    if args.concurrency > 4 and not args.allow_high_concurrency:
        parser.error("concurrency above 4 requires --allow-high-concurrency")
    if args.oversized_body and not args.max_size:
        parser.error("--oversized-body also requires --max-size")
    if os.name != "nt":
        parser.error("this evaluation currently uses Windows process-memory counters")

    scenario_specs = [
        ("small", 64 * 1024, 1, {}),
        ("representative-large", 1 * 1024 * 1024, 1, {}),
        ("concurrent-large", 1 * 1024 * 1024, args.concurrency, {}),
        ("oversized-content-length-rejected", 0, 1, {"declared_oversize": True}),
    ]
    if args.max_size:
        scenario_specs.append(("maximum-file-size", MAX_FILE_SIZE, 1, {}))
    if args.oversized_body:
        scenario_specs.extend(
            [
                (
                    "streamed-body-exact-limit",
                    VERIFY_BODY_LIMIT,
                    1,
                    {"streamed_body_size": VERIFY_BODY_LIMIT},
                ),
                (
                    "streamed-body-one-byte-over",
                    VERIFY_BODY_LIMIT + 1,
                    1,
                    {"streamed_body_size": VERIFY_BODY_LIMIT + 1},
                ),
            ]
        )
    scenarios = []
    for name, payload_size, concurrency, options in scenario_specs:
        runs = [
            _run_scenario(name, payload_size, concurrency, **options)
            for _ in range(args.runs)
        ]
        metric_keys = (
            "peak_private_commit_bytes",
            "peak_private_commit_increase_over_baseline_bytes",
            "peak_working_set_bytes",
        )
        summary = {
            key: {
                "median": statistics.median(run[key] for run in runs),
                "minimum": min(run[key] for run in runs),
                "maximum": max(run[key] for run in runs),
            }
            for key in metric_keys
        }
        scenarios.append({"scenario": name, "runs": runs, "summary": summary})
    result = {
        "python": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "memory_scope": "backend child process only; not total machine memory",
        "configured_file_limit_bytes": MAX_FILE_SIZE,
        "configured_package_limit_bytes": MAX_PACKAGE_SIZE,
        "multipart_overhead_limit_bytes": MULTIPART_OVERHEAD,
        "verify_request_body_limit_bytes": VERIFY_BODY_LIMIT,
        "fresh_child_runs_per_scenario": args.runs,
        "scenarios": scenarios,
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
