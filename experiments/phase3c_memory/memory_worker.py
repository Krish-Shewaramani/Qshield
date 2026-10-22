"""Benchmark-only ASGI wrapper exposing this process's Windows memory counters."""

from __future__ import annotations

import json
import os

from backend.app.main import app as backend_app
from experiments.phase3c_memory.benchmark_upload_memory import _windows_memory_counters

_baseline: dict[str, int] | None = None


class MemoryProbeApp:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        global _baseline
        if scope["type"] == "http" and scope.get("path") in {
            "/__qshield_memory/baseline",
            "/__qshield_memory/stats",
        }:
            counters = _windows_memory_counters(os.getpid())
            values = {
                "private_commit_bytes": int(counters.PagefileUsage),
                "peak_private_commit_bytes": int(counters.PeakPagefileUsage),
                "working_set_bytes": int(counters.WorkingSetSize),
                "peak_working_set_bytes": int(counters.PeakWorkingSetSize),
            }
            if scope["path"].endswith("/baseline"):
                _baseline = values
            body = json.dumps({"baseline": _baseline, "current": values}).encode("ascii")
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("ascii"))],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


app = MemoryProbeApp(backend_app)
