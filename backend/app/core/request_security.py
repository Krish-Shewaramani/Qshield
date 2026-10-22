"""Host, browser-origin, and bounded-request checks for the local API."""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

from starlette.responses import JSONResponse
from starlette.requests import ClientDisconnect

from backend.app.core.config import (
    API_HOSTS,
    FILE_EXCHANGE_MULTIPART_OVERHEAD_BYTES,
    FRONTEND_ORIGINS,
    MAX_API_BODY_BYTES,
)
from backend.app.file_exchange.protocol import MAX_FILE_SIZE, MAX_PACKAGE_SIZE

_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_BROWSER_METADATA = frozenset({"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer"})


class LocalAPIRequestSecurityMiddleware:
    """Reject unexpected Host/origin headers and cap request memory use."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers: dict[str, list[str]] = defaultdict(list)
        for name, value in scope.get("headers", []):
            headers[name.decode("latin-1").lower()].append(value.decode("latin-1"))

        hosts = headers.get("host", [])
        if len(hosts) != 1 or hosts[0].lower() not in API_HOSTS:
            await JSONResponse({"detail": "invalid local Host header"}, status_code=400)(scope, receive, send)
            return

        origins = headers.get("origin", [])
        if len(origins) > 1:
            await JSONResponse({"detail": "request origin is not allowed"}, status_code=403)(scope, receive, send)
            return
        origin = origins[0] if origins else None
        if origin is not None and origin not in FRONTEND_ORIGINS:
            await JSONResponse({"detail": "request origin is not allowed"}, status_code=403)(scope, receive, send)
            return

        fetch_site_values = headers.get("sec-fetch-site", [])
        if len(fetch_site_values) > 1:
            await JSONResponse({"detail": "invalid browser request metadata"}, status_code=403)(scope, receive, send)
            return
        fetch_site = fetch_site_values[0].lower() if fetch_site_values else None
        if fetch_site == "cross-site" and origin is None:
            await JSONResponse({"detail": "cross-site request is not allowed"}, status_code=403)(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        request_path = scope.get("path", "")
        if method == "POST" and request_path == "/api/encrypt":
            body_limit = MAX_FILE_SIZE + FILE_EXCHANGE_MULTIPART_OVERHEAD_BYTES
        elif method == "POST" and request_path in {"/api/decrypt", "/api/verify"}:
            body_limit = MAX_PACKAGE_SIZE + FILE_EXCHANGE_MULTIPART_OVERHEAD_BYTES
        else:
            body_limit = MAX_API_BODY_BYTES
        if origin is None and method in _STATE_CHANGING_METHODS:
            if any(name in headers for name in _BROWSER_METADATA):
                await JSONResponse(
                    {"detail": "state-changing browser requests require an allowed Origin"},
                    status_code=403,
                )(scope, receive, send)
                return
        elif origin is None and "referer" in headers:
            if len(headers["referer"]) != 1 or _referer_origin(headers["referer"][0]) not in FRONTEND_ORIGINS:
                await JSONResponse({"detail": "request origin is not allowed"}, status_code=403)(scope, receive, send)
                return

        lengths = headers.get("content-length", [])
        if len(lengths) > 1:
            await JSONResponse({"detail": "invalid Content-Length"}, status_code=400)(scope, receive, send)
            return
        if lengths:
            raw_length = lengths[0]
            if not raw_length.isascii() or not raw_length.isdecimal() or len(raw_length) > 20:
                await JSONResponse({"detail": "invalid Content-Length"}, status_code=400)(scope, receive, send)
                return
            if int(raw_length) > body_limit:
                await JSONResponse({"detail": "request body is too large"}, status_code=413)(scope, receive, send)
                return

        total_bytes = 0
        response_started = False
        response_complete = False
        rejected = False

        async def send_limited(message):
            nonlocal response_started, response_complete
            if rejected:
                return
            if message["type"] == "http.response.start":
                response_started = True
            elif message["type"] == "http.response.body" and not message.get("more_body", False):
                response_complete = True
            await send(message)

        async def reject_oversized_request():
            nonlocal response_started, response_complete, rejected
            rejected = True
            if not response_started:
                body = b'{"detail":"request body is too large"}'
                response_started = True
                await send(
                    {
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode("ascii")),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body, "more_body": False})
                response_complete = True
            elif not response_complete:
                # ASGI cannot replace a status after response start. Finish the
                # existing response so the server does not wait for more output.
                await send({"type": "http.response.body", "body": b"", "more_body": False})
                response_complete = True

        async def limited_receive():
            nonlocal total_bytes
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] != "http.request":
                return message
            total_bytes += len(message.get("body", b""))
            if total_bytes > body_limit:
                await reject_oversized_request()
                # The chunk crossing the limit is never delivered downstream.
                return {"type": "http.disconnect"}
            return message

        try:
            await self.app(scope, limited_receive, send_limited)
        except ClientDisconnect:
            # Framework request parsing may raise on the disconnect we expose
            # after sending 413. Contain only that expected unwind, and only
            # once the rejection response is complete. Other failures,
            # including errors while sending the response, must propagate.
            if not rejected or not response_complete:
                raise


def _referer_origin(referer: str) -> str | None:
    try:
        parsed = urlsplit(referer)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None
        return f"{parsed.scheme}://{parsed.netloc}"
    except ValueError:
        return None
