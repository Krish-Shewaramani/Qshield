import asyncio
import unittest

from fastapi.testclient import TestClient
from starlette.requests import ClientDisconnect

from backend.app.core.config import MAX_API_BODY_BYTES
from backend.app.core.request_security import LocalAPIRequestSecurityMiddleware
from backend.app.main import app


class RequestSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app, base_url="http://127.0.0.1:8000")
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def test_allows_explicit_local_frontend_origins_with_cors(self) -> None:
        for origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
            response = self.client.get("/api/health", headers={"Origin": origin})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers.get("access-control-allow-origin"), origin)
            self.assertEqual(
                response.headers.get("access-control-expose-headers"), "Content-Disposition"
            )

    def test_rejects_untrusted_origin_and_host(self) -> None:
        response = self.client.get("/api/health", headers={"Origin": "https://attacker.example"})
        self.assertEqual(response.status_code, 403)
        response = self.client.get("/api/health", headers={"Host": "attacker.example"})
        self.assertEqual(response.status_code, 400)

    def test_rejects_cross_site_state_change_but_allows_nonbrowser_local_client(self) -> None:
        rejected = self.client.post(
            "/api/trusted-keys/preview",
            json={"public_key_pem": "bad"},
            headers={"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(rejected.status_code, 403)
        missing_origin = self.client.post(
            "/api/trusted-keys/preview",
            json={"public_key_pem": "bad"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(missing_origin.status_code, 403)
        local_client = self.client.post("/api/trusted-keys/preview", json={"public_key_pem": "bad"})
        self.assertEqual(local_client.status_code, 400)
        self.assertEqual(local_client.json(), {"detail": "invalid or unsupported public key"})

    def test_rejects_oversized_body_and_does_not_echo_oversized_passphrase(self) -> None:
        oversized = self.client.post(
            "/api/trusted-keys/preview",
            content=b"x" * (MAX_API_BODY_BYTES + 1),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(oversized.status_code, 413)
        sentinel = "private-passphrase-sentinel-" + "x" * 1100
        validation = self.client.post(
            "/api/keys/kem", json={"label": "test", "passphrase": sentinel}
        )
        self.assertEqual(validation.status_code, 422)
        self.assertNotIn(sentinel, validation.text)

    def test_rejects_duplicate_origin_and_malformed_length(self) -> None:
        duplicate = self.client.get(
            "/api/health",
            headers=[("Origin", "http://localhost:5173"), ("Origin", "http://localhost:5173")],
        )
        self.assertEqual(duplicate.status_code, 403)
        malformed = self.client.get("/api/health", headers={"Content-Length": "-1"})
        self.assertEqual(malformed.status_code, 400)

    def _run_middleware(
        self,
        *,
        path="/api/trusted-keys/preview",
        chunks=(),
        headers=(),
        downstream=None,
        fail_413_send=False,
    ):
        source_index = 0
        source_reads = 0
        events = []
        received_chunks = []
        sent = []

        async def receive():
            nonlocal source_index, source_reads
            source_reads += 1
            events.append(f"receive-{source_reads}")
            if source_index >= len(chunks):
                return {"type": "http.disconnect"}
            body = chunks[source_index]
            source_index += 1
            return {
                "type": "http.request",
                "body": body,
                "more_body": source_index < len(chunks),
            }

        async def send(message):
            if fail_413_send and message.get("status") == 413:
                raise RuntimeError("send failure")
            sent.append(message)

        async def default_downstream(scope, app_receive, app_send):
            events.append("downstream-enter")
            while True:
                message = await app_receive()
                if message["type"] == "http.disconnect":
                    break
                received_chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            await app_send({"type": "http.response.start", "status": 204, "headers": []})
            await app_send({"type": "http.response.body", "body": b"", "more_body": False})

        scope = {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": [(b"host", b"127.0.0.1:8000"), *headers],
            "http_version": "1.1",
            "scheme": "http",
            "query_string": b"",
            "server": ("127.0.0.1", 8000),
            "client": ("127.0.0.1", 12345),
            "root_path": "",
        }
        app = LocalAPIRequestSecurityMiddleware(downstream or default_downstream)
        asyncio.run(app(scope, receive, send))
        response_starts = [m for m in sent if m["type"] == "http.response.start"]
        return {
            "status": response_starts[-1]["status"] if response_starts else None,
            "source_reads": source_reads,
            "received_chunks": received_chunks,
            "events": events,
            "sent": sent,
        }

    def test_rejected_host_and_origin_are_checked_before_body_consumption(self) -> None:
        for headers, expected in (
            ([(b"host", b"attacker.example")], 400),
            ([(b"origin", b"https://attacker.example")], 403),
        ):
            result = self._run_middleware(chunks=[b"must not be read"], headers=headers)
            self.assertEqual(result["status"], expected)
            self.assertEqual(result["source_reads"], 0)

    def test_declared_oversized_content_length_is_rejected_before_body_consumption(self) -> None:
        result = self._run_middleware(
            chunks=[b"must not be read"],
            headers=[(b"content-length", str(MAX_API_BODY_BYTES + 1).encode("ascii"))],
        )
        self.assertEqual(result["status"], 413)
        self.assertEqual(result["source_reads"], 0)

    def test_under_limit_streamed_body_works_with_and_without_content_length(self) -> None:
        body = b"x" * MAX_API_BODY_BYTES
        for headers in ([], [(b"content-length", str(len(body)).encode("ascii"))]):
            result = self._run_middleware(chunks=[body[:20000], body[20000:]], headers=headers)
            self.assertEqual(result["status"], 204)
            self.assertEqual(b"".join(result["received_chunks"]), body)
            self.assertEqual(result["events"][0], "downstream-enter")
            self.assertEqual(result["source_reads"], 2)

    def test_chunked_body_exactly_at_limit_succeeds_and_one_byte_over_is_withheld(self) -> None:
        exact = self._run_middleware(chunks=[b"x" * MAX_API_BODY_BYTES])
        self.assertEqual(exact["status"], 204)
        self.assertEqual(exact["received_chunks"], [b"x" * MAX_API_BODY_BYTES])

        over = self._run_middleware(chunks=[b"x" * MAX_API_BODY_BYTES, b"y"])
        self.assertEqual(over["status"], 413)
        self.assertEqual(over["received_chunks"], [b"x" * MAX_API_BODY_BYTES])
        self.assertEqual(over["source_reads"], 2)
        self.assertEqual(sum(m["type"] == "http.response.start" for m in over["sent"]), 1)

    def test_downstream_starts_before_body_chunks_are_read(self) -> None:
        result = self._run_middleware(chunks=[b"first", b"second"])
        self.assertEqual(result["status"], 204)
        self.assertEqual(result["events"][0], "downstream-enter")
        self.assertEqual(result["events"][1], "receive-1")

    def test_disconnect_is_forwarded_without_hanging_or_inventing_413(self) -> None:
        result = self._run_middleware(chunks=[])
        self.assertEqual(result["status"], 204)
        self.assertEqual(result["source_reads"], 1)

    def test_oversize_after_response_start_does_not_attempt_a_second_response(self) -> None:
        async def early_response(scope, receive, send):
            await send({"type": "http.response.start", "status": 202, "headers": []})
            await send({"type": "http.response.body", "body": b"started", "more_body": True})
            await receive()
            await receive()

        result = self._run_middleware(
            chunks=[b"x" * MAX_API_BODY_BYTES, b"y"], downstream=early_response
        )
        starts = [m for m in result["sent"] if m["type"] == "http.response.start"]
        self.assertEqual([m["status"] for m in starts], [202])
        self.assertEqual(result["sent"][-1], {"type": "http.response.body", "body": b"", "more_body": False})

    def test_expected_disconnect_after_complete_413_is_contained(self) -> None:
        async def disconnect_unwind(scope, receive, send):
            await receive()
            message = await receive()
            self.assertEqual(message["type"], "http.disconnect")
            raise ClientDisconnect()

        result = self._run_middleware(
            chunks=[b"x" * MAX_API_BODY_BYTES, b"y"], downstream=disconnect_unwind
        )
        self.assertEqual(result["status"], 413)
        self.assertEqual(sum(message["type"] == "http.response.start" for message in result["sent"]), 1)

    def test_unrelated_downstream_exception_after_rejection_propagates(self) -> None:
        async def unrelated_error(scope, receive, send):
            await receive()
            await receive()
            raise RuntimeError("downstream failure")

        with self.assertRaisesRegex(RuntimeError, "downstream failure"):
            self._run_middleware(
                chunks=[b"x" * MAX_API_BODY_BYTES, b"y"], downstream=unrelated_error
            )

    def test_failure_sending_413_propagates(self) -> None:
        async def reads_over_limit(scope, receive, send):
            await receive()
            await receive()

        with self.assertRaisesRegex(RuntimeError, "send failure"):
            self._run_middleware(
                chunks=[b"x" * MAX_API_BODY_BYTES, b"y"],
                downstream=reads_over_limit,
                fail_413_send=True,
            )
