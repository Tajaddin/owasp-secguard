import asyncio
import json
import threading

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from secguard.detectors import Severity
from secguard.middleware import SecGuardMiddleware


def make_app(**kwargs):
    app = FastAPI()
    app.add_middleware(SecGuardMiddleware, **kwargs)

    @app.get("/search")
    def search(q: str = ""):
        return {"q": q}

    @app.post("/items")
    async def items(payload: dict):
        return {"received": payload}

    @app.post("/raw")
    async def raw(request: Request):
        return {"length": len(await request.body())}

    @app.post("/stream")
    async def stream(request: Request):
        await request.body()

        async def chunks():
            yield b"a"
            yield b"b"

        return StreamingResponse(chunks())

    return app


def _post_with_timeout(client, path, timeout=5.0, **kwargs):
    # The hang this guards against spins the event loop without yielding, so
    # only a separate thread can time it out.
    result = {}
    worker = threading.Thread(
        target=lambda: result.setdefault("resp", client.post(path, **kwargs)), daemon=True
    )
    worker.start()
    worker.join(timeout)
    assert not worker.is_alive(), f"POST {path} hung"
    return result["resp"]


class TestBlockingMode:
    def test_blocks_sqli_in_query(self):
        client = TestClient(make_app())
        resp = client.get("/search", params={"q": "1' OR '1'='1"})
        assert resp.status_code == 403
        assert resp.json()["error"].startswith("request blocked")

    def test_blocks_xss_in_query(self):
        client = TestClient(make_app())
        resp = client.get("/search", params={"q": "<script>alert(1)</script>"})
        assert resp.status_code == 403

    def test_blocks_injection_in_body(self):
        client = TestClient(make_app())
        resp = client.post("/items", json={"name": "; cat /etc/passwd"})
        assert resp.status_code == 403

    def test_allows_benign_query(self):
        client = TestClient(make_app())
        resp = client.get("/search", params={"q": "best laptops 2024"})
        assert resp.status_code == 200
        assert resp.json()["q"] == "best laptops 2024"

    def test_allows_benign_body(self):
        client = TestClient(make_app())
        resp = client.post("/items", json={"name": "Alice", "email": "a@example.com"})
        assert resp.status_code == 200
        assert resp.json()["received"]["name"] == "Alice"

    def test_blocks_payload_hidden_behind_json_unicode_escapes(self):
        client = TestClient(make_app())
        for body in (
            r'{"q": "\u003cscript>alert(1)\u003c/script>"}',
            r'{"q": "1 union\u0020select password from users"}',
            r'{"\u003cscript>alert(1)</script>": 1}',
        ):
            resp = client.post(
                "/items", content=body, headers={"content-type": "application/json"}
            )
            assert resp.status_code == 403, body

    def test_blocks_payload_in_utf16_and_utf32_json_bodies(self):
        # json.loads, and so the app, detects these encodings on its own.
        client = TestClient(make_app())
        for payload, encoding in (
            ({"q": "<script>alert(1)</script>"}, "utf-16-le"),
            ({"q": "<script>alert(1)</script>"}, "utf-32"),
            ({"q": "1 union select password from users"}, "utf-16"),
        ):
            resp = client.post(
                "/items",
                content=json.dumps(payload).encode(encoding),
                headers={"content-type": "application/json"},
            )
            assert resp.status_code == 403, encoding

    def test_blocks_payload_in_either_value_of_a_duplicated_key(self):
        client = TestClient(make_app())
        for body in (
            '{"q": "<script>alert(1)</script>", "q": "x"}',
            '{"q": "x", "q": "<script>alert(1)</script>"}',
        ):
            resp = client.post(
                "/items", content=body, headers={"content-type": "application/json"}
            )
            assert resp.status_code == 403, body

    def test_reports_each_rule_once(self):
        client = TestClient(make_app())
        resp = client.post(
            "/raw?q=<script>x</script>",
            content=b"<script>alert(1)</script>\\n",
            headers={"content-type": "text/plain"},
        )
        assert resp.status_code == 403
        assert [d["rule"] for d in resp.json()["detections"]] == ["script-tag"]

    def test_rejects_body_over_the_inspection_limit(self):
        client = TestClient(make_app(max_body_bytes=1024))
        resp = client.post("/items", json={"name": "a" * 2000})
        assert resp.status_code == 413


class TestBodyReplay:
    def test_streaming_response_after_body_inspection_completes(self):
        client = TestClient(make_app())
        resp = _post_with_timeout(client, "/stream", json={"a": 1})
        assert resp.status_code == 200
        assert resp.content == b"ab"

    def test_empty_body_post_completes(self):
        client = TestClient(make_app())
        resp = _post_with_timeout(client, "/raw")
        assert resp.status_code == 200
        assert resp.json() == {"length": 0}

    def test_receive_passes_through_to_server_after_replay(self):
        seen = []

        async def downstream(scope, receive, send):
            seen.append(await receive())
            seen.append(await receive())
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        incoming = [
            {"type": "http.request", "body": b'{"a": 1}', "more_body": False},
            {"type": "http.disconnect"},
        ]

        async def receive():
            return incoming.pop(0)

        async def send(message):
            pass

        scope = {"type": "http", "method": "POST", "path": "/", "query_string": b"", "headers": []}
        asyncio.run(SecGuardMiddleware(downstream)(scope, receive, send))

        assert seen == [
            {"type": "http.request", "body": b'{"a": 1}', "more_body": False},
            {"type": "http.disconnect"},
        ]

    def test_audit_mode_streams_an_oversized_body_through_intact(self):
        sent = b'{"name": "' + b"a" * 4000 + b'"}'
        incoming = [
            {"type": "http.request", "body": sent[i : i + 1000], "more_body": i + 1000 < len(sent)}
            for i in range(0, len(sent), 1000)
        ]
        received = []

        async def downstream(scope, receive, send):
            while True:
                message = await receive()
                received.append(message["body"])
                if not message["more_body"]:
                    break
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        async def receive():
            return incoming.pop(0)

        async def send(message):
            pass

        scope = {"type": "http", "method": "POST", "path": "/", "query_string": b"", "headers": []}
        middleware = SecGuardMiddleware(downstream, block=False, max_body_bytes=1500)
        asyncio.run(middleware(scope, receive, send))

        assert b"".join(received) == sent


class TestAuditMode:
    def test_audit_mode_passes_through(self):
        client = TestClient(make_app(block=False))
        resp = client.get("/search", params={"q": "1' OR '1'='1"})
        # Not blocked, request still served.
        assert resp.status_code == 200

    def test_high_severity_threshold(self):
        # With HIGH threshold, a single low/medium pattern should not block.
        client = TestClient(make_app(min_severity=Severity.HIGH))
        resp = client.get("/search", params={"q": "best products to select"})
        assert resp.status_code == 200
