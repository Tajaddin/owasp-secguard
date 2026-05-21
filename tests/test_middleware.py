from fastapi import FastAPI
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

    return app


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
