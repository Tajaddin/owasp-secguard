"""Starlette/FastAPI middleware that inspects requests for injection payloads.

Checks the path, query parameters, and (optionally) the body. On a detection
at or above the configured severity it either blocks with 403 or passes
through while recording the detections (audit mode). Detections are attached
to request.state for downstream logging.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from secguard.detectors import Detection, Severity, scan_value

_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}


class SecGuardMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        min_severity: Severity = Severity.MEDIUM,
        block: bool = True,
        inspect_body: bool = True,
        max_body_bytes: int = 256 * 1024,
    ):
        self.app = app
        self.min_severity = min_severity
        self.block = block
        self.inspect_body = inspect_body
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        detections = self._inspect_url(request)

        body = b""
        if self.inspect_body and request.method in ("POST", "PUT", "PATCH"):
            body = await _read_body(receive, self.max_body_bytes)
            if body:
                detections += scan_value(body.decode("utf-8", errors="ignore"))

        flagged = [d for d in detections if _ORDER[d.severity] >= _ORDER[self.min_severity]]

        if flagged and self.block:
            response = JSONResponse(
                {
                    "error": "request blocked by secguard",
                    "detections": [
                        {"category": d.category.value, "severity": d.severity.value, "rule": d.pattern}
                        for d in flagged
                    ],
                },
                status_code=403,
            )
            await response(scope, receive, send)
            return

        scope.setdefault("state", {})
        scope["state"]["secguard_detections"] = flagged

        # Replay the already-consumed body to downstream.
        async def replay_receive():
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay_receive if body else receive, send)

    def _inspect_url(self, request: Request) -> list[Detection]:
        out: list[Detection] = []
        out += scan_value(request.url.path)
        for _, value in request.query_params.multi_items():
            out += scan_value(value)
        return out


async def _read_body(receive: Callable[[], Awaitable[dict]], cap: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > cap:
            chunks.append(chunk)
            break
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


# Convenience for FastAPI: `app.add_middleware(SecGuardMiddleware, ...)`
__all__ = ["SecGuardMiddleware", "Response"]
