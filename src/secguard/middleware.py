"""Starlette/FastAPI middleware that inspects requests for injection payloads.

Checks the path, query parameters, and (optionally) the body. On a detection
at or above the configured severity it either blocks with 403 or passes
through while recording the detections (audit mode). Detections are attached
to request.state for downstream logging.

Bodies are inspected up to ``max_body_bytes``. A larger body is rejected with
413 in blocking mode, since the part past the limit would go unchecked; in
audit mode the inspected prefix is replayed and the rest streams through.
"""
from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive

from secguard.detectors import Detection, Severity, scan_value

_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}

_JSON_ESCAPE = re.compile(r'\\(?:u[0-9a-fA-F]{4}|["\\/bfnrt])')


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

        if self.inspect_body and request.method in ("POST", "PUT", "PATCH"):
            body, more_body = await _read_body(receive, self.max_body_bytes)
            if len(body) > self.max_body_bytes and self.block:
                response = JSONResponse(
                    {
                        "error": "request body exceeds the inspection limit",
                        "max_body_bytes": self.max_body_bytes,
                    },
                    status_code=413,
                )
                await response(scope, receive, send)
                return
            if body:
                detections += _scan_body(body)
            receive = _replay(body, more_body, receive)

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

        await self.app(scope, receive, send)

    def _inspect_url(self, request: Request) -> list[Detection]:
        out: list[Detection] = []
        out += scan_value(request.url.path)
        for _, value in request.query_params.multi_items():
            out += scan_value(value)
        return out


async def _read_body(receive: Callable[[], Awaitable[dict]], cap: int) -> tuple[bytes, bool]:
    """Read the body until it ends or passes ``cap``.

    Returns the bytes read and whether more body is still to come. Reading
    stops on the first chunk past ``cap``, so at most one chunk over it is held.
    """
    chunks: list[bytes] = []
    size = 0
    more_body = True
    while more_body and size <= cap:
        message = await receive()
        if message["type"] != "http.request":
            # Leave the disconnect for the app's next receive() to report.
            break
        chunk = message.get("body", b"")
        chunks.append(chunk)
        size += len(chunk)
        more_body = message.get("more_body", False)
    return b"".join(chunks), more_body


def _scan_body(body: bytes) -> list[Detection]:
    """Scan the body as the app will read it.

    A body that parses as JSON is parsed with ``json.loads``, as Starlette's
    ``request.json()`` does, so escapes are decoded and UTF-16 and UTF-32
    bodies are detected; every key and string value is then scanned,
    including both values of a duplicated key, since parsers differ on which
    one they keep. Any other body is scanned as UTF-8 text, a second time
    with JSON string escapes decoded.
    """
    try:
        parsed = json.loads(body, object_pairs_hook=list)
    except (ValueError, RecursionError):
        text = body.decode("utf-8", errors="ignore")
        detections = scan_value(text)
        if "\\" in text:
            detections += scan_value(_json_unescape(text))
        return detections
    return [d for value in _json_strings(parsed) for d in scan_value(value)]


def _json_strings(value: object):
    """Yield every string in JSON parsed with ``object_pairs_hook=list``,
    where each object is a list of (key, value) pairs."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


def _json_unescape(text: str) -> str:
    """Decode JSON string escapes in text that does not parse as JSON."""
    return _JSON_ESCAPE.sub(lambda m: json.loads(f'"{m.group(0)}"'), text)


def _replay(body: bytes, more_body: bool, receive: Receive) -> Receive:
    """Give the app the body this middleware already consumed, once, then hand
    every later call to the server's receive (the rest of a body that passed
    the limit, and http.disconnect, which streaming responses wait on)."""
    replayed = False

    async def replay_receive():
        nonlocal replayed
        if replayed:
            return await receive()
        replayed = True
        return {"type": "http.request", "body": body, "more_body": more_body}

    return replay_receive


# Convenience for FastAPI: `app.add_middleware(SecGuardMiddleware, ...)`
__all__ = ["SecGuardMiddleware", "Response"]
