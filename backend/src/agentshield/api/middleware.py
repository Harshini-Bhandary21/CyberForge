"""HTTP hardening middleware: security headers, request-size cap and rate limiting."""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

_DOC_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if not request.url.path.startswith(_DOC_PATHS):
            resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
            resp.headers["Cache-Control"] = "no-store"  # verdicts and audit data must not be cached
        if request.url.scheme == "https":
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp


class BodyLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized bodies up-front (declared length) to blunt memory-exhaustion attempts."""

    def __init__(self, app, max_bytes: int) -> None:  # noqa: ANN001
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            return JSONResponse({"detail": "Request body too large"}, status_code=413)
        if request.headers.get("transfer-encoding", "").lower() == "chunked":
            return JSONResponse({"detail": "Chunked uploads are not accepted"}, status_code=411)
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding one-minute window per API key (or client IP). In-process: put a gateway in front for
    multi-replica deployments."""

    def __init__(self, app, per_minute: int) -> None:  # noqa: ANN001
        super().__init__(app)
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    @staticmethod
    def _who(request: Request) -> str:
        key = request.headers.get("x-api-key")
        if key:
            return "k:" + hashlib.sha256(key.encode()).hexdigest()[:16]
        return "ip:" + (request.client.host if request.client else "unknown")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if self.per_minute <= 0 or request.url.path.endswith("/health"):
            return await call_next(request)
        now = time.monotonic()
        window = self._hits[self._who(request)]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= self.per_minute:
            retry = max(1, int(60 - (now - window[0])))
            return JSONResponse(
                {"detail": "Rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(retry)},
            )
        window.append(now)
        return await call_next(request)
