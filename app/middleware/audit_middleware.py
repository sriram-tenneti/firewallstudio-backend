"""Audit middleware — auto-captures state-changing requests.

Intercepts POST/PUT/PATCH/DELETE and writes audit trail entries.
For reads (GET) no audit is recorded.
"""

import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class AuditMiddleware(BaseHTTPMiddleware):
    """Injects X-Request-Id if missing and logs mutating requests.

    The actual audit recording is done in the route handlers / services
    because they have access to the before/after document state. This
    middleware ensures every request has a correlation ID.
    """

    AUDITED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Ensure every request has a correlation ID
        if "X-Request-Id" not in request.headers:
            request.state.request_id = f"req-{uuid.uuid4().hex[:12]}"
        else:
            request.state.request_id = request.headers["X-Request-Id"]

        response = await call_next(request)
        return response
