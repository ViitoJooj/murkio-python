"""ASGI middleware: FastAPI, Starlette, Django (ASGI), Quart..."""

from __future__ import annotations

import asyncio
import functools
from typing import Any, Awaitable, Callable, Dict, Optional

from .client import AuthResult, Murkio, parse_cookies

SCOPE_KEY = "murkio"
Scope = Dict[str, Any]


def request_from_scope(scope: Scope) -> Dict[str, Any]:
    """The request fields ``Murkio.protect`` needs, from an ASGI HTTP scope."""
    headers: Dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers") or []:
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        headers[name] = f"{headers[name]}; {value}" if name == "cookie" and name in headers else headers.get(name, value)
    query = (scope.get("query_string") or b"").decode("latin-1")
    path = (scope.get("root_path") or "") + (scope.get("path") or "/")
    return {
        "method": scope.get("method", "GET"),
        "scheme": scope.get("scheme", "http"),
        "host": headers.get("host", "localhost"),
        "path": f"{path}?{query}" if query else path,
        "headers": headers,
        "cookies": parse_cookies(headers.get("cookie")),
    }


class MurkioMiddleware:
    """Puts the ``AuthResult`` in ``scope["murkio"]`` and enforces the options.

        app.add_middleware(MurkioMiddleware)                              # FastAPI/Starlette
        app.add_middleware(MurkioMiddleware, required=True, sign_in_url="/login")

    The verification is local and fast, but the first request (and a key
    rotation, ``load_user``, ``check_revocation``) call the API with a blocking
    client, so the work runs in the default executor, off the event loop.
    """

    def __init__(self, app: Callable[..., Awaitable[None]], murkio: Optional[Murkio] = None, **options: Any) -> None:
        self.app = app
        self.murkio = murkio or Murkio()
        self.options = options

    async def __call__(self, scope: Scope, receive: Callable[..., Awaitable[Any]], send: Callable[..., Awaitable[None]]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        protect = functools.partial(self.murkio.protect, **request_from_scope(scope), **self.options)
        result, response = await asyncio.get_running_loop().run_in_executor(None, protect)
        scope[SCOPE_KEY] = result
        if response is None:
            await self.app(scope, receive, send)
            return

        await send({
            "type": "http.response.start",
            "status": response.status,
            "headers": [(name.lower().encode("latin-1"), value.encode("latin-1")) for name, value in response.headers],
        })
        await send({"type": "http.response.body", "body": response.body})


def get(scope: Scope) -> AuthResult:
    """The ``AuthResult`` the middleware stored (an empty one without the middleware)."""
    return scope.get(SCOPE_KEY) or AuthResult(reason="missing")
