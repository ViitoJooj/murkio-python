"""WSGI middleware: Flask, Django (WSGI), Pyramid, Bottle..."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any, Callable, Dict, Iterable, Optional

from .client import AuthResult, Murkio, parse_cookies

ENVIRON_KEY = "murkio"


def request_from_environ(environ: Dict[str, Any]) -> Dict[str, Any]:
    """The request fields ``Murkio.protect`` needs, from a WSGI environ."""
    headers = {
        name[5:].replace("_", "-").lower(): value
        for name, value in environ.items()
        if name.startswith("HTTP_") and isinstance(value, str)
    }
    query = environ.get("QUERY_STRING") or ""
    path = (environ.get("SCRIPT_NAME") or "") + (environ.get("PATH_INFO") or "/")
    return {
        "method": environ.get("REQUEST_METHOD", "GET"),
        "scheme": environ.get("wsgi.url_scheme", "http"),
        "host": headers.get("host") or environ.get("SERVER_NAME", "localhost"),
        "path": f"{path}?{query}" if query else path,
        "headers": headers,
        "cookies": parse_cookies(headers.get("cookie")),
    }


class MurkioMiddleware:
    """Puts the ``AuthResult`` in ``environ["murkio"]`` and enforces the options.

        app = MurkioMiddleware(app)                                  # optional auth
        app = MurkioMiddleware(app, required=True, sign_in_url="/login")

    Options: ``required``, ``roles``, ``sign_in_url``, ``handshake``,
    ``load_user`` and ``check_revocation`` (see ``Murkio.protect``).
    """

    def __init__(self, app: Callable[..., Iterable[bytes]], murkio: Optional[Murkio] = None, **options: Any) -> None:
        self.app = app
        self.murkio = murkio or Murkio()
        self.options = options

    def __call__(self, environ: Dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        result, response = self.murkio.protect(**request_from_environ(environ), **self.options)
        environ[ENVIRON_KEY] = result
        if response is None:
            return self.app(environ, start_response)
        start_response(f"{response.status} {HTTPStatus(response.status).phrase}", response.headers)
        return [response.body]


def get(environ: Dict[str, Any]) -> AuthResult:
    """The ``AuthResult`` the middleware stored (an empty one without the middleware)."""
    return environ.get(ENVIRON_KEY) or AuthResult(reason="missing")
