"""Murkio identity for Python backends.

    from murkio import Murkio

    murkio = Murkio()  # reads MURKIO_PUBLISHABLE_KEY

Use ``murkio.wsgi.MurkioMiddleware`` (Flask, Django, any WSGI app),
``murkio.asgi.MurkioMiddleware`` (FastAPI, Starlette, Django ASGI) or the
``murkio.flask``, ``murkio.django`` and ``murkio.fastapi`` helpers, and write the
components into your pages with ``murkio.head()``, ``murkio.canvas()``...
"""

from .client import (
    DEFAULT_API_URL,
    ApiError,
    AuthResult,
    ExpiredToken,
    Markup,
    Murkio,
    Response,
    Session,
    TokenError,
    User,
    fnv1a32,
    parse_cookies,
)

__all__ = [
    "DEFAULT_API_URL",
    "ApiError",
    "AuthResult",
    "ExpiredToken",
    "Markup",
    "Murkio",
    "Response",
    "Session",
    "TokenError",
    "User",
    "fnv1a32",
    "parse_cookies",
]
__version__ = "0.1.0"
