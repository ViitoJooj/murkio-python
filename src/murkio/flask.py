"""Flask helpers.

from murkio import Murkio
from murkio.flask import init_app, protect, current

murkio = Murkio()
init_app(app, murkio)                      # g.murkio on every request

@app.get("/dashboard")
@protect(murkio, required=True, sign_in_url="/login", load_user=True)
def dashboard():
    return f"Hello {current().user.email}"
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Optional

from .client import AuthResult, Murkio
from .wsgi import request_from_environ


def _to_flask(response: Any) -> Any:
    import flask

    return flask.Response(response.body, status=response.status, headers=response.headers)


def init_app(app: Any, murkio: Optional[Murkio] = None, **options: Any) -> Murkio:
    """Authenticates every request into ``flask.g.murkio`` (options as in ``Murkio.protect``)."""
    import flask

    client = murkio or Murkio()

    def _murkio_before_request() -> Any:
        result, response = client.protect(**request_from_environ(flask.request.environ), **options)
        flask.g.murkio = result
        return _to_flask(response) if response is not None else None

    def _murkio_context() -> Dict[str, Any]:
        return {"murkio": client, "murkio_auth": current()}

    app.before_request(_murkio_before_request)
    app.context_processor(_murkio_context)
    return client


def current() -> AuthResult:
    """The ``AuthResult`` of the current request."""
    import flask

    return getattr(flask.g, "murkio", None) or AuthResult(reason="missing")


def protect(murkio: Murkio, **options: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Protects one view: ``@protect(murkio, required=True, roles=["admin"])``."""

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            import flask

            result, response = murkio.protect(**request_from_environ(flask.request.environ), **options)
            flask.g.murkio = result
            if response is not None:
                return _to_flask(response)
            return view(*args, **kwargs)

        return wrapper

    return decorator
