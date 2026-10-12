"""Django middleware and decorator.

    # settings.py
    MIDDLEWARE = [..., "murkio.django.MurkioMiddleware"]
    MURKIO = {"sign_in_url": "/login"}       # optional: options of Murkio.protect

    # views.py
    from murkio.django import protect

    @protect(required=True, load_user=True)
    def dashboard(request):
        return HttpResponse(f"Hello {request.murkio.user.email}")

``request.murkio`` is the ``AuthResult``; ``request.murkio_client`` writes the
components (``{{ request.murkio_client.head }}`` in a template).
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Optional

from .client import Murkio
from .wsgi import request_from_environ

_client: Optional[Murkio] = None


def client() -> Murkio:
    """The process-wide client, created from the environment on first use."""
    global _client  # noqa: PLW0603 - one client for the process, created on first use
    if _client is None:
        _client = Murkio()
    return _client


def _options() -> Dict[str, Any]:
    try:
        from django.conf import settings

        return dict(getattr(settings, "MURKIO", {}) or {})
    except Exception:  # noqa: BLE001 - settings not configured
        return {}


def _to_django(response: Any) -> Any:
    from django.http import HttpResponse

    answer = HttpResponse(response.body, status=response.status)
    for name, value in response.headers:
        answer[name] = value
    return answer


def _protect(request: Any, options: Dict[str, Any]) -> Any:
    murkio = client()
    fields = request_from_environ(request.META)
    fields["scheme"] = getattr(request, "scheme", None) or fields["scheme"]
    result, response = murkio.protect(**fields, **options)
    request.murkio = result
    request.murkio_client = murkio
    return _to_django(response) if response is not None else None


class MurkioMiddleware:
    """Authenticates every request into ``request.murkio`` with the options in ``settings.MURKIO``."""

    def __init__(self, get_response: Callable[[Any], Any]) -> None:
        self.get_response = get_response

    def __call__(self, request: Any) -> Any:
        return _protect(request, _options()) or self.get_response(request)


def protect(**options: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Protects one view: ``@protect(required=True, roles=["admin"])``."""

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(view)
        def wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
            return _protect(request, {**_options(), **options}) or view(request, *args, **kwargs)

        return wrapper

    return decorator
