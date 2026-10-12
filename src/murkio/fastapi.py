"""FastAPI / Starlette dependencies.

from fastapi import Depends, FastAPI
from murkio import Murkio, Session
from murkio.asgi import MurkioMiddleware
from murkio.fastapi import require_session

murkio = Murkio()
app = FastAPI()
app.add_middleware(MurkioMiddleware, murkio=murkio)

@app.get("/api/orders")
def orders(session: Session = Depends(require_session())):
    return {"user": session.user_id}
"""

from __future__ import annotations

from typing import Callable, Optional, Sequence

from starlette.exceptions import HTTPException
from starlette.requests import Request

from .asgi import get
from .client import AuthResult, Session


def auth(request: Request) -> AuthResult:
    """Dependency: the ``AuthResult`` of the request (needs ``murkio.asgi.MurkioMiddleware``)."""
    return get(request.scope)


def require_session(roles: Optional[Sequence[str]] = None) -> Callable[[Request], Session]:
    """Dependency factory: the session, or 401 (403 without one of ``roles``).

    The parameter is annotated with Starlette's ``Request`` so FastAPI injects
    the request instead of reading it as a query parameter.
    """

    def dependency(request: Request) -> Session:
        result = get(request.scope)
        if result.session is None:
            raise HTTPException(status_code=401, detail="unauthorized")
        if roles and not result.session.has_role(*roles):
            raise HTTPException(status_code=403, detail="forbidden")
        return result.session

    return dependency
