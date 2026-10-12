# Murkio identity for Python

Tells who is behind each request and writes the login components into the pages you
render. Works with any WSGI or ASGI app, with helpers for Flask, Django and FastAPI.
Python 3.9+. The only setting is your publishable key.

```sh
pip install murkio
export MURKIO_PUBLISHABLE_KEY=pk_...    # MURKIO_API_URL is optional
```

## Flask

```python
from flask import Flask, render_template_string
from murkio import Murkio
from murkio.flask import init_app, protect, current

murkio = Murkio()
app = Flask(__name__)
init_app(app, murkio)  # g.murkio on every request; `murkio` in templates


@app.get("/login")
def login():
    return render_template_string("<head>{{ murkio.head(after_login='/dashboard') }}{{ murkio.bootstrap_script() }}</head><body>{{ murkio.canvas() }}</body>")


@app.get("/dashboard")
@protect(murkio, required=True, sign_in_url="/login", load_user=True)
def dashboard():
    return f"Hello {current().user.email}"
```

## Django

```python
# settings.py
MIDDLEWARE = [..., "murkio.django.MurkioMiddleware"]  # request.murkio on every request
MURKIO = {"sign_in_url": "/login"}

# views.py
from murkio.django import protect


@protect(required=True, roles=["admin"], load_user=True)
def admin(request):
    return HttpResponse(f"Hello {request.murkio.user.email}")
```

In templates: `{{ request.murkio_client.head }}`, `{{ request.murkio_client.canvas }}`.

## FastAPI / Starlette

```python
from fastapi import Depends, FastAPI
from murkio import Murkio, Session
from murkio.asgi import MurkioMiddleware
from murkio.fastapi import require_session

murkio = Murkio()
app = FastAPI()
app.add_middleware(MurkioMiddleware, murkio=murkio)


@app.get("/api/orders")
def orders(session: Session = Depends(require_session())):  # 401 without a session
    return {"user": session.user_id}


@app.get("/api/admin")
def admin(session: Session = Depends(require_session(["admin"]))):
    return {"roles": session.roles}
```

Any other framework: `murkio.wsgi.MurkioMiddleware(app, required=True)` puts the result
in `environ["murkio"]`; `murkio.asgi.MurkioMiddleware` in `scope["murkio"]`; or call
`murkio.protect(method=..., scheme=..., host=..., path=..., headers=..., cookies=...)`.

## Your own layout

```jinja
{{ murkio.email_input(class_="input", placeholder="you@example.com") }}
{{ murkio.password_input(class_="input") }}
{{ murkio.keep_logged("Keep me signed in") }}
{{ murkio.login_button("Sign in", class_="btn") }}
{{ murkio.register_button("Create account", class_="btn") }}
{{ murkio.error_message() }}
```

The helpers return escaped markup (`__html__`), so Jinja2 and Django print them as is.

## How it works

The same contract as the other server SDKs (`libs/spec/server`): `GET /v1/client` gives
the application, issuer and JWKS; access tokens are verified locally (Ed25519, `iss`,
`aud`, `exp`); the token comes from `Authorization: Bearer` or the `__Host-` session
cookie of the browser SDK, which only counts for GET/HEAD/OPTIONS or same-origin
requests (CSRF). `load_user=True` reads `POST /v1/me` (cached a minute);
`check_revocation=True` asks the API whether the session was revoked (cached 30 s). A
page request with an expired cookie gets a short handshake page that refreshes it. The
backend never signs anyone in: the browser does.

## Developing

```sh
pip install -e . -r requirements-test.txt
python -m unittest discover -s tests
```

The tests read the token vectors every Murkio server SDK shares. That copy (`spec/`) and
the checks in `infra/pipeline/` are kept in the Murkio identity service and synced from
there, so they are not edited here.

Every pull request runs the workflows in `.github/workflows`. The same checks, locally
(`pip install -r requirements-dev.txt` brings the tools):

| Workflow | What it runs |
| --- | --- |
| Build | `python -m build`, `twine check --strict dist/*`, then installs the wheel and imports it |
| Format | `ruff format --check .` |
| Lint | `ruff check .`, `mypy` (strict) |
| Tests | the suite on Python 3.9 and 3.14 |
| Quality & Governance Checks | `for check in infra/pipeline/*.py; do python3 "$check"; done` |
| Security | `bandit -r src -c pyproject.toml`, `pip-audit --strict .`, `gitleaks git .`, `zizmor --pedantic .` |
| CodeQL, Dependency Review | run by GitHub on the pull request |

Security reports: see [SECURITY.md](SECURITY.md).
