"""Fixtures compartidas (T005). Solo identidades ficticias del dominio @lab.securefin.local."""

from __future__ import annotations

import itertools
import json
import os
from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth.hashers import make_password
from django.test import Client
from django.utils import timezone

ORIGIN = "https://securefin.local"
API = "/api/v1"
STRONG_PASSWORD = "correcto caballo batería grapa 2026"  # 15+ caracteres, sin reglas de composición

_counter = itertools.count(1)
_hash_cache: dict[str, str] = {}


@pytest.fixture
def stack_url():
    """URL del stack de Compose. Si falta, la prueba FALLA (nunca se omite en silencio; U2)."""
    url = os.environ.get("SECUREFIN_STACK_URL")
    if not url:
        pytest.fail("SECUREFIN_STACK_URL no está definida: las pruebas `stack` necesitan el stack levantado.")
    return url


class ApiClient:
    """Cliente HTTP que emula al SPA: HTTPS, mismo origen, cookie CSRF y cabecera X-CSRFToken."""

    def __init__(self, ip: str = "203.0.113.10"):
        self.client = Client(enforce_csrf_checks=True, HTTP_HOST="securefin.local")
        self.ip = ip

    def _headers(self, extra=None):
        headers = {
            "secure": True,
            "HTTP_ORIGIN": ORIGIN,
            "HTTP_X_FORWARDED_FOR": self.ip,
            "REMOTE_ADDR": "10.0.0.2",
            "HTTP_USER_AGENT": "pytest-securefin",
        }
        token = self.csrf_token
        if token:
            headers["HTTP_X_CSRFTOKEN"] = token
        if extra:
            headers.update(extra)
        return headers

    @property
    def csrf_token(self):
        cookie = self.client.cookies.get("__Host-sf_csrftoken")
        return cookie.value if cookie else None

    def fetch_csrf(self):
        return self.client.get(f"{API}/auth/csrf", **self._headers())

    def get(self, path, **extra):
        return self.client.get(f"{API}{path}", **self._headers(extra))

    def _send(self, method, path, data=None, csrf=True, **extra):
        if csrf and not self.csrf_token:
            self.fetch_csrf()
        headers = self._headers(extra)
        if not csrf:
            headers.pop("HTTP_X_CSRFTOKEN", None)
        body = json.dumps(data) if data is not None else ""
        return getattr(self.client, method)(
            f"{API}{path}", data=body, content_type="application/json", **headers
        )

    def post(self, path, data=None, csrf=True, **extra):
        return self._send("post", path, data, csrf, **extra)

    def patch(self, path, data=None, csrf=True, **extra):
        return self._send("patch", path, data, csrf, **extra)

    def delete(self, path, csrf=True, **extra):
        return self._send("delete", path, None, csrf, **extra)

    @property
    def session_cookie(self):
        cookie = self.client.cookies.get("__Host-sf_session")
        return cookie.value if cookie and cookie.value else None

    def login(self, email, password=STRONG_PASSWORD):
        return self.post("/auth/login", {"email": email, "password": password})


@pytest.fixture
def api():
    return ApiClient()


@pytest.fixture
def api_factory():
    def _make(ip="203.0.113.10"):
        return ApiClient(ip=ip)

    return _make


def _cached_hash(password: str) -> str:
    if password not in _hash_cache:
        _hash_cache[password] = make_password(password)
    return _hash_cache[password]


@pytest.fixture
def make_user(db):
    """Crea usuarios ficticios; reutiliza el hash Argon2id por contraseña para acelerar la suite."""
    from apps.iam.models import User

    def _make(role="client", status="active", password=STRONG_PASSWORD, email=None, name=None):
        n = next(_counter)
        user = User(
            email=email or f"usuario{n}@lab.securefin.local",
            name=name or f"Usuario Ficticio {n}",
            role=role,
            status=status,
        )
        user.password = _cached_hash(password)
        user.save()
        return user

    return _make


@pytest.fixture
def login_as(api_factory, make_user):
    """Devuelve (cliente, usuario) con una sesión `full` para cualquier rol.

    Sustituto de prueba hasta US3: todavía no existe `TOTPDevice`, así que Administrador y Auditor no
    pueden cumplir el MFA. Durante la prueba se da por cumplido el MFA en `IsFullyAuthenticated` y,
    solo durante el login, se omite el alta obligatoria. Con US3 se sustituye por un alta TOTP real.
    """
    patcher = mock.patch("apps.iam.api.permissions.user_mfa_enabled", return_value=True)
    patcher.start()
    ips = itertools.count(20)

    def _login(role="client", user=None):
        user = user or make_user(role=role)
        client = api_factory(ip=f"203.0.113.{next(ips)}")
        with mock.patch("apps.iam.services.authentication.mfa_required", return_value=False):
            response = client.login(user.email)
        assert response.status_code == 200 and response.json()["status"] == "authenticated"
        return client, user

    yield _login
    patcher.stop()


class Clock:
    """Reloj controlable: parchea apps.core.clock.now."""

    def __init__(self):
        self.current = timezone.now()

    def now(self):
        return self.current

    def advance(self, **kwargs):
        self.current = self.current + timedelta(**kwargs)
        return self.current


@pytest.fixture
def clock():
    c = Clock()
    with mock.patch("apps.core.clock.now", side_effect=c.now):
        yield c
