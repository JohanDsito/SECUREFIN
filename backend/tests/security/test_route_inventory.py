"""TS-S23 (T024): sin Django Admin y sin rutas anónimas fuera de la lista permitida."""

import pytest
from rest_framework.permissions import AllowAny

from tests.security.routes import iter_api_routes

pytestmark = pytest.mark.security

# Únicas rutas anónimas permitidas por el contrato §2
ANONYMOUS_ALLOWED = {
    "/api/v1/auth/csrf",
    "/api/v1/auth/register",
    "/api/v1/auth/login",
    "/api/v1/auth/logout",
    "/api/v1/auth/activate",
    "/api/v1/auth/password-reset/request",
    "/api/v1/auth/password-reset/confirm",
    "/api/v1/auth/login/mfa",
    "/api/v1/auth/login/enroll/setup",
    "/api/v1/auth/login/enroll/confirm",
    "/api/v1/auth/login/mfa-reset-request",
}


def test_django_admin_is_not_exposed(api, db):
    assert api.client.get("/admin/", secure=True).status_code == 404
    assert api.client.get("/admin/login/", secure=True).status_code == 404


def test_only_contract_routes_are_anonymous():
    for path, view_class in iter_api_routes():
        if any(p is AllowAny for p in getattr(view_class, "permission_classes", [])):
            assert path in ANONYMOUS_ALLOWED, f"ruta anónima no permitida: {path}"


def test_no_route_creates_privileged_users_anonymously():
    for path, view_class in iter_api_routes():
        if path.startswith("/api/v1/admin/"):
            assert not any(p is AllowAny for p in getattr(view_class, "permission_classes", []))
