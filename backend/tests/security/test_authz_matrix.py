"""TS-S01 (T058): matriz de autorización generada desde ROLE_PERMISSIONS sobre todas las rutas.

Cada vista protegida declara `required_permission` (un permiso de la matriz) o figura en
ANY_FULL_SESSION. La prueba recorre todas las rutas registradas bajo /api/v1/, todos sus métodos y
los tres roles, de modo que las rutas que añadan US3–US7 quedan cubiertas sin tocar este archivo:

- sin sesión → 401;
- rol sin el permiso de función → 403 y evento `authz_denied` (BFLA);
- rol con el permiso → ni 401 ni 403 (la respuesta concreta la fijan las pruebas de contrato).
"""

from __future__ import annotations

import pytest
from rest_framework.permissions import AllowAny

from apps.audit.models import SecurityEvent
from apps.iam.policies.matrix import ROLE_PERMISSIONS, has_permission
from tests.security.routes import iter_api_routes

pytestmark = pytest.mark.security

# Rutas protegidas sin permiso de función: basta una sesión `full` con el MFA del rol cumplido.
ANY_FULL_SESSION = {"/api/v1/auth/session"}

METHODS = ("get", "post", "put", "patch", "delete")
ROLES = sorted(ROLE_PERMISSIONS)
KNOWN_PERMISSIONS = frozenset().union(*ROLE_PERMISSIONS.values())


def _is_anonymous(view_class) -> bool:
    return any(p is AllowAny for p in getattr(view_class, "permission_classes", []))


def _protected_endpoints():
    endpoints = []
    for path, view_class in iter_api_routes():
        if _is_anonymous(view_class):
            continue
        for method in METHODS:
            if hasattr(view_class, method):
                endpoints.append((path, method, view_class))
    return endpoints


PROTECTED = _protected_endpoints()
_IDS = [f"{m.upper()} {p}" for p, m, _ in PROTECTED]


def _call(client, method, path):
    relative = path.removeprefix("/api/v1")
    if method == "get":
        return client.get(relative)
    # Siempre con CSRF válido: aquí se prueba la autorización, no la protección CSRF (test_csrf_cors).
    return client._send(method, relative, None if method == "delete" else {})


def test_matrix_covers_routes():
    """Sin rutas protegidas, la prueba generada no protegería nada: se exige al menos US1 y US2."""
    paths = {p for p, _, _ in PROTECTED}
    assert "/api/v1/auth/session" in paths
    assert "/api/v1/users/me/profile" in paths


@pytest.mark.parametrize(("path", "method", "view_class"), PROTECTED, ids=_IDS)
def test_every_protected_route_declares_its_permission(path, method, view_class):
    permission = getattr(view_class, "required_permission", None)
    if permission is None:
        assert path in ANY_FULL_SESSION, f"{path} no declara required_permission (denegar por defecto)"
        return
    assert permission in KNOWN_PERMISSIONS, f"{path}: permiso desconocido {permission!r}"
    names = [p.__name__ for p in view_class.permission_classes]
    assert f"HasRolePermission[{permission}]" in names, f"{path}: falta HasRolePermission({permission})"


@pytest.mark.parametrize(("path", "method", "view_class"), PROTECTED, ids=_IDS)
def test_anonymous_gets_401(api, db, path, method, view_class):
    response = _call(api, method, path)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "auth_failed"


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize(("path", "method", "view_class"), PROTECTED, ids=_IDS)
def test_role_matrix(login_as, role, path, method, view_class):
    client, user = login_as(role)
    permission = getattr(view_class, "required_permission", None)
    allowed = permission is None or has_permission(role, permission)
    denied = SecurityEvent.objects.filter(
        event_type="authz_denied", actor_id=user.id, metadata__reason="function"
    )
    before = denied.count()

    response = _call(client, method, path)

    if allowed:
        assert response.status_code not in (401, 403), (role, method, path, response.status_code)
        assert denied.count() == before
    else:
        assert response.status_code == 403, (role, method, path, response.status_code)
        assert response.json()["error"]["code"] == "forbidden"
        assert denied.count() == before + 1
