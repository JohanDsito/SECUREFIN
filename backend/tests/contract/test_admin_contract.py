"""TS-C01, parte US4 (T084): Contrato de las rutas administrativas y de activación.

Rutas de contracts/iam-api.md §4:
- GET /admin/users
- POST /admin/users
- POST /admin/users/{id}/activation/resend
- PATCH /admin/users/{id}/role
- POST /admin/users/{id}/deactivate
- POST /admin/users/{id}/reactivate
- GET /admin/mfa-resets
- POST /admin/mfa-resets/{case_id}/open
- POST /admin/mfa-resets/{case_id}/authorize
- POST /admin/mfa-resets/{case_id}/cancel
Y endpoints auxiliares:
- POST /auth/activate
- POST /auth/login/mfa-reset-request
"""

from __future__ import annotations

import uuid
import pytest

from apps.iam.models import Role, Status
from tests.conftest import STRONG_PASSWORD
from tests.helpers import make_totp_device, totp_code

pytestmark = pytest.mark.contract

ADMIN_USER_ITEM = {"id", "email", "name", "role", "status", "mfa_enabled", "created_at", "last_login_at"}
MFA_RESET_ITEM = {"case_id", "target_user_id", "target_email", "requested_at", "status"}


def test_get_admin_users_contract(login_as):
    """GET /admin/users: paginación, filtros y campos requeridos."""
    client, _ = login_as("admin")
    resp = client.get("/admin/users?role=admin&status=active&page=1")
    assert resp.status_code == 200
    assert resp.headers.get("Cache-Control") == "no-store"
    body = resp.json()
    assert "results" in body and "next" in body and "previous" in body
    if body["results"]:
        assert ADMIN_USER_ITEM.issubset(set(body["results"][0].keys()))


def test_post_admin_users_contract(login_as):
    """POST /admin/users: creación de usuario privilegiado."""
    client, _ = login_as("admin")
    resp = client.post(
        "/admin/users",
        {
            "email": "nuevo-auditor@lab.securefin.local",
            "name": "Nuevo Auditor",
            "role": Role.AUDITOR,
        },
    )
    assert resp.status_code == 201
    assert resp.headers.get("Cache-Control") == "no-store"
    body = resp.json()
    assert "id" in body and body["status"] == Status.PENDING_ACTIVATION


def test_post_admin_users_invalid_role_contract(login_as):
    """POST /admin/users rechaza roles no privilegiados como 'client' con 400."""
    client, _ = login_as("admin")
    resp = client.post(
        "/admin/users",
        {
            "email": "nuevo-cliente@lab.securefin.local",
            "name": "Cliente Rechazado",
            "role": Role.CLIENT,
        },
    )
    assert resp.status_code == 400


def test_post_resend_activation_contract(login_as, make_user):
    """POST /admin/users/{id}/activation/resend devuelve 204."""
    client, _ = login_as("admin")
    target = make_user(status=Status.PENDING_ACTIVATION)
    resp = client.post(f"/admin/users/{target.id}/activation/resend", {})
    assert resp.status_code == 204


def test_patch_user_role_contract(login_as, make_user):
    """PATCH /admin/users/{id}/role: actualiza rol y devuelve 200."""
    client, _ = login_as("admin")
    target = make_user(role=Role.CLIENT)
    resp = client.patch(f"/admin/users/{target.id}/role", {"role": Role.AUDITOR})
    assert resp.status_code == 200


def test_post_deactivate_and_reactivate_contract(login_as, make_user):
    """POST /admin/users/{id}/deactivate y /reactivate devuelven 204."""
    client, _ = login_as("admin")
    target = make_user(role=Role.CLIENT, status=Status.ACTIVE)

    resp_deact = client.post(f"/admin/users/{target.id}/deactivate", {})
    assert resp_deact.status_code == 204

    resp_react = client.post(f"/admin/users/{target.id}/reactivate", {})
    assert resp_react.status_code == 204


def test_get_mfa_resets_contract(login_as):
    """GET /admin/mfa-resets: lista de casos y campos obligatorios."""
    client, _ = login_as("admin")
    resp = client.get("/admin/mfa-resets?status=requested")
    assert resp.status_code == 200
    assert resp.headers.get("Cache-Control") == "no-store"
    body = resp.json()
    assert "results" in body
    if body["results"]:
        assert MFA_RESET_ITEM.issubset(set(body["results"][0].keys()))


def test_post_mfa_reset_open_contract(login_as):
    """POST /admin/mfa-resets/{case_id}/open devuelve 200 {status: 'pending_verification'}."""
    client, _ = login_as("admin")
    case_id = uuid.uuid4()
    resp = client.post(f"/admin/mfa-resets/{case_id}/open", {"request_channel": "in_person"})
    assert resp.status_code == 200
    assert resp.json().get("status") == "pending_verification"


def test_post_mfa_reset_authorize_contract(login_as):
    """POST /admin/mfa-resets/{case_id}/authorize devuelve 200 {status: 'authorized'}."""
    client, admin_user = login_as("admin")
    case_id = uuid.uuid4()
    resp = client.post(
        f"/admin/mfa-resets/{case_id}/authorize",
        {
            "verification_code": "ABCDEF12",
            "admin_totp_code": totp_code(admin_user.totp_secret),
            "channel_confirmed": True,
        },
    )
    assert resp.status_code == 200
    assert resp.json().get("status") == "authorized"


def test_post_mfa_reset_cancel_contract(login_as):
    """POST /admin/mfa-resets/{case_id}/cancel devuelve 204."""
    client, _ = login_as("admin")
    case_id = uuid.uuid4()
    resp = client.post(f"/admin/mfa-resets/{case_id}/cancel", {})
    assert resp.status_code == 204


def test_post_auth_activate_contract(api):
    """POST /auth/activate devuelve 400 invalid_token ante token inválido."""
    resp = api.post(
        "/auth/activate",
        {"token": "token_invalido_de_prueba", "password": STRONG_PASSWORD},
    )
    assert resp.status_code == 400
    assert resp.json().get("error", {}).get("code") == "invalid_token"


def test_post_mfa_reset_request_contract(api, make_user):
    """POST /auth/login/mfa-reset-request devuelve 202 status: 'mfa_reset_requested' en pre_auth."""
    user = make_user()
    make_totp_device(user)
    api.login(user.email, STRONG_PASSWORD)
    resp = api.post("/auth/login/mfa-reset-request", {})
    assert resp.status_code == 202
    assert resp.json() == {"status": "mfa_reset_requested"}
