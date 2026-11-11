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

from apps.iam.models import MfaResetStatus, Role, Status
from apps.iam.services import tokens
from tests.conftest import STRONG_PASSWORD
from tests.helpers import fresh_totp, make_totp_device, opened_case, requested_case

pytestmark = pytest.mark.contract

ADMIN_USER_ITEM = {"id", "email", "name", "role", "status", "mfa_enabled", "created_at", "last_login_at"}
MFA_RESET_ITEM = {"case_id", "target_user_id", "target_email", "requested_at", "status"}
FORBIDDEN_OUTPUT = ("password", "verifier", "secret", "token", "challenge")


def _no_sensitive_keys(payload) -> None:
    text = str(payload).lower()
    for word in FORBIDDEN_OUTPUT:
        assert word not in text, word


# --- Usuarios ---------------------------------------------------------------------------------------
def test_get_admin_users_contract(login_as, make_user):
    """GET /admin/users: paginación, filtros y exactamente los campos del contrato."""
    client, _ = login_as("admin")
    make_user(role=Role.AUDITOR)
    resp = client.get("/admin/users?role=auditor&status=active&page=1")
    assert resp.status_code == 200
    assert resp.headers.get("Cache-Control") == "no-store"
    body = resp.json()
    assert set(body) == {"results", "next", "previous"}
    assert body["results"], "el filtro debía devolver al menos el Auditor creado"
    for item in body["results"]:
        assert set(item) == ADMIN_USER_ITEM
        assert item["role"] == "auditor" and item["status"] == "active"
    _no_sensitive_keys(body)


def test_get_admin_users_pagination(login_as, make_user):
    client, _ = login_as("admin")
    for _ in range(21):
        make_user(role=Role.CLIENT)
    first = client.get("/admin/users?role=client").json()
    assert len(first["results"]) == 20 and first["next"] == 2 and first["previous"] is None
    second = client.get("/admin/users?role=client&page=2").json()
    assert second["previous"] == 1


@pytest.mark.parametrize("query", ["role=root", "status=borrado", "page=0", "foo=1"])
def test_get_admin_users_rejects_invalid_filters(login_as, query):
    client, _ = login_as("admin")
    resp = client.get(f"/admin/users?{query}")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "validation_error"


def test_get_admin_users_reports_mfa_enabled(login_as):
    client, admin = login_as("admin")
    item = next(i for i in client.get("/admin/users?role=admin").json()["results"] if i["id"] == str(admin.id))
    assert item["mfa_enabled"] is True


def test_post_admin_users_contract(login_as):
    """POST /admin/users: creación de usuario privilegiado."""
    client, _ = login_as("admin")
    resp = client.post(
        "/admin/users",
        {"email": "nuevo-auditor@lab.securefin.local", "name": "Nuevo Auditor", "role": Role.AUDITOR},
    )
    assert resp.status_code == 201
    assert resp.headers.get("Cache-Control") == "no-store"
    body = resp.json()
    assert set(body) == {"id", "status"} and body["status"] == Status.PENDING_ACTIVATION


def test_post_admin_users_invalid_role_contract(login_as):
    """POST /admin/users rechaza roles no privilegiados como 'client' con 400."""
    client, _ = login_as("admin")
    resp = client.post(
        "/admin/users",
        {"email": "nuevo-cliente@lab.securefin.local", "name": "Cliente Rechazado", "role": Role.CLIENT},
    )
    assert resp.status_code == 400


def test_post_admin_users_rejects_unknown_fields(login_as):
    client, _ = login_as("admin")
    resp = client.post(
        "/admin/users",
        {"email": "x@lab.securefin.local", "name": "X", "role": "auditor", "password": STRONG_PASSWORD},
    )
    assert resp.status_code == 400


def test_post_admin_users_duplicate_email_conflict(login_as, make_user):
    client, _ = login_as("admin")
    existing = make_user()
    resp = client.post("/admin/users", {"email": existing.email.upper(), "name": "Dup", "role": "auditor"})
    assert resp.status_code == 409


def test_post_resend_activation_contract(login_as, make_user):
    """POST /admin/users/{id}/activation/resend devuelve 204; sobre una cuenta activa, 409."""
    client, _ = login_as("admin")
    target = make_user(status=Status.PENDING_ACTIVATION)
    assert client.post(f"/admin/users/{target.id}/activation/resend", {}).status_code == 204
    active = make_user()
    assert client.post(f"/admin/users/{active.id}/activation/resend", {}).status_code == 409


def test_patch_user_role_contract(login_as, make_user):
    """PATCH /admin/users/{id}/role: actualiza rol y devuelve 200."""
    client, _ = login_as("admin")
    target = make_user(role=Role.CLIENT)
    resp = client.patch(f"/admin/users/{target.id}/role", {"role": Role.AUDITOR})
    assert resp.status_code == 200
    assert resp.json()["role"] == Role.AUDITOR


@pytest.mark.parametrize("user_id", ["no-es-un-uuid", str(uuid.uuid4())])
def test_admin_user_routes_unknown_or_malformed_id_404(login_as, user_id):
    client, _ = login_as("admin")
    assert client.patch(f"/admin/users/{user_id}/role", {"role": "auditor"}).status_code == 404
    assert client.post(f"/admin/users/{user_id}/deactivate", {}).status_code == 404
    assert client.post(f"/admin/users/{user_id}/reactivate", {}).status_code == 404
    assert client.post(f"/admin/users/{user_id}/activation/resend", {}).status_code == 404


def test_post_deactivate_and_reactivate_contract(login_as, make_user):
    """POST /admin/users/{id}/deactivate y /reactivate devuelven 204; transiciones inválidas, 409."""
    client, _ = login_as("admin")
    target = make_user(role=Role.CLIENT, status=Status.ACTIVE)

    assert client.post(f"/admin/users/{target.id}/deactivate", {}).status_code == 204
    assert client.post(f"/admin/users/{target.id}/deactivate", {}).status_code == 409
    assert client.post(f"/admin/users/{target.id}/reactivate", {}).status_code == 204
    assert client.post(f"/admin/users/{target.id}/reactivate", {}).status_code == 409


# --- Reinicio de MFA --------------------------------------------------------------------------------
def test_get_mfa_resets_contract(login_as, make_user):
    """GET /admin/mfa-resets: lista de casos y exactamente los campos del contrato."""
    client, _ = login_as("admin")
    case = requested_case(make_user())
    resp = client.get("/admin/mfa-resets?status=requested")
    assert resp.status_code == 200
    assert resp.headers.get("Cache-Control") == "no-store"
    body = resp.json()
    assert set(body) == {"results"}
    item = next(i for i in body["results"] if i["case_id"] == str(case.id))
    assert set(item) == MFA_RESET_ITEM and item["status"] == "requested"
    _no_sensitive_keys(body)


def test_get_mfa_resets_rejects_unknown_status(login_as):
    client, _ = login_as("admin")
    assert client.get("/admin/mfa-resets?status=foo").status_code == 400


def test_post_mfa_reset_open_contract(login_as, make_user):
    """POST /admin/mfa-resets/{case_id}/open devuelve 200 {status: 'pending_verification'}."""
    client, _ = login_as("admin")
    case = requested_case(make_user())
    resp = client.post(f"/admin/mfa-resets/{case.id}/open", {"request_channel": "in_person"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "pending_verification"}
    # Un caso que ya no está `requested` → 409
    again = client.post(f"/admin/mfa-resets/{case.id}/open", {"request_channel": "in_person"})
    assert again.status_code == 409


def test_post_mfa_reset_open_rejects_unknown_channel(login_as, make_user):
    client, _ = login_as("admin")
    case = requested_case(make_user())
    assert client.post(f"/admin/mfa-resets/{case.id}/open", {"request_channel": "email"}).status_code == 400


@pytest.mark.parametrize("case_id", ["no-es-un-uuid", str(uuid.uuid4())])
def test_mfa_reset_routes_unknown_case_404(login_as, case_id):
    client, admin = login_as("admin")
    assert client.post(f"/admin/mfa-resets/{case_id}/open", {"request_channel": "in_person"}).status_code == 404
    body = {"verification_code": "ABCDEFGH", "admin_totp_code": fresh_totp(admin), "channel_confirmed": True}
    assert client.post(f"/admin/mfa-resets/{case_id}/authorize", body).status_code == 404
    assert client.post(f"/admin/mfa-resets/{case_id}/cancel", {}).status_code == 404


def test_post_mfa_reset_authorize_contract(login_as, make_user):
    """POST /admin/mfa-resets/{case_id}/authorize devuelve 200 {status: 'authorized'}."""
    client, admin = login_as("admin")
    case, code = opened_case(admin, make_user())
    resp = client.post(
        f"/admin/mfa-resets/{case.id}/authorize",
        {"verification_code": code, "admin_totp_code": fresh_totp(admin), "channel_confirmed": True},
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "authorized"}


def test_post_mfa_reset_authorize_requires_channel_confirmation(login_as, make_user):
    client, admin = login_as("admin")
    case, code = opened_case(admin, make_user())
    resp = client.post(
        f"/admin/mfa-resets/{case.id}/authorize",
        {"verification_code": code, "admin_totp_code": fresh_totp(admin), "channel_confirmed": False},
    )
    assert resp.status_code == 400
    case.refresh_from_db()
    assert case.status == MfaResetStatus.PENDING_VERIFICATION and case.challenge_attempts == 0


def test_post_mfa_reset_cancel_contract(login_as, make_user):
    """POST /admin/mfa-resets/{case_id}/cancel devuelve 204; un caso ya cerrado, 409."""
    client, _ = login_as("admin")
    case = requested_case(make_user())
    assert client.post(f"/admin/mfa-resets/{case.id}/cancel", {}).status_code == 204
    assert client.post(f"/admin/mfa-resets/{case.id}/cancel", {}).status_code == 409


# --- Auxiliares (§2) --------------------------------------------------------------------------------
def test_post_auth_activate_contract(api, db):
    """POST /auth/activate devuelve 400 invalid_token ante token inválido."""
    resp = api.post("/auth/activate", {"token": "token_invalido_de_prueba", "password": STRONG_PASSWORD})
    assert resp.status_code == 400
    assert resp.json().get("error", {}).get("code") == "invalid_token"


def test_post_auth_activate_success_204(api, make_user):
    user = make_user(role=Role.AUDITOR, status=Status.PENDING_ACTIVATION)
    token = tokens.issue(user, "account_activation")
    resp = api.post("/auth/activate", {"token": token, "password": STRONG_PASSWORD})
    assert resp.status_code == 204
    assert resp.content == b""


def test_post_auth_activate_requires_csrf(api, make_user):
    resp = api.post("/auth/activate", {"token": "x" * 43, "password": STRONG_PASSWORD}, csrf=False)
    assert resp.status_code == 403


def test_post_mfa_reset_request_contract(api, make_user):
    """POST /auth/login/mfa-reset-request devuelve 202 status: 'mfa_reset_requested' en pre_auth."""
    user = make_user()
    make_totp_device(user)
    api.login(user.email, STRONG_PASSWORD)
    resp = api.post("/auth/login/mfa-reset-request", {})
    assert resp.status_code == 202
    assert resp.json() == {"status": "mfa_reset_requested"}
