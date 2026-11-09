"""TS-I09 / TS-I10 (T068): TOTP (antirrepetición y tolerancia), códigos de recuperación de un solo
uso, concurrencia con select_for_update y caducidad del alta pendiente."""

from __future__ import annotations

import threading
from datetime import timedelta

import pytest
from django.db import connection

from apps.iam.models import RecoveryCode, TOTPDevice
from apps.iam.services import mfa, recovery_codes
from tests.helpers import make_totp_device, totp_code

pytestmark = pytest.mark.integration


# --- TOTP -----------------------------------------------------------------------------------------
def test_repeated_totp_code_is_rejected_by_api(api_factory, make_user):
    user = make_user()
    secret = make_totp_device(user)
    code = totp_code(secret)
    first = api_factory()
    first.login(user.email)
    assert first.post("/auth/login/mfa", {"totp_code": code}).status_code == 200
    second = api_factory()
    assert second.login(user.email).json() == {"status": "mfa_required"}
    assert second.post("/auth/login/mfa", {"totp_code": code}).status_code == 401  # V11


@pytest.mark.parametrize(("steps", "accepted"), [(-2, False), (-1, True), (0, True), (1, True), (2, False)])
def test_tolerance_is_one_interval(make_user, clock, steps, accepted):
    user = make_user()
    secret = make_totp_device(user)
    assert mfa.verify_totp(user, totp_code(secret, steps=steps)) is accepted


def test_timestep_must_strictly_increase(make_user, clock):
    user = make_user()
    secret = make_totp_device(user)
    assert mfa.verify_totp(user, totp_code(secret, steps=1)) is True
    # Un código anterior (aunque esté dentro de la ventana) ya no se acepta.
    assert mfa.verify_totp(user, totp_code(secret, steps=0)) is False
    assert mfa.verify_totp(user, totp_code(secret, steps=1)) is False
    clock.advance(seconds=60)
    assert mfa.verify_totp(user, totp_code(secret)) is True


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", None, "１２３４５６"])
def test_malformed_totp_codes(make_user, bad):
    user = make_user()
    make_totp_device(user)
    assert mfa.verify_totp(user, bad) is False


def test_verify_without_active_device(make_user):
    user = make_user()
    assert mfa.verify_totp(user, "123456") is False


# --- Códigos de recuperación ----------------------------------------------------------------------
def test_recovery_codes_single_use(make_user):
    user = make_user()
    make_totp_device(user)
    codes = recovery_codes.generate_batch(user)
    assert len(codes) == 10 and len(set(codes)) == 10
    assert recovery_codes.consume(user, codes[0]) == 9
    assert recovery_codes.consume(user, codes[0]) is None
    assert recovery_codes.consume(user, codes[1]) == 8


def test_recovery_code_input_is_normalized(make_user):
    user = make_user()
    codes = recovery_codes.generate_batch(user)
    raw = codes[0]
    messy = " ".join(raw[i : i + 4] for i in range(0, 28, 4)).lower()
    assert recovery_codes.consume(user, messy) == 9


def test_previous_batch_is_rejected(make_user):
    user = make_user()
    old = recovery_codes.generate_batch(user)
    new = recovery_codes.generate_batch(user)
    assert recovery_codes.consume(user, old[0]) is None
    assert RecoveryCode.objects.filter(user=user, status="invalidated").count() == 10
    assert recovery_codes.consume(user, new[0]) == 9


def test_recovery_codes_are_stored_only_as_argon2id(make_user):
    user = make_user()
    codes = recovery_codes.generate_batch(user)
    stored = list(RecoveryCode.objects.filter(user=user).values_list("verifier", flat=True))
    assert all(v.startswith("$argon2id$v=19$m=19456,t=2,p=1$") for v in stored)
    assert not any(code in v for code in codes for v in stored)


@pytest.mark.parametrize("bad", ["", "X" * 27, "X" * 29, "U" * 28, None])
def test_malformed_recovery_codes(make_user, bad):
    user = make_user()
    recovery_codes.generate_batch(user)
    assert recovery_codes.consume(user, bad) is None


# --- Concurrencia (select_for_update) -------------------------------------------------------------
def _race(target, *args):
    barrier = threading.Barrier(2)
    results = []

    def run():
        try:
            barrier.wait()
            results.append(target(*args))
        finally:
            connection.close()

    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_concurrent_recovery_code_consumed_once(concurrent_db, make_user):
    user = make_user()
    codes = recovery_codes.generate_batch(user)
    results = _race(recovery_codes.consume, user, codes[0])
    assert sorted(results, key=lambda r: r is None) == [9, None]


def test_concurrent_totp_code_accepted_once(concurrent_db, make_user):
    user = make_user()
    secret = make_totp_device(user)
    results = _race(mfa.verify_totp, user, totp_code(secret))
    assert sorted(results) == [False, True]


# --- Alta pendiente -------------------------------------------------------------------------------
def test_pending_enrollment_expires_after_10_minutes(make_user, clock):
    user = make_user()
    data = mfa.start_enrollment(user)
    clock.advance(minutes=10, seconds=1)
    with pytest.raises(mfa.MfaError):
        mfa.confirm_enrollment(user, totp_code(data["secret_base32"]))
    assert not TOTPDevice.objects.filter(user=user, status="active").exists()
    assert not RecoveryCode.objects.filter(user=user).exists()


def test_pending_enrollment_within_10_minutes(make_user, clock):
    user = make_user()
    data = mfa.start_enrollment(user)
    clock.advance(minutes=9, seconds=59)
    codes = mfa.confirm_enrollment(user, totp_code(data["secret_base32"]))
    assert len(codes) == 10
    assert TOTPDevice.objects.get(user=user).status == "active"


def test_new_setup_replaces_previous_pending(make_user):
    user = make_user()
    first = mfa.start_enrollment(user)
    second = mfa.start_enrollment(user)
    assert first["secret_base32"] != second["secret_base32"]
    assert TOTPDevice.objects.filter(user=user, status="pending").count() == 1
    with pytest.raises(mfa.MfaError):
        mfa.confirm_enrollment(user, totp_code(first["secret_base32"]))


def test_reconfiguration_keeps_active_device_until_confirmed(make_user):
    user = make_user()
    old_secret = make_totp_device(user)
    old_codes = recovery_codes.generate_batch(user)
    data = mfa.start_enrollment(user)
    # Abandonar el alta no desactiva el MFA vigente.
    assert TOTPDevice.objects.filter(user=user, status="active").count() == 1
    assert mfa.verify_totp(user, totp_code(old_secret)) is True
    new_codes = mfa.confirm_enrollment(user, totp_code(data["secret_base32"]))
    assert TOTPDevice.objects.filter(user=user).count() == 1
    assert recovery_codes.consume(user, old_codes[0]) is None
    assert recovery_codes.consume(user, new_codes[0]) == 9
    assert mfa.verify_totp(user, totp_code(old_secret, steps=1)) is False


def test_secret_is_never_stored_in_clear(make_user):
    user = make_user()
    data = mfa.start_enrollment(user)
    device = TOTPDevice.objects.get(user=user)
    assert data["secret_base32"].encode() not in bytes(device.secret_ciphertext)
    assert len(bytes(device.nonce)) == 12 and device.key_version == "v1"


# --- Invariantes del modelo y concurrencia de alta/confirmación (revisión de US3) ------------------
def _raw_device(user, status):
    from apps.iam.crypto import aead

    enc = aead.encrypt_totp_secret(user.id, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
    return TOTPDevice(user=user, status=status, secret_ciphertext=enc.ciphertext, nonce=enc.nonce,
                      key_version=enc.key_version)


@pytest.mark.parametrize("status", ["active", "pending"])
def test_database_allows_at_most_one_device_per_open_state(make_user, status):
    from django.db import IntegrityError, transaction

    user = make_user()
    _raw_device(user, status).save()
    with pytest.raises(IntegrityError), transaction.atomic():
        _raw_device(user, status).save()


def test_one_active_and_one_pending_can_coexist(make_user):
    user = make_user()
    _raw_device(user, "active").save()
    _raw_device(user, "pending").save()
    assert TOTPDevice.objects.filter(user=user).count() == 2


def test_unique_constraints_are_conditional_on_open_states():
    """La unicidad se limita a `active` y `pending`: un estado histórico futuro no quedaría limitado."""
    constraints = {c.name: c for c in TOTPDevice._meta.constraints}
    for name, state in (("iam_totp_one_active_per_user", "active"), ("iam_totp_one_pending_per_user", "pending")):
        constraint = constraints[name]
        assert constraint.fields == ("user",)
        assert constraint.condition.children == [("status", state)]
    assert "iam_totp_one_per_status" not in constraints


def test_concurrent_setups_do_not_fail(concurrent_db, make_user):
    user = make_user()
    results = _race(lambda u: mfa.start_enrollment(u)["secret_base32"], user)
    assert len(results) == 2  # ninguna petición termina en error (antes: IntegrityError → 500)
    assert TOTPDevice.objects.filter(user=user, status="pending").count() == 1


def test_concurrent_confirmations_never_create_two_active_devices(concurrent_db, make_user):
    user = make_user()
    secret = mfa.start_enrollment(user)["secret_base32"]
    code = totp_code(secret)

    def confirm(u):
        try:
            return len(mfa.confirm_enrollment(u, code))
        except mfa.MfaError:
            return "rechazada"

    assert sorted(_race(confirm, user), key=str) == [10, "rechazada"]
    assert TOTPDevice.objects.filter(user=user, status="active").count() == 1
    assert RecoveryCode.objects.filter(user=user, status="available").count() == 10


def test_concurrent_setup_and_confirm_keep_a_single_active_device(concurrent_db, make_user):
    user = make_user()
    make_totp_device(user)  # MFA vigente
    secret = mfa.start_enrollment(user)["secret_base32"]
    code = totp_code(secret)
    barrier = threading.Barrier(2)
    errors = []

    def run(target):
        try:
            barrier.wait()
            target()
        except mfa.MfaError:
            pass
        except Exception as exc:  # noqa: BLE001 - cualquier otro error es un fallo de la prueba
            errors.append(exc)
        finally:
            connection.close()

    threads = [
        threading.Thread(target=run, args=(lambda: mfa.confirm_enrollment(user, code),)),
        threading.Thread(target=run, args=(lambda: mfa.start_enrollment(user),)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert TOTPDevice.objects.filter(user=user, status="active").count() == 1
    assert TOTPDevice.objects.filter(user=user, status="pending").count() <= 1


def test_concurrent_batch_generation_leaves_a_single_batch(concurrent_db, make_user):
    user = make_user()
    _race(recovery_codes.generate_batch, user)
    available = RecoveryCode.objects.filter(user=user, status="available")
    assert available.count() == 10
    assert available.values("batch_id").distinct().count() == 1
