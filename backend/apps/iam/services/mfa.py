"""Segundo factor TOTP (T074, T077; R5; FR-024 a FR-027, FR-031, FR-012).

- Secreto de 160 bits (`secrets`), SHA-1, 6 dígitos, periodo de 30 s y tolerancia de ±1 intervalo.
- Antirrepetición: solo se acepta un intervalo estrictamente posterior a `last_used_timestep`,
  comprobado y actualizado bajo `select_for_update` (dos peticiones con el mismo código: una gana).
- El secreto se guarda cifrado con AES-256-GCM (crypto.aead) y solo se devuelve durante el alta.
- Un alta `pending` caduca a los 10 min. Reconfigurar conserva el dispositivo activo hasta confirmar.
- Activar, desactivar o reconfigurar revoca las demás sesiones y rota la actual (FR-012).
- El tiempo sale de `apps.core.clock` (no de `time.time()`) para poder probarlo con un reloj simulado.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import re
import secrets

import pyotp
import segno
from django.db import transaction

from apps.audit.services import record_event
from apps.core import clock
from apps.iam.crypto import aead
from apps.iam.models import TOTPDevice, TOTPStatus
from apps.iam.policies.matrix import mfa_required
from apps.iam.policies.password_validators import normalize_password
from apps.iam.services.mfa_state import lock_user_mfa, user_mfa_enabled

ISSUER = "SecureFin Gateway"
DIGITS = 6
PERIOD = 30
VALID_WINDOW = 1
SECRET_BYTES = 20  # 160 bits
_CODE_RE = re.compile(r"[0-9]{6}")  # solo dígitos ASCII (str.isdigit aceptaría otros sistemas)


class MfaError(Exception):
    """Error de MFA. Los mensajes nunca incluyen secretos ni códigos."""


class VerificationFailed(MfaError):
    """Contraseña o código incorrectos, o alta inexistente o caducada."""


class MfaNotEnabled(MfaError):
    pass


class MfaPolicyError(MfaError):
    """La operación contradice el requisito de MFA del rol (p. ej. desactivarlo siendo Administrador)."""


# --- Primitivas -----------------------------------------------------------------------------------
def _timestep(moment) -> int:
    return int(moment.timestamp()) // PERIOD


def _secret(device: TOTPDevice) -> str | None:
    """Secreto en claro, o None si el texto cifrado no se autentica (alterado, trasplantado de otro
    usuario o con una versión de clave retirada). Falla de forma cerrada y deja rastro en la auditoría."""
    try:
        return aead.decrypt_totp_secret(device.user_id, device.nonce, device.secret_ciphertext, device.key_version)
    except aead.DecryptionError:
        record_event("totp_rejected", "failure", actor_id=device.user_id, target_type="user",
                     target_id=device.user_id, metadata={"reason": "decryption_failed"})
        return None


def _matching_timestep(secret: str | None, code, last_used: int | None) -> int | None:
    """Intervalo (dentro de ±1) cuyo código coincide y es posterior a `last_used`; si no, None."""
    if secret is None or not isinstance(code, str) or not _CODE_RE.fullmatch(code):
        return None
    totp = pyotp.TOTP(secret, digits=DIGITS, interval=PERIOD, digest=hashlib.sha1)
    current = _timestep(clock.now())
    for step in range(current - VALID_WINDOW, current + VALID_WINDOW + 1):
        if last_used is not None and step <= last_used:
            continue
        if hmac.compare_digest(totp.at(step * PERIOD), code):
            return step
    return None


def _qr_data_uri(uri: str) -> str:
    buffer = io.BytesIO()
    segno.make(uri, error="m").save(buffer, kind="svg", scale=4, border=2, xmldecl=False)
    return "data:image/svg+xml;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


# --- Verificación ---------------------------------------------------------------------------------
def verify_totp(user, code) -> bool:
    """Verifica un código con el dispositivo activo y consume su intervalo (antirrepetición)."""
    if not isinstance(code, str) or not _CODE_RE.fullmatch(code):
        return False
    with transaction.atomic():
        device = TOTPDevice.objects.select_for_update().filter(user=user, status=TOTPStatus.ACTIVE).first()
        if device is None:
            return False
        step = _matching_timestep(_secret(device), code, device.last_used_timestep)
        if step is None:
            return False
        device.last_used_timestep = step
        device.save(update_fields=["last_used_timestep"])
    return True


def require_active(user) -> None:
    if not user_mfa_enabled(user):
        raise MfaNotEnabled


def reauthenticate_password(user, password) -> None:
    if not isinstance(password, str) or not user.check_password(normalize_password(password)):
        record_event(
            "login_failed",
            "failure",
            actor=user,
            target_type="user",
            target_id=user.id,
            metadata={"reason": "invalid_credentials", "stage": "reauth"},
        )
        raise VerificationFailed


def reauthenticate(user, password, totp) -> None:
    """Contraseña + código TOTP del dispositivo activo (FR-027, FR-030)."""
    reauthenticate_password(user, password)
    if not verify_totp(user, totp):
        record_event("totp_rejected", "failure", actor=user, target_type="user", target_id=user.id,
                     metadata={"reason": "invalid_code"})
        raise VerificationFailed


# --- Alta, confirmación, desactivación ------------------------------------------------------------
def start_enrollment(user) -> dict:
    """Crea (o sustituye) el alta `pending` y devuelve el secreto una única vez."""
    secret = base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii")
    encrypted = aead.encrypt_totp_secret(user.id, secret)
    with transaction.atomic():
        lock_user_mfa(user)
        TOTPDevice.objects.filter(user=user, status=TOTPStatus.PENDING).delete()
        TOTPDevice.objects.create(
            user=user,
            status=TOTPStatus.PENDING,
            secret_ciphertext=encrypted.ciphertext,
            nonce=encrypted.nonce,
            key_version=encrypted.key_version,
        )
    uri = pyotp.TOTP(secret, digits=DIGITS, interval=PERIOD).provisioning_uri(name=user.email, issuer_name=ISSUER)
    return {"otpauth_uri": uri, "qr_svg_data_uri": _qr_data_uri(uri), "secret_base32": secret}


def confirm_enrollment(user, code, session=None, rotate: bool = True) -> list[str]:
    """Activa el alta pendiente con un código válido y genera los códigos de recuperación.

    Si ya había un dispositivo activo (reconfiguración, FR-031), se sustituye y su lote de códigos
    queda invalidado. Devuelve los códigos en claro una única vez.
    """
    from apps.iam.services import recovery_codes, session_admin

    rejected = False
    with transaction.atomic():
        lock_user_mfa(user)
        pending = (
            TOTPDevice.objects.select_for_update().filter(user=user, status=TOTPStatus.PENDING).first()
        )
        step = None
        if pending is not None and not pending.is_expired_pending():
            step = _matching_timestep(_secret(pending), code, None)
        if step is None:
            rejected = True
        else:
            previous = TOTPDevice.objects.select_for_update().filter(user=user, status=TOTPStatus.ACTIVE).first()
            reconfigured = previous is not None
            if previous is not None:
                previous.delete()
            pending.status = TOTPStatus.ACTIVE
            pending.confirmed_at = clock.now()
            pending.last_used_timestep = step
            pending.save(update_fields=["status", "confirmed_at", "last_used_timestep"])
            new_codes = recovery_codes.generate_batch(user)
            record_event(
                "mfa_reconfigured" if reconfigured else "mfa_enabled",
                "success",
                actor=user,
                target_type="user",
                target_id=user.id,
            )
    if rejected:
        # Fuera de la transacción: el rechazo queda registrado aunque la operación falle.
        record_event("totp_rejected", "failure", actor=user, target_type="user", target_id=user.id,
                     metadata={"reason": "enrollment"})
        raise VerificationFailed
    session_admin.rotate_after_mfa_change(user, session, rotate=rotate)
    return new_codes


def disable(user, password, code, session=None) -> None:
    """Desactiva el MFA (solo roles con MFA opcional; FR-027) e invalida los códigos."""
    from apps.iam.services import recovery_codes, session_admin

    if mfa_required(user.role):
        raise MfaPolicyError
    require_active(user)
    reauthenticate(user, password, code)
    with transaction.atomic():
        lock_user_mfa(user)
        TOTPDevice.objects.filter(user=user).delete()
        recovery_codes.invalidate_all(user)
        record_event("mfa_disabled", "success", actor=user, target_type="user", target_id=user.id)
    session_admin.rotate_after_mfa_change(user, session)
