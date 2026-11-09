"""Estado de MFA de un usuario. Los modelos TOTPDevice y RecoveryCode llegan en US3; hasta entonces
no hay MFA ni códigos de recuperación."""

from django.core.exceptions import ObjectDoesNotExist


def user_mfa_enabled(user) -> bool:
    try:
        device = user.totp_device
    except (ObjectDoesNotExist, AttributeError):
        return False
    return getattr(device, "status", None) == "active"


def recovery_codes_remaining(user) -> int:
    """Códigos del lote vigente aún disponibles (data-model → RecoveryCode.status = available)."""
    codes = getattr(user, "recovery_codes", None)
    if codes is None:
        return 0
    return codes.filter(status="available").count()
