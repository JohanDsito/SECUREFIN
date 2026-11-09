"""Estado de MFA de un usuario. El modelo TOTPDevice llega en US3; hasta entonces no hay MFA."""

from django.core.exceptions import ObjectDoesNotExist


def user_mfa_enabled(user) -> bool:
    try:
        device = user.totp_device
    except (ObjectDoesNotExist, AttributeError):
        return False
    return getattr(device, "status", None) == "active"
