"""Estado de MFA de un usuario y bloqueo por usuario de las operaciones de MFA."""

from apps.iam.models import RecoveryCode, RecoveryCodeStatus, TOTPDevice, TOTPStatus, User


def user_mfa_enabled(user) -> bool:
    if user is None or not getattr(user, "pk", None):
        return False
    return TOTPDevice.objects.filter(user=user, status=TOTPStatus.ACTIVE).exists()


def recovery_codes_remaining(user) -> int:
    """Códigos del lote vigente aún disponibles."""
    return RecoveryCode.objects.filter(user=user, status=RecoveryCodeStatus.AVAILABLE).count()


def lock_user_mfa(user) -> None:
    """Serializa las operaciones de MFA de un usuario (alta, confirmación, desactivación, lotes).

    Bloquea la fila del usuario con SELECT ... FOR UPDATE; debe llamarse dentro de una transacción.
    Sin él, dos altas simultáneas insertarían dos `pending` (IntegrityError → 500) y dos generaciones
    de lote simultáneas dejarían 20 códigos disponibles. Todas las operaciones bloquean primero el
    usuario y después sus dispositivos o códigos: el orden es siempre el mismo, sin interbloqueos.
    """
    User.objects.select_for_update().only("id").get(pk=user.pk)
