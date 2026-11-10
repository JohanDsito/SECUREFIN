from apps.iam.policies.matrix import has_permission


class FinancePermissionDenied(PermissionError):
    pass


def require_permission(user, permission: str) -> None:
    if not getattr(user, "is_authenticated", False):
        raise FinancePermissionDenied("Se requiere una sesión autenticada.")
    if not has_permission(getattr(user, "role", ""), permission):
        raise FinancePermissionDenied("No tienes permiso para esta operación financiera.")
