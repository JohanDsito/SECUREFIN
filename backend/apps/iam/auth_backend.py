"""Backend que recupera el usuario de la sesión (para AuthenticationMiddleware y login()).

La verificación de credenciales la hace el servicio de autenticación; este backend solo resuelve el
usuario de `_auth_user_id` y descarta cuentas no activas (FR-012: una cuenta desactivada pierde
el acceso de inmediato).
"""

from apps.iam.models import Status, User


class SessionUserBackend:
    def authenticate(self, request, **credentials):  # no se usa: ver services.authentication
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id, status=Status.ACTIVE)
        except (User.DoesNotExist, ValueError):
            return None
