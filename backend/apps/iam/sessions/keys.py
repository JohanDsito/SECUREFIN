"""Claves internas de los datos de sesión (R2, R13; I1, I3, U3)."""

# Nivel de autenticación de la sesión: "pre_auth" o "full". Sin él, la sesión no se persiste (I1).
LEVEL = "_sf_auth_level"
# Usuario con la contraseña validada y el MFA pendiente. No autentica ni da permisos (U3).
PENDING_USER = "_sf_pending_user_id"
# Creación inicial de la sesión (ISO 8601). Se hereda en cada rotación: origen del límite de 8 h (I3).
CREATED_AT = "_sf_created_at"
# Momento del paso a "full" (ISO 8601); informativo.
AUTHENTICATED_AT = "_sf_authenticated_at"
# Duración de la fase pre_auth en segundos (300 normal, 600 en un alta obligatoria de MFA).
PRE_AUTH_TTL = "_sf_pre_auth_ttl"
# Clave de Django con el usuario autenticado tras login().
DJANGO_USER = "_auth_user_id"

PRE_AUTH = "pre_auth"
FULL = "full"
