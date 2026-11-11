"""Formato uniforme de errores (contrato §1): {"error": {"code", "message"}}."""

from __future__ import annotations

from rest_framework import exceptions
from rest_framework.views import exception_handler as drf_exception_handler

AUTH_FAILED_MESSAGE = "Credenciales inválidas o demasiados intentos. Inténtalo más tarde."


class BusinessRuleConflict(exceptions.APIException):
    status_code = 409
    default_code = "conflict"
    default_detail = "La operación entra en conflicto con una regla de negocio."


class VerificationFailedError(exceptions.APIException):
    """Reautenticación fallida en una operación sobre el propio MFA (contraseña o código)."""

    status_code = 400
    default_code = "verification_failed"
    default_detail = "No se pudo verificar la contraseña o el código."


class InvalidTokenError(exceptions.APIException):
    status_code = 400
    default_code = "invalid_token"
    default_detail = "El enlace no es válido o ha caducado."


def _first_message(data) -> str:
    if isinstance(data, dict):
        for value in data.values():
            return _first_message(value)
    if isinstance(data, list) and data:
        return _first_message(data[0])
    return str(data)


def exception_handler(exc, context):
    response = drf_exception_handler(exc, context)
    if response is None:
        return None
    if isinstance(exc, (exceptions.NotAuthenticated, exceptions.AuthenticationFailed)):
        error = {"code": "auth_failed", "message": AUTH_FAILED_MESSAGE}
    elif isinstance(exc, exceptions.ValidationError):
        error = {
            "code": "validation_error",
            "message": _first_message(response.data),
            "fields": response.data,
        }
    elif isinstance(exc, exceptions.PermissionDenied):
        if str(exc.detail).startswith("CSRF Failed"):
            error = {"code": "csrf_failed", "message": "Falta o es inválido el token CSRF."}
        else:
            code = exc.get_codes()
            # Códigos de negocio propios (p. ej. self_action_forbidden) se conservan; el genérico
            # de DRF se publica como "forbidden".
            if not isinstance(code, str) or code == "permission_denied":
                code = "forbidden"
            error = {"code": code, "message": "No tienes permiso para realizar esta acción."}
    elif isinstance(exc, exceptions.NotFound):
        error = {"code": "not_found", "message": "Recurso no encontrado."}
    elif isinstance(exc, exceptions.Throttled):
        error = {"code": "throttled", "message": "Demasiadas solicitudes. Inténtalo más tarde."}
    elif isinstance(exc, exceptions.MethodNotAllowed):
        error = {"code": "method_not_allowed", "message": "Método no permitido."}
    else:
        # Las vistas financieras levantan APIException(detail={"detail": "..."}): se extrae el texto y
        # el código anidados en lugar de publicar el repr del diccionario ("{'detail': ErrorDetail(…)}").
        codes = exc.get_codes() if hasattr(exc, "get_codes") else "error"
        while isinstance(codes, (dict, list)) and codes:
            codes = next(iter(codes.values())) if isinstance(codes, dict) else codes[0]
        detail = getattr(exc, "detail", exc)
        message = _first_message(detail) if isinstance(detail, (dict, list)) else str(detail)
        error = {"code": codes if isinstance(codes, str) else "error", "message": message}
    response.data = {"error": error}
    return response
