"""Middleware transversal: identificador de petición (R14)."""

from __future__ import annotations

import contextvars
import uuid

_request_id: contextvars.ContextVar[uuid.UUID | None] = contextvars.ContextVar(
    "securefin_request_id", default=None
)


def current_request_id() -> uuid.UUID:
    """Identificador de la petición actual; fuera de una petición se genera uno nuevo."""
    value = _request_id.get()
    return value if value is not None else uuid.uuid4()


class RequestIdMiddleware:
    """Asigna un UUID a cada petición para correlacionar logs técnicos y eventos de auditoría."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = uuid.uuid4()
        request.request_id = request_id
        token = _request_id.set(request_id)
        try:
            response = self.get_response(request)
        finally:
            _request_id.reset(token)
        response["X-Request-ID"] = str(request_id)
        return response


class ApiNoStoreMiddleware:
    """Las respuestas de la API nunca se cachean (contrato §1; T-19)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.path.startswith("/api/"):
            response["Cache-Control"] = "no-store"
        return response
