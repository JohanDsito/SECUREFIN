"""Entrega de la cookie CSRF (T041; R3; I1).

Pedir el token CSRF NO crea ninguna sesión: CSRF_USE_SESSIONS = False y la cookie
`__Host-sf_csrftoken` es independiente del almacén de sesiones (SC19).
"""

from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


@method_decorator(ensure_csrf_cookie, name="dispatch")
class CsrfView(APIView):
    permission_classes = [AllowAny]
    authentication_classes: list = []

    def get(self, request):
        return Response(status=204)


def csrf_failure(request, reason=""):
    """Respuesta JSON uniforme ante un fallo de CSRF (403). No revela el motivo interno."""
    return JsonResponse(
        {"error": {"code": "csrf_failed", "message": "Falta o es inválido el token CSRF."}},
        status=403,
    )
