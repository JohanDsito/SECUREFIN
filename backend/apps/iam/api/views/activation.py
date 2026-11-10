"""POST /auth/activate (T087; contrato §2; FR-021).

Ruta anónima de la lista permitida, con CSRF obligatorio (`anonymous_state_changing`).

- Token usado, caducado, sustituido, alterado o de una cuenta que ya no está pendiente →
  `400 invalid_token`, siempre con el mismo mensaje.
- Contraseña que incumple la política → `400 validation_error` con los mensajes del validador; el
  canje del token se revierte, de modo que el enlace sigue sirviendo para otro intento.
- Éxito → `204`. No se crea sesión: el usuario inicia sesión y configura el MFA si su rol lo exige.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.iam.api.decorators import anonymous_state_changing
from apps.iam.api.exceptions import InvalidTokenError
from apps.iam.api.serializers.admin import ActivateSerializer
from apps.iam.services import activation, tokens
from apps.iam.sessions.middleware import client_ip


@anonymous_state_changing
class ActivateView(APIView):
    def post(self, request):
        serializer = ActivateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            activation.activate(data["token"], data["password"], source_ip=client_ip(request))
        except tokens.InvalidToken as exc:
            raise InvalidTokenError() from exc
        except DjangoValidationError as exc:
            raise ValidationError({"password": exc.messages}) from exc
        return Response(status=status.HTTP_204_NO_CONTENT)
