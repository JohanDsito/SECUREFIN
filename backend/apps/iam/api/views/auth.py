"""Vistas de autenticación y sesión (T055; contrato §2)."""

from __future__ import annotations

from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth import logout
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.audit.services import record_event
from apps.iam.api.decorators import anonymous_state_changing
from apps.iam.api.serializers.auth import LoginSerializer, RegisterSerializer
from apps.iam.services import authentication, registration
from apps.iam.sessions import keys as K
from apps.iam.sessions.middleware import client_ip

NEUTRAL_REGISTRATION_ERROR = "No fue posible completar el registro con los datos proporcionados."


@anonymous_state_changing
class RegisterView(APIView):
    throttle_scope = "register"  # T101: 5/h por IP

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            registration.register(data["email"], data["name"], data["password"], client_ip(request))
        except DjangoValidationError as exc:
            raise ValidationError({"password": exc.messages}) from exc
        except registration.RegistrationUnavailable as exc:
            raise ValidationError({"email": [NEUTRAL_REGISTRATION_ERROR]}) from exc
        return Response({"status": "registered"}, status=status.HTTP_201_CREATED)


@anonymous_state_changing
class LoginView(APIView):
    throttle_scope = "login"  # T101: 20/min por IP

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            result = authentication.password_login(
                request, data["email"], data["password"], client_ip(request)
            )
        except authentication.AuthenticationFailedError as exc:
            raise AuthenticationFailed() from exc
        body = {"status": result.status}
        if result.status == "authenticated":
            body["user"] = authentication.user_summary(result.user)
        return Response(body)


@anonymous_state_changing
class LogoutView(APIView):
    def post(self, request):
        user = request.user if request.user.is_authenticated else None
        logout(request)  # flush(): borra la fila de sesión
        if user is not None:
            record_event("logout", "success", actor=user, target_type="user", target_id=user.id,
                         source_ip=client_ip(request))
        return Response(status=status.HTTP_204_NO_CONTENT)


class SessionView(APIView):
    """Sesión actual. Solo sesiones `full` (permiso por defecto IsFullyAuthenticated)."""

    def get(self, request):
        row = request.session.row
        cfg = settings.SECUREFIN_SESSION
        idle = row.last_activity_at + timedelta(seconds=cfg["IDLE_TIMEOUT"])
        created = datetime.fromisoformat(request.session[K.CREATED_AT])
        return Response(
            {
                "user": authentication.user_summary(request.user),
                "session": {
                    "public_id": str(row.public_id),
                    "authenticated_at": request.session.get(K.AUTHENTICATED_AT),
                    "idle_expires_at": idle.isoformat(),
                    "absolute_expires_at": (created + timedelta(seconds=cfg["ABSOLUTE_LIFETIME"])).isoformat(),
                },
            }
        )
