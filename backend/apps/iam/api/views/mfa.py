"""Vistas de MFA (T078; contrato §2 y §3).

Login en dos pasos (`pre_auth`, rutas anónimas de la lista permitida con CSRF obligatorio):
  POST /auth/login/mfa, /auth/login/enroll/setup, /auth/login/enroll/confirm
  Sin sesión `pre_auth` válida → 401 genérico (nunca indican el motivo).

Autoservicio (Full + Owner, permiso de función declarado):
  POST /users/{id}/mfa/totp/setup|confirm|disable, /users/{id}/mfa/recovery-codes/regenerate

Las respuestas con secreto o códigos llevan `Cache-Control: no-store` (además de la cabecera global).
"""

from __future__ import annotations

import functools

from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.iam.api.decorators import anonymous_state_changing
from apps.iam.api.exceptions import BusinessRuleConflict, VerificationFailedError
from apps.iam.api.permissions import resolve_owned_user
from apps.iam.api.serializers.mfa import (
    EmptySerializer,
    LoginMfaSerializer,
    OptionalPasswordSerializer,
    ReauthSerializer,
    TotpCodeSerializer,
)
from apps.iam.api.views.users import OwnResourceView
from apps.iam.policies.matrix import MFA_DISABLE_SELF, MFA_SELF, RECOVERY_CODES_SELF
from apps.iam.services import authentication, mfa, recovery_codes
from apps.iam.services.mfa_state import user_mfa_enabled
from apps.iam.sessions.middleware import client_ip


def _no_store(response: Response) -> Response:
    response["Cache-Control"] = "no-store"
    return response


def _validated(serializer_class, request) -> dict:
    serializer = serializer_class(data=request.data)
    serializer.is_valid(raise_exception=True)
    return serializer.validated_data


def _mfa_errors(func):
    """Traduce los errores del servicio a respuestas del contrato."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except mfa.VerificationFailed as exc:
            raise VerificationFailedError() from exc
        except mfa.MfaNotEnabled as exc:
            raise BusinessRuleConflict("El MFA no está activo.") from exc
        except mfa.MfaPolicyError as exc:
            raise PermissionDenied() from exc

    return wrapper


# --- Login en dos pasos (pre_auth) ----------------------------------------------------------------
@anonymous_state_changing
class LoginMfaView(APIView):
    def post(self, request):
        data = _validated(LoginMfaSerializer, request)
        try:
            user, remaining = authentication.complete_mfa(
                request,
                client_ip(request),
                totp_code=data.get("totp_code"),
                recovery_code=data.get("recovery_code"),
            )
        except authentication.AuthenticationFailedError as exc:
            raise AuthenticationFailed() from exc
        body = {"status": "authenticated", "user": authentication.user_summary(user)}
        if remaining is not None:
            body["recovery_codes_remaining"] = remaining
        return _no_store(Response(body))


@anonymous_state_changing
class EnrollSetupView(APIView):
    def post(self, request):
        _validated(EmptySerializer, request)
        user = authentication.pending_enrollment_user(request)
        if user is None:
            raise AuthenticationFailed()
        return _no_store(Response(mfa.start_enrollment(user)))


@anonymous_state_changing
class EnrollConfirmView(APIView):
    def post(self, request):
        data = _validated(TotpCodeSerializer, request)
        try:
            user, codes = authentication.complete_enrollment(request, data["totp_code"], client_ip(request))
        except authentication.AuthenticationFailedError as exc:
            raise AuthenticationFailed() from exc
        body = {"status": "authenticated", "user": authentication.user_summary(user), "recovery_codes": codes}
        return _no_store(Response(body))


# --- Autoservicio (Full + Owner) ------------------------------------------------------------------
class TotpSetupView(OwnResourceView):
    required_permission = MFA_SELF

    @_mfa_errors
    def post(self, request, user_id):
        owner = resolve_owned_user(request, user_id)
        data = _validated(OptionalPasswordSerializer, request)
        if user_mfa_enabled(owner):
            # Reconfigurar exige la contraseña (FR-031); el código del nuevo dispositivo llega en confirm.
            if "password" not in data:
                raise ValidationError({"password": ["Confirma tu contraseña para reconfigurar el MFA."]})
            mfa.reauthenticate_password(owner, data["password"])
        return _no_store(Response(mfa.start_enrollment(owner)))


class TotpConfirmView(OwnResourceView):
    required_permission = MFA_SELF

    @_mfa_errors
    def post(self, request, user_id):
        owner = resolve_owned_user(request, user_id)
        data = _validated(TotpCodeSerializer, request)
        codes = mfa.confirm_enrollment(owner, data["totp_code"], session=request.session)
        return _no_store(Response({"recovery_codes": codes}))


class TotpDisableView(OwnResourceView):
    required_permission = MFA_DISABLE_SELF

    @_mfa_errors
    def post(self, request, user_id):
        owner = resolve_owned_user(request, user_id)
        data = _validated(ReauthSerializer, request)
        mfa.disable(owner, data["password"], data["totp_code"], session=request.session)
        return Response(status=status.HTTP_204_NO_CONTENT)


class RecoveryCodesRegenerateView(OwnResourceView):
    required_permission = RECOVERY_CODES_SELF

    @_mfa_errors
    def post(self, request, user_id):
        owner = resolve_owned_user(request, user_id)
        data = _validated(ReauthSerializer, request)
        codes = recovery_codes.regenerate(owner, data["password"], data["totp_code"], session=request.session)
        return _no_store(Response({"recovery_codes": codes}))
