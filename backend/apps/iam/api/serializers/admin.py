"""Serializers de administración y activación (T090, T087; contrato §2 y §4; FR-002).

Entrada: lista permitida estricta (`StrictSerializer`), también para los parámetros de consulta.
Salida: solo los campos del contrato; nunca contraseñas, verificadores, códigos ni tokens.
"""

from __future__ import annotations

from rest_framework import serializers

from apps.iam.api.serializers.auth import StrictSerializer
from apps.iam.api.serializers.mfa import _code_field
from apps.iam.models import MfaResetStatus, RequestChannel, Role, Status
from apps.iam.models.user import validate_no_control_chars
from apps.iam.policies.password_validators import MAX_PASSWORD_LENGTH
from apps.iam.services.admin_users import PRIVILEGED_ROLES


# --- Usuarios (§4) ----------------------------------------------------------------------------------
class UserListQuerySerializer(StrictSerializer):
    role = serializers.ChoiceField(choices=Role.choices, required=False)
    status = serializers.ChoiceField(choices=Status.choices, required=False)
    page = serializers.IntegerField(min_value=1, max_value=100000, required=False, default=1)


class AdminUserItemSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    email = serializers.EmailField(read_only=True)
    name = serializers.CharField(read_only=True)
    role = serializers.CharField(read_only=True)
    status = serializers.CharField(read_only=True)
    mfa_enabled = serializers.BooleanField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    last_login_at = serializers.DateTimeField(read_only=True)


class CreatePrivilegedUserSerializer(StrictSerializer):
    email = serializers.EmailField(max_length=254)
    name = serializers.CharField(min_length=1, max_length=100, validators=[validate_no_control_chars])
    role = serializers.ChoiceField(choices=[(r.value, r.label) for r in PRIVILEGED_ROLES])


class ChangeRoleSerializer(StrictSerializer):
    role = serializers.ChoiceField(choices=Role.choices)


# --- Reinicio de MFA (§4) ---------------------------------------------------------------------------
class MfaResetListQuerySerializer(StrictSerializer):
    status = serializers.ChoiceField(choices=MfaResetStatus.choices, required=False)


class MfaResetItemSerializer(serializers.Serializer):
    case_id = serializers.UUIDField(read_only=True)
    target_user_id = serializers.UUIDField(read_only=True)
    target_email = serializers.EmailField(read_only=True)
    requested_at = serializers.DateTimeField(read_only=True)
    status = serializers.CharField(read_only=True)


class OpenCaseSerializer(StrictSerializer):
    request_channel = serializers.ChoiceField(choices=RequestChannel.choices)


class AuthorizeCaseSerializer(StrictSerializer):
    verification_code = _code_field(16)
    admin_totp_code = _code_field(10)
    channel_confirmed = serializers.BooleanField()

    def validate_channel_confirmed(self, value):
        if value is not True:
            raise serializers.ValidationError("Confirma el canal fuera de banda por el que recibiste el código.")
        return value


# --- Activación (§2) --------------------------------------------------------------------------------
class ActivateSerializer(StrictSerializer):
    token = serializers.CharField(max_length=128, trim_whitespace=False)
    # Longitud máxima comprobada ANTES de hashear (T-21)
    password = serializers.CharField(max_length=MAX_PASSWORD_LENGTH, trim_whitespace=False)
