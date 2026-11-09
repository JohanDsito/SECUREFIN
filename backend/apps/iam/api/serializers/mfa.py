"""Serializers de MFA con lista permitida de campos (T078; contrato §2–§3).

Las longitudes máximas se comprueban antes de cualquier operación costosa (descifrado, Argon2id).
"""

from __future__ import annotations

from rest_framework import serializers

from apps.iam.api.serializers.auth import StrictSerializer
from apps.iam.policies.password_validators import MAX_PASSWORD_LENGTH


def _code_field(max_length: int, required: bool = True):
    return serializers.CharField(max_length=max_length, required=required, trim_whitespace=True)


def _password_field(required: bool = True):
    return serializers.CharField(max_length=MAX_PASSWORD_LENGTH, required=required, trim_whitespace=False)


class EmptySerializer(StrictSerializer):
    """Cuerpo vacío: cualquier campo se rechaza con 400."""


class LoginMfaSerializer(StrictSerializer):
    totp_code = _code_field(10, required=False)
    recovery_code = _code_field(64, required=False)

    def validate(self, attrs):
        if ("totp_code" in attrs) == ("recovery_code" in attrs):
            raise serializers.ValidationError(
                {"non_field_errors": ["Envía un código TOTP o un código de recuperación."]}
            )
        return attrs


class TotpCodeSerializer(StrictSerializer):
    totp_code = _code_field(10)


class OptionalPasswordSerializer(StrictSerializer):
    password = _password_field(required=False)


class ReauthSerializer(StrictSerializer):
    password = _password_field()
    totp_code = _code_field(10)
