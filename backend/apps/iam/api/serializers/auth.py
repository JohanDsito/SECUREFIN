"""Serializers de autenticación con lista permitida de campos (T052; FR-002; T-07)."""

from __future__ import annotations

from rest_framework import serializers

from apps.iam.models.user import validate_no_control_chars
from apps.iam.policies.password_validators import MAX_PASSWORD_LENGTH


class StrictSerializer(serializers.Serializer):
    """Rechaza cualquier campo no declarado (p. ej. `role`, `status`, `mfa_*`) con 400."""

    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError({"non_field_errors": ["Se esperaba un objeto JSON."]})
        unknown = sorted(set(data) - set(self.fields))
        if unknown:
            raise serializers.ValidationError(
                {field: ["Campo no permitido."] for field in unknown}
            )
        return super().to_internal_value(data)


class RegisterSerializer(StrictSerializer):
    email = serializers.EmailField(max_length=254)
    name = serializers.CharField(min_length=1, max_length=100, validators=[validate_no_control_chars])
    # Longitud máxima comprobada ANTES de hashear (T-21)
    password = serializers.CharField(max_length=MAX_PASSWORD_LENGTH, trim_whitespace=False)


class LoginSerializer(StrictSerializer):
    email = serializers.CharField(max_length=254)
    password = serializers.CharField(max_length=MAX_PASSWORD_LENGTH, trim_whitespace=False)
