"""Serializers de los recursos propios (T062; contrato §3; FR-018).

Lista permitida en ambos sentidos: en la entrada solo `name` es editable (cualquier otro campo,
incluidos `role`, `status`, `email` y `mfa_*`, da 400); en la salida solo se exponen los campos del
contrato. `SessionSerializer` publica `public_id` y nunca el verificador de la clave.
"""

from __future__ import annotations

from rest_framework import serializers

from apps.iam.api.serializers.auth import StrictSerializer
from apps.iam.models.user import validate_no_control_chars
from apps.iam.policies.matrix import mfa_required
from apps.iam.services.mfa_state import recovery_codes_remaining, user_mfa_enabled


class ProfileSerializer(StrictSerializer):
    id = serializers.UUIDField(read_only=True)
    email = serializers.EmailField(read_only=True)
    name = serializers.CharField(min_length=1, max_length=100, validators=[validate_no_control_chars])
    role = serializers.CharField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)

    def update(self, instance, validated_data):
        instance.name = validated_data["name"]
        instance.save(update_fields=["name"])
        return instance


class SessionSerializer(serializers.Serializer):
    public_id = serializers.UUIDField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    last_activity_at = serializers.DateTimeField(read_only=True)
    ip_address = serializers.IPAddressField(read_only=True)
    user_agent = serializers.CharField(read_only=True)
    current = serializers.SerializerMethodField()

    def get_current(self, row) -> bool:
        return row.public_id == self.context.get("current_public_id")


class SecuritySerializer(serializers.Serializer):
    mfa_enabled = serializers.SerializerMethodField()
    mfa_required = serializers.SerializerMethodField()
    recovery_codes_remaining = serializers.SerializerMethodField()

    def get_mfa_enabled(self, user) -> bool:
        return user_mfa_enabled(user)

    def get_mfa_required(self, user) -> bool:
        return mfa_required(user.role)

    def get_recovery_codes_remaining(self, user) -> int:
        return recovery_codes_remaining(user)
