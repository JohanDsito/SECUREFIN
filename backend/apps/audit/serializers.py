"""Serializers de la consulta de auditoría (T106; contrato §5).

Los filtros llegan por la query string y se validan con lista permitida: cualquier parámetro no
declarado da 400. La salida expone solo los campos del contrato; los metadatos ya se guardan con
lista permitida y sin secretos (record_event).
"""

from __future__ import annotations

from rest_framework import serializers

from apps.audit.models import EVENT_TYPES, Outcome
from apps.audit.queries import SUMMARY_WINDOWS
from apps.iam.api.serializers.auth import StrictSerializer


class EventQuerySerializer(StrictSerializer):
    event_type = serializers.ChoiceField(choices=EVENT_TYPES, required=False)
    outcome = serializers.ChoiceField(choices=Outcome.choices, required=False)
    actor_id = serializers.UUIDField(required=False)
    page = serializers.IntegerField(min_value=1, max_value=100000, required=False, default=1)

    def get_fields(self):
        # `from` es palabra reservada de Python: se declara aquí.
        fields = super().get_fields()
        fields["from"] = serializers.DateTimeField(required=False)
        fields["to"] = serializers.DateTimeField(required=False)
        return fields


class SummaryQuerySerializer(StrictSerializer):
    minutes = serializers.ChoiceField(choices=SUMMARY_WINDOWS, required=False, default=15)


class SecurityEventSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    occurred_at = serializers.DateTimeField()
    event_type = serializers.CharField()
    outcome = serializers.CharField()
    actor_id = serializers.UUIDField(allow_null=True)
    actor_role = serializers.CharField(allow_null=True)
    target_type = serializers.CharField(allow_null=True)
    target_id = serializers.UUIDField(allow_null=True)
    source_ip = serializers.CharField(allow_null=True)
    request_id = serializers.UUIDField()
    metadata = serializers.JSONField()
