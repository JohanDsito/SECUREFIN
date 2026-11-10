from rest_framework import serializers

from apps.finance.models import Currency
from apps.iam.api.serializers.auth import StrictSerializer


class TransferRequestSerializer(StrictSerializer):
    source_account_id = serializers.UUIDField()
    destination_account_id = serializers.UUIDField()
    amount_minor = serializers.IntegerField(min_value=1)
    currency = serializers.ChoiceField(choices=Currency.choices)
    description = serializers.CharField(max_length=140, allow_blank=True, required=False, default="")


class TransferSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    correlation_id = serializers.UUIDField()
    kind = serializers.CharField()
    status = serializers.CharField()
    amount_minor = serializers.IntegerField()
    currency = serializers.CharField()
    description = serializers.CharField()
    approval_count_required = serializers.IntegerField()
    rejection_reason = serializers.CharField()
    created_at = serializers.DateTimeField()
    resolved_at = serializers.DateTimeField(allow_null=True)


class TransactionListSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    kind = serializers.CharField()
    status = serializers.CharField()
    amount_minor = serializers.IntegerField()
    currency = serializers.CharField()
    description = serializers.CharField()
    source_account = serializers.SerializerMethodField()
    destination_account = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField()

    def get_source_account(self, transaction):
        account = transaction.source_account
        return None if account is None or account.is_system else account.masked_number

    def get_destination_account(self, transaction):
        account = transaction.destination_account
        return None if account is None or account.is_system else account.masked_number
