from rest_framework import serializers

from apps.finance.models import AccountStatus, AccountType, Currency, DemoAccount
from apps.iam.api.serializers.auth import StrictSerializer


class AccountCreateSerializer(StrictSerializer):
    type = serializers.ChoiceField(
        choices=[
            (AccountType.CHECKING, AccountType.CHECKING.label),
            (AccountType.SAVINGS, AccountType.SAVINGS.label),
        ]
    )
    currency = serializers.ChoiceField(choices=Currency.choices)


class AccountSerializer(serializers.ModelSerializer):
    type = serializers.CharField(source="account_type", read_only=True)
    available_balance_minor = serializers.IntegerField(read_only=True)
    status = serializers.ChoiceField(choices=AccountStatus.choices, read_only=True)

    class Meta:
        model = DemoAccount
        fields = (
            "id",
            "masked_number",
            "type",
            "currency",
            "available_balance_minor",
            "status",
            "created_at",
        )
        read_only_fields = fields


class RecentTransactionSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    kind = serializers.CharField()
    status = serializers.CharField()
    amount_minor = serializers.IntegerField()
    currency = serializers.CharField()
    description = serializers.CharField()
    created_at = serializers.DateTimeField()
