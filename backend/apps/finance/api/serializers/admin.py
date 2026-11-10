from rest_framework import serializers
from django.db.models import Count, Q

from apps.finance.models import FinancialTransaction
from apps.iam.api.serializers.auth import StrictSerializer


class ApprovalReasonSerializer(StrictSerializer):
    reason = serializers.CharField(max_length=240, allow_blank=True, required=False, default="")


class ApprovalQueueSerializer(serializers.ModelSerializer):
    source_account = serializers.CharField(source="source_account.masked_number", read_only=True)
    destination_account = serializers.CharField(
        source="destination_account.masked_number", read_only=True
    )
    creator_email = serializers.EmailField(source="creator.email", read_only=True)
    approvals_received = serializers.IntegerField(read_only=True)

    class Meta:
        model = FinancialTransaction
        fields = (
            "id",
            "correlation_id",
            "creator_email",
            "source_account",
            "destination_account",
            "amount_minor",
            "currency",
            "description",
            "status",
            "approval_count_required",
            "approvals_received",
            "created_at",
        )
