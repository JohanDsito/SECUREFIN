from __future__ import annotations

import uuid

from django.db.models import Count, Q
from rest_framework import status
from rest_framework.exceptions import APIException, NotFound
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.finance.api.serializers.admin import ApprovalQueueSerializer, ApprovalReasonSerializer
from apps.finance.models import FinancialTransaction, TransactionKind, TransactionStatus
from apps.finance.services.approvals import ApprovalError, ApprovalNotFound, decide_transfer
from apps.iam.api.permissions import HasRolePermission, IsFullyAuthenticated
from apps.iam.policies.matrix import FINANCE_ADMIN_READ, FINANCE_APPROVALS_DECIDE


class FinanceAdminConflict(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_code = "finance_admin_conflict"


class ApprovalQueueView(APIView):
    required_permission = FINANCE_ADMIN_READ
    permission_classes = [IsFullyAuthenticated, HasRolePermission(FINANCE_ADMIN_READ)]

    def get(self, request):
        pending = (
            FinancialTransaction.objects.filter(
                kind=TransactionKind.TRANSFER,
                status=TransactionStatus.PENDING_APPROVAL,
            )
            .select_related("source_account", "destination_account", "creator")
            .annotate(
                approvals_received=Count(
                    "decisions", filter=Q(decisions__decision="approved")
                )
            )
            .order_by("created_at")
        )
        return Response(ApprovalQueueSerializer(pending, many=True).data)


class ApprovalDecisionView(APIView):
    required_permission = FINANCE_APPROVALS_DECIDE
    permission_classes = [IsFullyAuthenticated, HasRolePermission(FINANCE_APPROVALS_DECIDE)]

    def post(self, request, transaction_id: str, decision: str):
        if decision not in ("approve", "reject"):
            raise NotFound()
        try:
            parsed_id = uuid.UUID(transaction_id)
        except ValueError as exc:
            raise NotFound() from exc
        serializer = ApprovalReasonSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        decision_value = "approved" if decision == "approve" else "rejected"
        try:
            result = decide_transfer(
                request.user,
                parsed_id,
                decision_value,
                serializer.validated_data["reason"],
            )
        except ApprovalNotFound as exc:
            raise NotFound() from exc
        except ApprovalError as exc:
            raise FinanceAdminConflict(detail={"detail": str(exc)}) from exc
        response_status = (
            status.HTTP_202_ACCEPTED
            if result.status == TransactionStatus.PENDING_APPROVAL
            else status.HTTP_200_OK
        )
        return Response(
            {
                "id": str(result.pk),
                "status": result.status,
                "approval_count_required": result.approval_count_required,
                "rejection_reason": result.rejection_reason,
            },
            status=response_status,
        )
