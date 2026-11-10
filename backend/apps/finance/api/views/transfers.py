from __future__ import annotations

import uuid

from rest_framework import status
from rest_framework.exceptions import APIException, NotFound, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.finance.api.serializers.transfers import TransferRequestSerializer, TransferSerializer
from apps.finance.models import FinancialTransaction
from apps.finance.services.transfers import (
    IdempotencyConflict,
    TransferAccountNotFound,
    TransferError,
    create_transfer,
    preview_transfer,
)
from apps.iam.api.permissions import HasRolePermission, IsFullyAuthenticated
from apps.iam.policies.matrix import FINANCE_TRANSFERS_CREATE


class TransferConflict(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_code = "transfer_conflict"


class TransferPreviewView(APIView):
    required_permission = FINANCE_TRANSFERS_CREATE
    permission_classes = [IsFullyAuthenticated, HasRolePermission(FINANCE_TRANSFERS_CREATE)]

    def post(self, request):
        serializer = TransferRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            result = preview_transfer(
                request.user,
                data["source_account_id"],
                data["destination_account_id"],
                data["amount_minor"],
                data["currency"],
                data["description"],
            )
        except TransferAccountNotFound as exc:
            raise NotFound() from exc
        except TransferError as exc:
            raise TransferConflict(detail={"detail": str(exc)}) from exc
        return Response(result)


class TransferCreateView(APIView):
    required_permission = FINANCE_TRANSFERS_CREATE
    permission_classes = [IsFullyAuthenticated, HasRolePermission(FINANCE_TRANSFERS_CREATE)]

    def post(self, request):
        serializer = TransferRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            key = str(uuid.UUID(request.headers.get("Idempotency-Key", "")))
        except (ValueError, AttributeError) as exc:
            raise ValidationError(
                {"Idempotency-Key": ["Se requiere un UUID válido para la idempotencia."]}
            ) from exc

        data = serializer.validated_data
        try:
            result = create_transfer(
                request.user,
                data["source_account_id"],
                data["destination_account_id"],
                data["amount_minor"],
                data["currency"],
                data["description"],
                key,
            )
        except TransferAccountNotFound as exc:
            raise NotFound() from exc
        except IdempotencyConflict as exc:
            raise TransferConflict(detail={"detail": str(exc)}) from exc
        except TransferError as exc:
            raise TransferConflict(detail={"detail": str(exc)}) from exc
        response_status = (
            status.HTTP_202_ACCEPTED
            if result.status == "pending_approval"
            else status.HTTP_201_CREATED
        )
        return Response(TransferSerializer(result).data, status=response_status)


class TransferDetailView(APIView):
    required_permission = FINANCE_TRANSFERS_CREATE
    permission_classes = [IsFullyAuthenticated, HasRolePermission(FINANCE_TRANSFERS_CREATE)]

    def get(self, request, transaction_id: str):
        try:
            parsed_id = uuid.UUID(transaction_id)
        except ValueError:
            parsed_id = None
        transaction = (
            FinancialTransaction.objects.filter(pk=parsed_id, creator=request.user).first()
            if parsed_id is not None
            else None
        )
        if transaction is None:
            raise NotFound()
        return Response(TransferSerializer(transaction).data)
