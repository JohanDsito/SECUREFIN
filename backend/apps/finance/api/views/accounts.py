from __future__ import annotations

import uuid

from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.audit.services import record_event
from apps.finance.api.serializers.accounts import (
    AccountCreateSerializer,
    AccountSerializer,
    RecentTransactionSerializer,
)
from apps.finance.models import DemoAccount
from apps.finance.policies.permissions import FinancePermissionDenied
from apps.finance.services.accounts import InvalidAccountRequest, open_account
from apps.finance.services.dashboard import dashboard_data
from apps.iam.api.permissions import HasRolePermission, IsFullyAuthenticated
from apps.iam.policies.matrix import FINANCE_ACCOUNTS_SELF
from apps.iam.sessions.middleware import client_ip


class DashboardView(APIView):
    required_permission = FINANCE_ACCOUNTS_SELF
    permission_classes = [IsFullyAuthenticated, HasRolePermission(FINANCE_ACCOUNTS_SELF)]

    def get(self, request):
        data = dashboard_data(request.user)
        return Response(
            {
                "balances": data["balances"],
                "accounts": AccountSerializer(data["accounts"], many=True).data,
                "recent_transactions": RecentTransactionSerializer(
                    data["recent_transactions"], many=True
                ).data,
                "unread_notifications": data["unread_notifications"],
            }
        )


class AccountListView(APIView):
    required_permission = FINANCE_ACCOUNTS_SELF
    permission_classes = [IsFullyAuthenticated, HasRolePermission(FINANCE_ACCOUNTS_SELF)]

    def get(self, request):
        accounts = DemoAccount.objects.filter(owner=request.user).order_by("-created_at")
        return Response(AccountSerializer(accounts, many=True).data)

    def post(self, request):
        serializer = AccountCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            account = open_account(
                request.user,
                serializer.validated_data["currency"],
                serializer.validated_data["type"],
            )
        except InvalidAccountRequest as exc:
            raise ValidationError({"detail": str(exc)}) from exc
        except FinancePermissionDenied as exc:
            raise PermissionDenied(str(exc)) from exc
        return Response(AccountSerializer(account).data, status=status.HTTP_201_CREATED)


class AccountDetailView(APIView):
    required_permission = FINANCE_ACCOUNTS_SELF
    permission_classes = [IsFullyAuthenticated, HasRolePermission(FINANCE_ACCOUNTS_SELF)]

    def get(self, request, account_id: str):
        try:
            parsed_id = uuid.UUID(account_id)
        except (ValueError, AttributeError):
            parsed_id = None
        account = (
            DemoAccount.objects.filter(pk=parsed_id, owner=request.user).first()
            if parsed_id is not None
            else None
        )
        if account is None:
            record_event(
                "authz_denied",
                "denied",
                actor=request.user,
                source_ip=client_ip(request),
                metadata={"path": request.path[:200], "method": request.method, "reason": "object"},
            )
            raise NotFound()
        return Response(AccountSerializer(account).data)
