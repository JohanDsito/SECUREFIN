from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.finance.api.serializers.transfers import TransactionListSerializer
from apps.finance.models import Currency, TransactionKind, TransactionStatus
from apps.finance.services.transactions import transactions_page
from apps.iam.api.permissions import HasRolePermission, IsFullyAuthenticated
from apps.iam.policies.matrix import FINANCE_TRANSACTIONS_READ


class TransactionFilterSerializer(serializers.Serializer):
    from_date = serializers.DateTimeField(required=False)
    to_date = serializers.DateTimeField(required=False)
    status = serializers.ChoiceField(choices=TransactionStatus.choices, required=False)
    kind = serializers.ChoiceField(choices=TransactionKind.choices, required=False)
    currency = serializers.ChoiceField(choices=Currency.choices, required=False)
    account_id = serializers.UUIDField(required=False)
    page = serializers.IntegerField(min_value=1, max_value=100_000, default=1)


class TransactionListView(APIView):
    required_permission = FINANCE_TRANSACTIONS_READ
    permission_classes = [IsFullyAuthenticated, HasRolePermission(FINANCE_TRANSACTIONS_READ)]

    def get(self, request):
        allowed_params = {
            "from",
            "to",
            "status",
            "kind",
            "currency",
            "account_id",
            "page",
        }
        unknown = set(request.query_params) - allowed_params
        if unknown:
            raise ValidationError({field: ["Parámetro no permitido."] for field in sorted(unknown)})
        raw_filters = {"page": request.query_params.get("page", 1)}
        for field in ("status", "kind", "currency", "account_id"):
            if field in request.query_params:
                raw_filters[field] = request.query_params[field]
        if "from" in request.query_params:
            raw_filters["from_date"] = request.query_params["from"]
        if "to" in request.query_params:
            raw_filters["to_date"] = request.query_params["to"]
        serializer = TransactionFilterSerializer(data=raw_filters)
        serializer.is_valid(raise_exception=True)
        filters = {
            "from": serializer.validated_data.get("from_date"),
            "to": serializer.validated_data.get("to_date"),
            "status": serializer.validated_data.get("status"),
            "kind": serializer.validated_data.get("kind"),
            "currency": serializer.validated_data.get("currency"),
            "account_id": serializer.validated_data.get("account_id"),
        }
        if filters["from"] and filters["to"] and filters["from"] > filters["to"]:
            raise ValidationError({"to": ["La fecha final debe ser posterior a la fecha inicial."]})
        result = transactions_page(
            request.user, filters=filters, page=serializer.validated_data["page"]
        )
        return Response(
            {
                "count": result["count"],
                "page": result["page"],
                "pages": result["pages"],
                "results": TransactionListSerializer(result["results"], many=True).data,
            }
        )
