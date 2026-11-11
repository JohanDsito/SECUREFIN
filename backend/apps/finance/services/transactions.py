from django.core.paginator import Paginator
from django.db.models import Q

from apps.finance.models import DemoAccount, FinancialTransaction


def transactions_page(user, *, filters: dict, page: int, per_page: int = 20):
    account_ids = DemoAccount.objects.filter(owner=user).values("id")
    queryset = (
        FinancialTransaction.objects.filter(
            Q(source_account_id__in=account_ids) | Q(destination_account_id__in=account_ids)
        )
        .select_related("source_account", "destination_account")
        .order_by("-created_at")
    )
    for field in ("status", "kind", "currency"):
        if filters.get(field):
            queryset = queryset.filter(**{field: filters[field]})
    if filters.get("from"):
        queryset = queryset.filter(created_at__gte=filters["from"])
    if filters.get("to"):
        queryset = queryset.filter(created_at__lte=filters["to"])
    if filters.get("account_id"):
        if filters["account_id"] not in DemoAccount.objects.filter(owner=user).values_list("id", flat=True):
            queryset = queryset.none()
        else:
            queryset = queryset.filter(
                Q(source_account_id=filters["account_id"])
                | Q(destination_account_id=filters["account_id"])
            )
    paginator = Paginator(queryset, per_page)
    page_obj = paginator.get_page(page)
    return {
        "count": paginator.count,
        "page": page_obj.number,
        "pages": paginator.num_pages,
        "results": list(page_obj.object_list),
    }
