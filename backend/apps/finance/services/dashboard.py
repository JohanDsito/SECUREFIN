from django.db.models import Q, Sum

from apps.finance.services.accounts import ensure_welcome_account
from apps.finance.models import Currency, DemoAccount, FinancialNotification, FinancialTransaction


def dashboard_data(user) -> dict:
    ensure_welcome_account(user)
    accounts = DemoAccount.objects.filter(owner=user).order_by("-created_at")
    balances = {
        currency: (
            accounts.filter(currency=currency).aggregate(total=Sum("available_balance_minor"))["total"]
            or 0
        )
        for currency in Currency.values
    }
    recent_transactions = FinancialTransaction.objects.filter(
        Q(source_account__owner=user) | Q(destination_account__owner=user)
    ).order_by("-created_at")[:10]
    return {
        "balances": balances,
        "accounts": accounts,
        "recent_transactions": recent_transactions,
        "unread_notifications": FinancialNotification.objects.filter(
            recipient=user, read_at__isnull=True
        ).count(),
    }
