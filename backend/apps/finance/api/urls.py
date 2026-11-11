from django.urls import path

from apps.finance.api.views.accounts import AccountDetailView, AccountListView, DashboardView
from apps.finance.api.views.transactions import TransactionListView
from apps.finance.api.views.transfers import TransferCreateView, TransferDetailView, TransferPreviewView

urlpatterns = [
    path("dashboard", DashboardView.as_view(), name="finance-dashboard"),
    path("accounts", AccountListView.as_view(), name="finance-accounts"),
    path("accounts/<str:account_id>", AccountDetailView.as_view(), name="finance-account-detail"),
    path("transactions", TransactionListView.as_view(), name="finance-transactions"),
    path("transfers/preview", TransferPreviewView.as_view(), name="finance-transfer-preview"),
    path("transfers", TransferCreateView.as_view(), name="finance-transfer-create"),
    path(
        "transfers/<str:transaction_id>",
        TransferDetailView.as_view(),
        name="finance-transfer-detail",
    ),
]
