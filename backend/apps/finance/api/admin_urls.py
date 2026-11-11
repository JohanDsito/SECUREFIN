from django.urls import path

from apps.finance.api.views.admin import ApprovalDecisionView, ApprovalQueueView

urlpatterns = [
    path("approvals", ApprovalQueueView.as_view(), name="finance-admin-approvals"),
    path(
        "transfers/<str:transaction_id>/<str:decision>",
        ApprovalDecisionView.as_view(),
        name="finance-admin-transfer-decision",
    ),
]
