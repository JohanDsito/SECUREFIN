from django.urls import include, path

urlpatterns = [
    path("api/v1/", include("apps.iam.api.urls")),
    path("api/v1/finance/", include("apps.finance.api.urls")),
    path("api/v1/admin/finance/", include("apps.finance.api.admin_urls")),
    path("api/v1/audit/", include("apps.audit.urls")),
]
