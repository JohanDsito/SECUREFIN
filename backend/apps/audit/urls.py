"""Rutas de auditoría (contrato §5). Montadas en /api/v1/audit/."""

from django.urls import path

from apps.audit.views import AuditEventsView, AuditEventTypesView, AuditSummaryView

urlpatterns = [
    path("events", AuditEventsView.as_view(), name="audit-events"),
    path("event-types", AuditEventTypesView.as_view(), name="audit-event-types"),
    path("summary", AuditSummaryView.as_view(), name="audit-summary"),
]
