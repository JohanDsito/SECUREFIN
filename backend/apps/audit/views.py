"""Consulta de auditoría para el Auditor (T106; US6; contrato §5).

Solo lectura y solo para el rol con `audit.read` (el Auditor) con sesión `full` y MFA verificado.
El Administrador no la tiene: quien administra no audita sus propias acciones (segregación).
Cualquier otro método da 405.
"""

from __future__ import annotations

from rest_framework.response import Response
from rest_framework.views import APIView

from apps.audit import queries
from apps.audit.models import EVENT_TYPES
from apps.audit.serializers import EventQuerySerializer, SecurityEventSerializer, SummaryQuerySerializer
from apps.iam.api.permissions import HasRolePermission, IsFullyAuthenticated
from apps.iam.policies.matrix import AUDIT_READ


class _AuditView(APIView):
    required_permission = AUDIT_READ
    permission_classes = [IsFullyAuthenticated, HasRolePermission(AUDIT_READ)]


class AuditEventsView(_AuditView):
    """GET /audit/events: filtros `from`, `to`, `event_type`, `outcome`, `actor_id` y `page`."""

    def get(self, request):
        query = EventQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        data = query.validated_data
        page = queries.page_events(
            event_type=data.get("event_type"),
            outcome=data.get("outcome"),
            actor_id=data.get("actor_id"),
            start=data.get("from"),
            end=data.get("to"),
            page=data.get("page", 1),
        )
        return Response(
            {
                "count": page.paginator.count,
                "page": page.number,
                "pages": page.paginator.num_pages,
                "next": page.next_page_number() if page.has_next() else None,
                "previous": page.previous_page_number() if page.has_previous() else None,
                "results": SecurityEventSerializer(page.object_list, many=True).data,
            }
        )


class AuditEventTypesView(_AuditView):
    """GET /audit/event-types: catálogo cerrado de tipos de evento."""

    def get(self, request):
        return Response(list(EVENT_TYPES))


class AuditSummaryView(_AuditView):
    """GET /audit/summary?minutes=5|15|60: recuentos para el panel de monitoreo en vivo."""

    def get(self, request):
        query = SummaryQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        return Response(queries.summary(query.validated_data.get("minutes", 15)))
