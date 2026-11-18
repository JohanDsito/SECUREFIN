"""Consultas de solo lectura sobre los eventos de seguridad (T106; US6; contrato §5).

Las usa el panel de monitoreo del Auditor. Nada aquí modifica eventos: la tabla es append-only y el
rol `securefin_app` no tiene UPDATE ni DELETE sobre ella.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.db.models.functions import TruncMinute

from apps.audit.models import Outcome, SecurityEvent
from apps.core import clock

PAGE_SIZE = 50
SUMMARY_WINDOWS = (5, 15, 60)  # minutos
TOP_SOURCES = 5


def page_events(
    *,
    event_type: str | None = None,
    outcome: str | None = None,
    actor_id=None,
    start: datetime | None = None,
    end: datetime | None = None,
    page: int = 1,
):
    """Página de eventos filtrados, del más reciente al más antiguo."""
    qs = SecurityEvent.objects.order_by("-occurred_at", "-id")
    if event_type:
        qs = qs.filter(event_type=event_type)
    if outcome:
        qs = qs.filter(outcome=outcome)
    if actor_id:
        qs = qs.filter(actor_id=actor_id)
    if start:
        qs = qs.filter(occurred_at__gte=start)
    if end:
        qs = qs.filter(occurred_at__lt=end)
    return Paginator(qs, PAGE_SIZE).get_page(page)


def _bucket_minutes(window: int) -> int:
    return 1 if window <= 15 else 5


def summary(window: int) -> dict:
    """Recuentos de la ventana: por tipo, por resultado, línea de tiempo y orígenes con más fallos."""
    now = clock.now()
    since = now - timedelta(minutes=window)
    events = SecurityEvent.objects.filter(occurred_at__gte=since).order_by()

    by_type = {
        row["event_type"]: row["n"]
        for row in events.values("event_type").annotate(n=Count("id"))
    }
    by_outcome = {value: 0 for value in Outcome.values}
    for row in events.values("outcome").annotate(n=Count("id")):
        by_outcome[row["outcome"]] = row["n"]

    # Línea de tiempo: cubetas de 1 min (ventanas cortas) o 5 min (60 min), rellenas con ceros.
    step = _bucket_minutes(window)
    start = since.replace(second=0, microsecond=0)
    start -= timedelta(minutes=start.minute % step)
    buckets: dict[datetime, dict[str, int]] = {}
    cursor = start
    while cursor <= now:
        buckets[cursor] = {value: 0 for value in Outcome.values}
        cursor += timedelta(minutes=step)
    rows = (
        events.annotate(minute=TruncMinute("occurred_at"))
        .values("minute")
        .annotate(
            success=Count("id", filter=Q(outcome=Outcome.SUCCESS)),
            failure=Count("id", filter=Q(outcome=Outcome.FAILURE)),
            denied=Count("id", filter=Q(outcome=Outcome.DENIED)),
        )
    )
    for row in rows:
        minute = row["minute"]
        key = minute - timedelta(minutes=minute.minute % step)
        bucket = buckets.setdefault(key, {value: 0 for value in Outcome.values})
        for value in Outcome.values:
            bucket[value] += row[value]

    top_sources = list(
        events.exclude(outcome=Outcome.SUCCESS)
        .exclude(source_ip__isnull=True)
        .values("source_ip")
        .annotate(n=Count("id"))
        .order_by("-n", "source_ip")[:TOP_SOURCES]
    )

    return {
        "window_minutes": window,
        "bucket_minutes": step,
        "generated_at": now,
        "total": sum(by_outcome.values()),
        "by_outcome": by_outcome,
        "by_type": by_type,
        "timeline": [{"start": key, **counts} for key, counts in sorted(buckets.items())],
        "top_sources": [{"source_ip": row["source_ip"], "count": row["n"]} for row in top_sources],
    }
