from apps.audit.services import record_event


def record_finance_event(
    event_type: str,
    outcome: str,
    *,
    actor=None,
    target_type: str | None = None,
    target_id=None,
    source_ip: str | None = None,
    metadata: dict | None = None,
):
    if not event_type.startswith("finance_"):
        raise ValueError("Solo se pueden registrar eventos financieros desde este servicio.")
    return record_event(
        event_type,
        outcome,
        actor=actor,
        target_type=target_type,
        target_id=target_id,
        source_ip=source_ip,
        metadata=metadata,
    )
