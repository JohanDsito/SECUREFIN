"""TS-S18 (T103) y contrato §5 (T104, parcial): consulta de auditoría solo para el Auditor.

- Administrador y Cliente → 403 en /audit/events, /audit/event-types y /audit/summary.
- PUT, PATCH y DELETE → 405 (solo lectura).
- Filtros con lista permitida: un parámetro desconocido o un valor fuera del catálogo → 400.
"""

import pytest

from apps.audit.models import EVENT_TYPES

pytestmark = pytest.mark.security

ROUTES = ("/audit/events", "/audit/event-types", "/audit/summary")


@pytest.mark.parametrize("role", ["admin", "client"])
@pytest.mark.parametrize("route", ROUTES)
def test_only_auditor_reads_audit(login_as, role, route):
    client, _ = login_as(role)
    response = client.get(route)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


@pytest.mark.parametrize("route", ROUTES)
def test_audit_is_read_only(login_as, route):
    client, _ = login_as("auditor")
    for method in ("put", "patch", "delete"):
        assert client._send(method, route, None if method == "delete" else {}).status_code == 405


def test_auditor_lists_events_newest_first(login_as):
    client, auditor = login_as("auditor")
    response = client.get("/audit/events")
    assert response.status_code == 200
    body = response.json()
    assert {"count", "page", "pages", "next", "previous", "results"} <= body.keys()
    assert body["results"], "el propio inicio de sesión del Auditor debe estar auditado"
    first = body["results"][0]
    assert set(first) == {
        "id", "occurred_at", "event_type", "outcome", "actor_id", "actor_role",
        "target_type", "target_id", "source_ip", "request_id", "metadata",
    }
    times = [e["occurred_at"] for e in body["results"]]
    assert times == sorted(times, reverse=True)


def test_events_filter_by_outcome_and_type(login_as, api_factory):
    client, _ = login_as("auditor")
    attacker = api_factory(ip="198.51.100.77")
    attacker.post("/auth/login", {"email": "nadie@lab.securefin.local", "password": "x" * 16})

    failures = client.get("/audit/events?outcome=failure&event_type=login_failed").json()["results"]
    assert failures
    assert all(e["event_type"] == "login_failed" and e["outcome"] == "failure" for e in failures)


@pytest.mark.parametrize(
    "query",
    ["?event_type=no_existe", "?outcome=maybe", "?actor_id=no-es-uuid", "?page=0", "?inventado=1", "?from=ayer"],
)
def test_events_reject_invalid_filters(login_as, query):
    client, _ = login_as("auditor")
    response = client.get(f"/audit/events{query}")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "validation_error"


def test_event_types_is_the_closed_catalog(login_as):
    client, _ = login_as("auditor")
    assert client.get("/audit/event-types").json() == list(EVENT_TYPES)


def test_summary_counts_the_window(login_as, api_factory):
    client, _ = login_as("auditor")
    attacker = api_factory(ip="198.51.100.88")
    attacker.post("/auth/login", {"email": "nadie@lab.securefin.local", "password": "x" * 16})

    response = client.get("/audit/summary?minutes=5")
    assert response.status_code == 200
    body = response.json()
    assert body["window_minutes"] == 5
    assert body["by_type"].get("login_failed", 0) >= 1
    assert body["by_type"].get("login_succeeded", 0) >= 1
    assert body["total"] == sum(body["by_outcome"].values())
    assert sum(b["success"] + b["failure"] + b["denied"] for b in body["timeline"]) == body["total"]
    assert {"source_ip": "198.51.100.88", "count": 1} in body["top_sources"]


def test_summary_rejects_unknown_window(login_as):
    client, _ = login_as("auditor")
    assert client.get("/audit/summary?minutes=7").status_code == 400
