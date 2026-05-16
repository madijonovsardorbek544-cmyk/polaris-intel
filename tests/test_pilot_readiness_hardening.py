from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from src.database import add_watchlist, list_item_feedback, list_pilot_leads, reset_memory_state, save_items
from src.main import app
from src.models import Watchlist
from src.services.analysis import analyze_item


VALID_LEAD = {
    "name": "Alex Pilot",
    "organization": "Acme",
    "role": "Security Lead",
    "email": "alex@example.com",
    "country": "USA",
    "organization_type": "energy",
    "problem_description": "Need early warning for Ukraine energy cyber risk.",
    "preferred_contact_method": "email",
}


def setup_function() -> None:
    asyncio.run(reset_memory_state())


def client(host: str = "testclient") -> TestClient:
    return TestClient(app)


def test_lead_rate_limit_blocks_sixth_submission_from_same_ip() -> None:
    c = client("203.0.113.10")
    for idx in range(5):
        payload = {**VALID_LEAD, "email": f"lead{idx}@example.com"}
        assert c.post("/api/leads", json=payload).status_code == 201
    blocked = c.post("/api/leads", json={**VALID_LEAD, "email": "lead6@example.com"})
    assert blocked.status_code == 429


def test_lead_rate_limit_blocks_third_submission_from_same_email() -> None:
    for idx in range(2):
        assert client(f"203.0.113.{idx}").post("/api/leads", json=VALID_LEAD).status_code == 201
    blocked = client("203.0.113.99").post("/api/leads", json=VALID_LEAD)
    assert blocked.status_code == 429


def test_lead_honeypot_does_not_create_real_lead() -> None:
    c = client()
    response = c.post("/api/leads", json={**VALID_LEAD, "website": "https://spam.example"})
    assert response.status_code == 201
    assert "lead_id" not in response.json()
    assert asyncio.run(list_pilot_leads()) == []


def test_normal_lead_submission_still_works() -> None:
    response = client().post("/api/leads", json=VALID_LEAD)
    assert response.status_code == 201
    assert response.json()["lead_id"]
    assert len(asyncio.run(list_pilot_leads())) == 1


def test_feedback_requires_existing_item_and_valid_feedback_still_works() -> None:
    c = client()
    missing = c.post(
        "/api/feedback/item/missing",
        json={"relevance": "useful", "severity_feedback": "accurate", "org_id": "demo", "comment": "no item"},
    )
    assert missing.status_code == 404

    item = analyze_item("CISA warns CVE-2026-10000 exploited", "Critical exploit affects USA energy.", "https://example.com/item", [])
    asyncio.run(save_items([item]))
    valid = c.post(
        f"/api/feedback/item/{item.id}",
        json={"relevance": "useful", "severity_feedback": "accurate", "org_id": "demo", "comment": "good"},
    )
    assert valid.status_code == 201
    assert len(asyncio.run(list_item_feedback())) == 1


def test_rematch_updates_existing_items_and_audit_log() -> None:
    item = analyze_item("Ransomware targets Ukraine energy operators", "Energy operators in Ukraine face ransomware risk.", "https://example.com/risk", [])
    asyncio.run(save_items([item]))
    asyncio.run(add_watchlist(Watchlist(id="wl-rematch", name="Energy", org_id="demo", countries=["Ukraine"], sectors=["energy"])))

    c = client()
    response = c.post("/api/rematch", params={"org_id": "demo"})
    assert response.status_code == 200
    body = response.json()
    assert body["items_checked"] == 1
    assert body["items_matched"] == 1

    updated = c.get(f"/api/items/{item.id}").json()
    assert updated["watchlist_matches"]
    assert "watchlist" in updated["tags"]

    audit = c.get("/api/audit", params={"action": "rematch_run"})
    assert audit.status_code == 200
    assert audit.json()[0]["action"] == "rematch_run"


def test_pilot_readiness_reports_blockers_in_demo_memory() -> None:
    response = client().get("/api/pilot-readiness")
    assert response.status_code == 200
    payload = response.json()
    assert payload["ready_for_real_pilot"] is False
    assert payload["checks"]["database_enabled"] is False
    assert payload["checks"]["demo_memory_warning"] is True


def test_first_pilot_workflow_end_to_end() -> None:
    async def seed_item() -> str:
        item = analyze_item(
            "CISA warns CVE-2026-22222 exploited against Ukraine energy",
            "Critical exploit and ransomware activity affects Ukraine energy operators.",
            "https://example.com/workflow",
            [],
        )
        await save_items([item])
        return item.id

    item_id = asyncio.run(seed_item())
    c = client()

    lead = c.post("/api/leads", json=VALID_LEAD)
    assert lead.status_code == 201

    leads = c.get("/api/leads", headers={"X-Polaris-API-Key": "test-key"})
    assert leads.status_code == 200
    assert leads.json()

    watchlist = c.post(
        "/api/watchlists",
        headers={"X-Polaris-API-Key": "test-key"},
        json={"name": "Pilot Energy", "org_id": "demo", "countries": ["Ukraine"], "sectors": ["energy"], "keywords": ["ransomware"]},
    )
    assert watchlist.status_code == 201

    rematch = c.post("/api/rematch", headers={"X-Polaris-API-Key": "test-key"}, params={"org_id": "demo"})
    assert rematch.status_code == 200
    assert rematch.json()["items_matched"] == 1

    generated = c.post("/api/alerts/generate", headers={"X-Polaris-API-Key": "test-key"}, params={"org_id": "demo"})
    assert generated.status_code == 200
    alert = generated.json()["alerts"][0]

    patched = c.patch(
        f"/api/alerts/{alert['id']}",
        headers={"X-Polaris-API-Key": "test-key"},
        json={"owner": "Alex", "status": "in_progress"},
    )
    assert patched.status_code == 200
    assert patched.json()["owner"] == "Alex"

    report = c.get("/api/reports/customer-proof", headers={"X-Polaris-API-Key": "test-key"}, params={"org_id": "demo"})
    assert report.status_code == 200
    assert report.json()["alerts_generated"] >= 1

    feedback = c.post(
        f"/api/feedback/item/{item_id}",
        headers={"X-Polaris-API-Key": "test-key"},
        json={"relevance": "useful", "severity_feedback": "accurate", "org_id": "demo", "comment": "pilot useful"},
    )
    assert feedback.status_code == 201

    audit = c.get("/api/audit", headers={"X-Polaris-API-Key": "test-key"})
    assert audit.status_code == 200
    actions = {event["action"] for event in audit.json()}
    assert {"watchlist_create", "rematch_run", "alert_generation", "alert_patch", "feedback_creation"}.issubset(actions)
