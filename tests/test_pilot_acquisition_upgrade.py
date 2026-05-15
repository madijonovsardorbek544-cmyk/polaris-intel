from __future__ import annotations

import asyncio
from dataclasses import replace

from fastapi.testclient import TestClient

import src.auth as auth
from src.config import settings
from src.database import add_watchlist, reset_memory_state, save_alerts, save_items
from src.main import app
from src.models import Alert, Watchlist
from src.scoring import source_reliability_tier, source_type
from src.services.analysis import analyze_item, now_iso


VALID_LEAD = {
    "name": "Aida Risk",
    "organization": "Central School",
    "role": "Operations",
    "email": "aida@example.org",
    "country": "Kazakhstan",
    "organization_type": "school",
    "problem_description": "We need risk monitoring.",
    "preferred_contact_method": "email",
}


def setup_function() -> None:
    asyncio.run(reset_memory_state())


def client() -> TestClient:
    return TestClient(app)


def set_key(monkeypatch, value: str = "pilot-secret") -> None:
    monkeypatch.setattr(auth, "settings", replace(settings, api_key=value))


def test_lead_api_safe_response_status_filter_metrics_and_patch(monkeypatch) -> None:
    set_key(monkeypatch)
    c = client()
    response = c.post("/api/leads", json=VALID_LEAD)
    assert response.status_code == 201
    body = response.json()
    assert body["ok"] is True
    assert body["message"] == "Pilot request received."
    assert "lead_id" in body
    assert "email" not in body

    assert c.post("/api/leads", json={**VALID_LEAD, "email": "bad"}).status_code in {400, 422}
    missing = dict(VALID_LEAD)
    missing.pop("problem_description")
    assert c.post("/api/leads", json=missing).status_code in {400, 422}
    assert c.get("/api/leads").status_code == 401

    headers = {"X-Polaris-API-Key": "pilot-secret"}
    leads = c.get("/api/leads?status=new&limit=50", headers=headers)
    assert leads.status_code == 200
    assert leads.json()[0]["email"] == VALID_LEAD["email"]

    patched = c.patch(f"/api/leads/{body['lead_id']}", json={"status": "qualified"}, headers=headers)
    assert patched.status_code == 200
    assert patched.json()["status"] == "qualified"

    metrics = c.get("/api/public-metrics", headers=headers)
    assert metrics.status_code == 200
    assert metrics.json()["pilot_form_submissions"] == 1


def test_demo_security_and_dashboard_acquisition_controls(monkeypatch) -> None:
    async def fake_refresh_store(force: bool = False) -> dict[str, object]:
        return {"ok": True, "status": "TEST", "items": 0}

    monkeypatch.setattr("src.main.refresh_store", fake_refresh_store)
    c = client()
    demo = c.get("/demo")
    assert demo.status_code == 200
    assert "document.createElement" in demo.text
    assert "safeHttpUrl" in demo.text
    assert "textContent = item.summary" in demo.text
    assert "innerHTML=items.map" not in demo.text
    assert "Sample watchlist templates" in demo.text

    dashboard = c.get("/dashboard")
    assert dashboard.status_code == 200
    html = dashboard.text
    assert "Pilot leads" in html and "/api/leads" in html
    assert "First pilot setup" in html
    assert "Customer proof report" in html
    assert "Useful" in html and "False positive" in html and "Severity too high" in html
    assert "Lead access blocked: invalid or missing API key." in html
    assert "No pilot requests yet." in html
    assert "copyProof" in html and "exportProofText" in html


def test_customer_proof_source_reliability_and_feedback(monkeypatch) -> None:
    set_key(monkeypatch)
    now = now_iso()

    async def seed() -> str:
        wl = Watchlist(id="wl-proof", name="Energy USA", org_id="demo", countries=["USA"], sectors=["energy"], created_at=now)
        await add_watchlist(wl)
        item = analyze_item(
            "CISA warns CVE-2026-55555 is actively exploited in energy systems",
            "A critical exploit affects energy organizations in the USA.",
            "https://www.cisa.gov/news-events/alerts/proof",
            [wl],
        )
        await save_items([item])
        await save_alerts([Alert(id="alert-proof", item_id=item.id, title=item.title, risk_level="High", matched_watchlist_id=wl.id, matched_watchlist_name=wl.name, reason="matched", recommended_action=item.recommended_action, created_at=now, updated_at=now, org_id="demo")])
        return item.id

    item_id = asyncio.run(seed())
    c = client()
    headers = {"X-Polaris-API-Key": "pilot-secret"}

    assert source_reliability_tier("https://www.cisa.gov/news-events/alerts/x") == "High"
    assert source_type("https://www.cisa.gov/news-events/alerts/x") == "official"
    item = c.get(f"/api/items/{item_id}").json()
    assert item["source_reliability"] == "High"
    assert item["source_type"] == "official"
    assert item["evidence_links"]
    assert item["evidence_summary"]
    assert any("Official source reliability +20" in factor for factor in item["confidence_factors"])

    proof = c.get("/api/reports/customer-proof?org_id=demo&days=7")
    assert proof.status_code == 200
    assert "POLARIS monitored" in proof.json()["proof_summary"]
    assert proof.json()["alerts_generated"] == 1

    feedback = c.post(f"/api/feedback/item/{item_id}", headers=headers, json={"relevance": "useful", "severity_feedback": "accurate", "comment": "Good", "org_id": "demo"})
    assert feedback.status_code == 201
    assert "pilot-secret" not in str(feedback.json())
    assert c.get("/api/feedback").status_code == 401
    listed = c.get("/api/feedback", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["item_id"] == item_id
