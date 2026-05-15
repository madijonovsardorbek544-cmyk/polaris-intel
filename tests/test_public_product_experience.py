from __future__ import annotations

import asyncio
from dataclasses import replace

from fastapi.testclient import TestClient

import src.auth as auth
import src.routes.intelligence as intelligence
from src.config import settings
from src.database import get_public_metrics, reset_memory_state
from src.main import app


def setup_function() -> None:
    asyncio.run(reset_memory_state())


def _client() -> TestClient:
    return TestClient(app)


def _set_api_key(monkeypatch, value: str) -> None:
    monkeypatch.setattr(auth, "settings", replace(settings, api_key=value))


VALID_LEAD = {
    "name": "Aida Risk",
    "organization": "Central School",
    "role": "Operations",
    "email": "aida@example.org",
    "country": "Kazakhstan",
    "organization_type": "school",
    "problem_description": "We need to understand cyber and disruption risks without a security department.",
    "preferred_contact_method": "email",
}


def test_public_routes_and_dashboard_split(monkeypatch) -> None:
    async def fake_refresh_store(force: bool = False) -> dict[str, object]:
        return {"ok": True, "status": "TEST", "items": 0, "force": force}

    monkeypatch.setattr("src.main.refresh_store", fake_refresh_store)
    c = _client()

    home = c.get("/")
    assert home.status_code == 200
    assert "Cyber-geopolitical risk intelligence for teams without a security department." in home.text
    assert "Open Live Demo" in home.text
    assert "Request Pilot" in home.text
    assert "Admin API key" not in home.text

    demo = c.get("/demo")
    assert demo.status_code == 200
    assert "Global Intelligence" in demo.text
    assert "Admin API key" not in demo.text
    assert "Create" not in demo.text
    assert "Export alerts CSV" not in demo.text

    dashboard = c.get("/dashboard")
    assert dashboard.status_code == 200
    assert "Operator dashboard. Write actions require API key." in dashboard.text
    assert "Admin API key" in dashboard.text
    assert "Create" in dashboard.text
    assert "Export alerts CSV" in dashboard.text
    assert "Pilot leads" in dashboard.text

    request = c.get("/request-pilot")
    assert request.status_code == 200
    assert "Request a POLARIS pilot" in request.text


def test_lead_api_validation_and_protection(monkeypatch) -> None:
    _set_api_key(monkeypatch, "lead-secret")
    c = _client()

    created = c.post("/api/leads", json=VALID_LEAD)
    assert created.status_code == 201
    payload = created.json()
    assert payload["ok"] is True
    assert payload["message"] == "Pilot request received."
    assert "email" not in payload

    bad_email = {**VALID_LEAD, "email": "not-an-email"}
    assert c.post("/api/leads", json=bad_email).status_code in {400, 422}

    missing_required = {**VALID_LEAD}
    missing_required.pop("problem_description")
    assert c.post("/api/leads", json=missing_required).status_code in {400, 422}

    assert c.get("/api/leads").status_code == 401
    protected = c.get("/api/leads", headers={"X-Polaris-API-Key": "lead-secret"})
    assert protected.status_code == 200
    assert protected.json()[0]["name"] == VALID_LEAD["name"]

    lead_id = payload["lead_id"]
    patched = c.patch(
        f"/api/leads/{lead_id}",
        headers={"X-Polaris-API-Key": "lead-secret"},
        json={"status": "qualified"},
    )
    assert patched.status_code == 200
    assert patched.json()["status"] == "qualified"


def test_public_metrics_increment_and_protection(monkeypatch) -> None:
    _set_api_key(monkeypatch, "metrics-secret")

    async def fake_refresh_store(force: bool = False) -> dict[str, object]:
        return {"ok": True, "status": "TEST", "items": 0, "force": force}

    monkeypatch.setattr("src.main.refresh_store", fake_refresh_store)
    c = _client()

    assert c.get("/").status_code == 200
    assert c.get("/demo").status_code == 200
    assert c.post("/api/leads", json=VALID_LEAD).status_code == 201

    assert c.get("/api/public-metrics").status_code == 401
    metrics = c.get("/api/public-metrics", headers={"X-Polaris-API-Key": "metrics-secret"})
    assert metrics.status_code == 200
    assert metrics.json()["landing_page_views"] == 1
    assert metrics.json()["demo_page_views"] == 1
    assert metrics.json()["pilot_form_submissions"] == 1


def test_health_and_head_routes_still_work() -> None:
    c = _client()
    assert c.get("/health").status_code == 200
    assert c.head("/").status_code == 200
    assert c.head("/health").status_code == 200
