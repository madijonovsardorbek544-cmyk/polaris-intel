from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from src.database import reset_memory_state, save_items
from src.main import app
from src.models import Alert
from src.services.analysis import analyze_item
from src.services.briefing import format_alert_for_telegram


def setup_function() -> None:
    asyncio.run(reset_memory_state())


def client() -> TestClient:
    return TestClient(app)


def test_core_read_endpoints_with_isolated_memory() -> None:
    c = client()
    assert c.get("/health").status_code == 200
    assert c.get("/api/items").status_code == 200
    assert c.get("/api/sources").status_code == 200
    assert c.get("/api/alerts").status_code == 200
    assert c.get("/api/brief/daily").status_code == 200


def test_watchlist_crud_endpoints_with_demo_writes() -> None:
    c = client()
    created = c.post(
        "/api/watchlists",
        json={"name": "Pilot Org", "org_id": "demo", "countries": ["Ukraine"], "sectors": ["energy"]},
    )
    assert created.status_code == 201
    watchlist = created.json()
    assert watchlist["org_id"] == "demo"

    detail = c.get(f"/api/watchlists/{watchlist['id']}")
    assert detail.status_code == 200
    assert detail.json()["name"] == "Pilot Org"

    updated = c.put(
        f"/api/watchlists/{watchlist['id']}",
        json={"name": "Updated Pilot Org", "org_id": "acme", "countries": ["USA"], "keywords": ["ransomware"]},
    )
    assert updated.status_code == 200
    assert updated.json()["org_id"] == "acme"
    assert updated.json()["name"] == "Updated Pilot Org"

    deleted = c.delete(f"/api/watchlists/{watchlist['id']}")
    assert deleted.status_code == 204
    assert c.get(f"/api/watchlists/{watchlist['id']}").status_code == 404


def test_alert_generation_detail_and_patch_endpoints() -> None:
    async def seed_item() -> None:
        from src.models import Watchlist

        watchlist = Watchlist(id="wl-api", name="API Energy", org_id="demo", countries=["Ukraine"], sectors=["energy"])
        item = analyze_item(
            "CISA warns CVE-2026-77777 is actively exploited in energy systems",
            "A critical exploit affects energy providers in Ukraine.",
            "https://www.cisa.gov/news-events/alerts/api-alert",
            [watchlist],
        )
        await save_items([item])

    asyncio.run(seed_item())
    c = client()

    generated_preview = c.get("/api/alerts")
    assert generated_preview.status_code == 200
    assert generated_preview.json()

    persisted = c.post("/api/alerts/generate")
    assert persisted.status_code == 200
    alert = persisted.json()["alerts"][0]
    assert alert["org_id"] == "demo"

    detail = c.get(f"/api/alerts/{alert['id']}")
    assert detail.status_code == 200
    assert detail.json()["id"] == alert["id"]

    patched = c.patch(f"/api/alerts/{alert['id']}", json={"status": "acknowledged", "notes": "Owner notified"})
    assert patched.status_code == 200
    assert patched.json()["status"] == "acknowledged"
    assert patched.json()["notes"] == "Owner notified"


def test_telegram_alert_formatter() -> None:
    alert = Alert(
        id="a1",
        item_id="item-1",
        title="Critical ransomware activity",
        risk_level="Critical",
        matched_watchlist_id="wl-1",
        matched_watchlist_name="Healthcare",
        reason="Sector healthcare matched watchlist Healthcare",
        recommended_action="Escalate to incident response.",
        created_at="2026-05-15T00:00:00+00:00",
        updated_at="2026-05-15T00:00:00+00:00",
    )

    message = format_alert_for_telegram(alert)

    assert "Critical" in message
    assert "Critical ransomware activity" in message
    assert "Healthcare" in message
    assert "Sector healthcare" in message
    assert "Escalate to incident response" in message
    assert "item-1" in message
