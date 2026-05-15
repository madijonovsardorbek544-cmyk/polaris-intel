from __future__ import annotations

import asyncio
from dataclasses import replace

from fastapi.testclient import TestClient

import src.auth as auth
import src.routes.intelligence as intelligence
from src.config import settings
from src.database import add_watchlist, reset_memory_state, save_alerts, save_items, source_status
from src.main import app
from src.models import Alert, SourceHealth, Watchlist
from src.services.analysis import analyze_item, now_iso


def setup_function() -> None:
    asyncio.run(reset_memory_state())


def _client() -> TestClient:
    return TestClient(app)


def _set_api_key(monkeypatch, value: str) -> None:
    monkeypatch.setattr(auth, "settings", replace(settings, api_key=value))


def test_demo_mode_empty_api_key_allows_write(monkeypatch) -> None:
    _set_api_key(monkeypatch, "")

    async def fake_refresh_store(force: bool = False) -> dict[str, object]:
        return {"ok": True, "status": "TEST", "force": force}

    monkeypatch.setattr(intelligence, "refresh_store", fake_refresh_store)
    c = _client()

    refresh = c.post("/api/refresh")
    assert refresh.status_code == 200
    assert refresh.json()["ok"] is True

    created = c.post("/api/watchlists", json={"name": "Demo writes", "org_id": "demo"})
    assert created.status_code == 201


def test_configured_api_key_protects_writes_and_allows_reads(monkeypatch) -> None:
    _set_api_key(monkeypatch, "secret-key")

    async def fake_refresh_store(force: bool = False) -> dict[str, object]:
        return {"ok": True, "status": "TEST", "force": force}

    monkeypatch.setattr(intelligence, "refresh_store", fake_refresh_store)
    c = _client()

    assert c.get("/api/items").status_code == 200
    assert c.get("/api/watchlists").status_code == 200

    assert c.post("/api/refresh").status_code == 401
    assert c.post("/api/refresh", headers={"X-Polaris-API-Key": "wrong"}).status_code == 401
    assert c.post("/api/refresh", headers={"X-Polaris-API-Key": "secret-key"}).status_code == 200

    assert c.post("/api/watchlists", json={"name": "Blocked", "org_id": "demo"}).status_code == 401
    allowed = c.post(
        "/api/watchlists",
        headers={"X-Polaris-API-Key": "secret-key"},
        json={"name": "Allowed", "org_id": "demo"},
    )
    assert allowed.status_code == 201
    assert allowed.json()["name"] == "Allowed"


def test_alerts_response_separates_persisted_and_generated_preview() -> None:
    async def seed() -> None:
        watchlist = Watchlist(id="wl-preview", name="Preview", org_id="demo", countries=["Ukraine"], sectors=["energy"])
        item = analyze_item(
            "CISA warns CVE-2026-44444 is actively exploited in energy systems",
            "A critical exploit affects energy providers in Ukraine.",
            "https://www.cisa.gov/news-events/alerts/preview",
            [watchlist],
        )
        await save_items([item])
        await save_alerts([
            Alert(
                id="old-alert",
                item_id="old-item",
                title="Old persisted alert",
                risk_level="High",
                matched_watchlist_id="wl-old",
                matched_watchlist_name="Old",
                reason="Existing persisted alert",
                recommended_action="Review.",
                created_at=now_iso(),
                updated_at=now_iso(),
                org_id="demo",
            )
        ])

    asyncio.run(seed())
    response = _client().get("/api/alerts")
    assert response.status_code == 200
    payload = response.json()
    assert payload["total_persisted"] == 1
    assert payload["total_generated_preview"] >= 1
    assert payload["persisted"][0]["id"] == "old-alert"
    assert payload["generated_preview"]


def test_alert_generation_counts_created_and_existing() -> None:
    async def seed() -> None:
        watchlist = Watchlist(id="wl-count", name="Count", org_id="demo", countries=["Ukraine"], sectors=["energy"])
        item = analyze_item(
            "CISA warns CVE-2026-55555 is actively exploited in energy systems",
            "A critical exploit affects energy providers in Ukraine.",
            "https://www.cisa.gov/news-events/alerts/count",
            [watchlist],
        )
        await save_items([item])

    asyncio.run(seed())
    c = _client()
    first = c.post("/api/alerts/generate")
    assert first.status_code == 200
    assert first.json()["created"] == 1
    assert first.json()["existing"] == 0

    second = c.post("/api/alerts/generate")
    assert second.status_code == 200
    assert second.json()["created"] == 0
    assert second.json()["existing"] == 1


def test_org_id_filtering_for_watchlists_alerts_brief_and_items() -> None:
    async def seed() -> None:
        demo = Watchlist(id="wl-demo", name="Demo", org_id="demo", countries=["Ukraine"], sectors=["energy"])
        acme = Watchlist(id="wl-acme", name="Acme", org_id="acme", countries=["USA"], sectors=["healthcare"])
        await add_watchlist(demo)
        await add_watchlist(acme)
        demo_item = analyze_item(
            "CISA warns CVE-2026-10101 is actively exploited in energy systems",
            "A critical exploit affects energy providers in Ukraine.",
            "https://www.cisa.gov/news-events/alerts/demo-org",
            [demo],
        )
        acme_item = analyze_item(
            "CISA warns CVE-2026-20202 is actively exploited in healthcare systems",
            "A critical exploit affects healthcare providers in the USA.",
            "https://www.cisa.gov/news-events/alerts/acme-org",
            [acme],
        )
        await save_items([demo_item, acme_item])
        await save_alerts([*intelligence.alerts_from_items([demo_item, acme_item])])

    asyncio.run(seed())
    c = _client()

    watchlists = c.get("/api/watchlists", params={"org_id": "acme"}).json()
    assert [watchlist["org_id"] for watchlist in watchlists] == ["acme"]

    alerts = c.get("/api/alerts", params={"org_id": "acme"}).json()
    assert alerts["total_persisted"] == 1
    assert alerts["persisted"][0]["org_id"] == "acme"

    items = c.get("/api/items", params={"org_id": "acme"}).json()
    assert items
    assert all(any(match["org_id"] == "acme" for match in item["watchlist_matches"]) for item in items)

    brief = c.get("/api/brief/daily", params={"org_id": "acme"}).json()
    assert len(brief["top_5_risks"]) == 1
    assert brief["top_5_risks"][0]["watchlist_matches"][0]["org_id"] == "acme"


def test_telegram_preview_endpoint(monkeypatch) -> None:
    _set_api_key(monkeypatch, "")

    async def seed() -> None:
        await save_alerts([
            Alert(
                id="telegram-alert",
                item_id="item-telegram",
                title="Critical ransomware activity",
                risk_level="Critical",
                matched_watchlist_id="wl-telegram",
                matched_watchlist_name="Healthcare",
                reason="Sector healthcare matched watchlist Healthcare",
                recommended_action="Escalate to incident response.",
                created_at=now_iso(),
                updated_at=now_iso(),
            )
        ])

    asyncio.run(seed())
    response = _client().post("/api/alerts/telegram-alert/telegram-preview")
    assert response.status_code == 200
    assert "POLARIS Alert" in response.json()["message"]
    assert "Critical ransomware activity" in response.json()["message"]


def test_source_status_uses_datetime_comparison() -> None:
    assert source_status(SourceHealth(source_url="x", last_empty_at="2026-05-15T12:00:00+00:00", last_success_at="2026-05-15T11:00:00+00:00")) == "empty"
    assert source_status(SourceHealth(source_url="x", last_empty_at="2026-05-15T10:00:00+00:00", last_success_at="2026-05-15T11:00:00+00:00")) == "healthy"
    assert source_status(SourceHealth(source_url="x", last_error="TimeoutError")) == "failing"
    assert source_status(SourceHealth(source_url="x")) == "pending"


def test_dashboard_html_smoke(monkeypatch) -> None:
    async def fake_refresh_store(force: bool = False) -> dict[str, object]:
        return {"ok": True, "status": "TEST", "items": 0}

    monkeypatch.setattr("src.main.refresh_store", fake_refresh_store)
    response = _client().get("/")
    assert response.status_code == 200
    html = response.text
    assert "POLARIS" in html
    assert "Daily brief" in html
    assert "Alerts" in html
    assert "Source health" in html
    assert "Admin API key" in html
