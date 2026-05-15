from __future__ import annotations

import asyncio
from dataclasses import replace

from fastapi.testclient import TestClient

import src.auth as auth
import src.routes.intelligence as intelligence
from src.config import settings
from src.database import add_source_config, add_watchlist, put_org_profile, reset_memory_state, save_alerts, save_items
from src.main import app
from src.models import Alert, OrgScoringProfile, SourceConfig, Watchlist
from src.services.analysis import analyze_item, now_iso
from src.services.ingestion import FeedFetchResult


def setup_function() -> None:
    asyncio.run(reset_memory_state())


def client() -> TestClient:
    return TestClient(app)


def test_full_sensitive_read_protection_coverage(monkeypatch) -> None:
    monkeypatch.setattr(auth, "settings", replace(settings, api_key="read-secret", protect_reads=True))
    c = client()
    now = now_iso()

    async def seed() -> None:
        item = analyze_item("CISA warns CVE-2026-99999 exploited", "Critical exploit in USA energy.", "https://example.com/a", [])
        await save_items([item])
        await save_alerts([Alert(id="a1", item_id=item.id, title=item.title, risk_level="High", matched_watchlist_id="wl", matched_watchlist_name="WL", reason="reason", recommended_action="act", created_at=now, updated_at=now)])

    asyncio.run(seed())
    protected = ["/api/latest", f"/api/items/{(c.get('/api/latest', headers={'X-Polaris-API-Key':'read-secret'}).json()[0]['id'])}", "/api/alerts/flat", "/api/alerts/a1", "/api/stats", "/api/summary"]
    for path in protected:
        assert c.get(path).status_code == 401
        assert c.get(path, headers={"X-Polaris-API-Key": "read-secret"}).status_code == 200
    assert c.get("/health").status_code == 200


def test_alert_ownership_update_and_events() -> None:
    now = now_iso()
    asyncio.run(save_alerts([Alert(id="a1", item_id="i1", title="Alert", risk_level="High", matched_watchlist_id="wl", matched_watchlist_name="WL", reason="reason", recommended_action="act", created_at=now, updated_at=now)]))
    c = client()
    res = c.patch("/api/alerts/a1", json={"status": "in_progress", "owner": "Alex", "due_at": "2026-05-20", "severity_override": "Critical", "resolution_summary": "Containment started", "notes": "Customer notified"})
    assert res.status_code == 200
    payload = res.json()
    assert payload["owner"] == "Alex"
    assert payload["status"] == "in_progress"
    events = c.get("/api/alerts/a1/events").json()
    assert {event["event_type"] for event in events} >= {"status_changed", "owner_changed", "notes_updated", "resolution_updated", "severity_override_changed"}


def test_onboarding_value_report_and_csv_exports() -> None:
    async def seed() -> None:
        wl = Watchlist(id="wl1", name="Energy", org_id="demo", countries=["Ukraine"], sectors=["energy"])
        await add_watchlist(wl)
        item = analyze_item("CISA warns CVE-2026-11111 exploited in energy", "Critical exploit affects Ukraine energy.", "https://example.com/item", [wl])
        await save_items([item])
        await save_alerts(intelligence.alerts_from_items([item]))

    asyncio.run(seed())
    c = client()
    templates = c.get("/api/onboarding/template").json()["templates"]
    assert {"school", "NGO", "logistics", "bank", "energy", "telecom", "government"}.issubset(templates.keys())
    report = c.get("/api/reports/value", params={"org_id": "demo", "days": 7}).json()
    assert report["total_items_monitored"] == 1
    assert report["total_alerts"] == 1
    assert c.get("/api/export/alerts.csv", params={"org_id": "demo"}).headers["content-type"].startswith("text/csv")
    assert c.get("/api/export/value-report.csv", params={"org_id": "demo"}).headers["content-type"].startswith("text/csv")


def test_source_config_crud_and_refresh_uses_enabled_configs(monkeypatch) -> None:
    c = client()
    created = c.post("/api/source-configs", json={"url": "https://example.com/rss", "label": "Example", "category": "custom", "enabled": True})
    assert created.status_code == 201
    source_id = created.json()["id"]
    assert c.get("/api/source-configs").json()[0]["url"] == "https://example.com/rss"
    assert c.patch(f"/api/source-configs/{source_id}", json={"enabled": False}).json()["enabled"] is False
    assert c.delete(f"/api/source-configs/{source_id}").status_code == 204

    async def seed_enabled() -> None:
        await add_source_config(SourceConfig(id="s1", url="https://enabled.example/rss", label="Enabled", enabled=True, created_at=now_iso()))

    asyncio.run(seed_enabled())
    seen: list[str] = []

    async def fake_fetch(client_obj, feed_url: str):
        seen.append(feed_url)
        return FeedFetchResult(feed_url=feed_url, items=[], ok=True, error=None, empty=True)

    monkeypatch.setattr("src.services.ingestion.fetch_feed_result", fake_fetch)
    c.post("/api/refresh")
    assert seen == ["https://enabled.example/rss"]


def test_org_scoring_profile_adjusts_risk_factors() -> None:
    wl = Watchlist(id="wl1", name="Energy", org_id="acme", countries=["Ukraine"], sectors=["energy"])
    profile = OrgScoringProfile(org_id="acme", high_priority_countries=["Ukraine"], high_priority_sectors=["energy"], risk_boost_keywords=["critical"], risk_reduce_keywords=["exercise"])
    item = analyze_item("Critical energy exercise in Ukraine", "Energy operators run an exercise in Ukraine.", "https://example.com/profile", [wl], org_profiles={"acme": profile})
    assert any("Org profile" in factor for factor in item.risk_factors)


def test_dashboard_contains_new_workflow_controls(monkeypatch) -> None:
    async def fake_refresh_store(force: bool = False) -> dict[str, object]:
        return {"ok": True, "status": "TEST", "items": 0}

    monkeypatch.setattr("src.main.refresh_store", fake_refresh_store)
    html = client().get("/").text
    for expected in ["Create from template", "Value report", "Source config", "Send Telegram", "No items exist", "Action: Add API key"]:
        assert expected in html


def test_telegram_send_missing_config_and_mocked_success(monkeypatch) -> None:
    now = now_iso()
    asyncio.run(save_alerts([Alert(id="tg1", item_id="i1", title="Telegram", risk_level="High", matched_watchlist_id="wl", matched_watchlist_name="WL", reason="reason", recommended_action="act", created_at=now, updated_at=now)]))
    c = client()
    missing_settings = replace(settings, telegram_bot_token="", telegram_chat_id="")
    monkeypatch.setattr(intelligence, "settings", missing_settings)
    assert c.post("/api/alerts/tg1/telegram-send").status_code == 400

    calls: list[dict[str, object]] = []

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

    class FakeAsyncClient:
        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def post(self, url: str, **kwargs: object) -> FakeResponse:
            calls.append({"url": url, **kwargs})
            return FakeResponse()

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(intelligence, "settings", replace(settings, telegram_bot_token="token", telegram_chat_id="chat"))
    sent = c.post("/api/alerts/tg1/telegram-send")
    assert sent.status_code == 200
    assert calls and "token" in calls[0]["url"]
    events = c.get("/api/alerts/tg1/events").json()
    assert {event["event_type"] for event in events} >= {"telegram_failed", "telegram_sent"}
