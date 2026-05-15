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
    assert len(first.json()["created_alerts"]) == 1

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
    response = _client().get("/dashboard")
    assert response.status_code == 200
    html = response.text
    assert "POLARIS" in html
    assert "Daily brief" in html
    assert "Alerts" in html
    assert "Source health" in html
    assert "Admin API key" in html
    assert "No org-specific matches yet" in html
    assert "Switch to Global Intelligence" in html
    assert 'downloadCsv(exportUrl("/api/export/alerts.csv")' in html
    assert 'fetch(url, { headers: adminHeaders(), cache: "no-store" })' in html
    assert "window.location" not in html


def test_dashboard_single_org_controls_exist(monkeypatch) -> None:
    async def fake_refresh_store(force: bool = False) -> dict[str, object]:
        return {"ok": True, "status": "TEST", "items": 0}

    monkeypatch.setattr("src.main.refresh_store", fake_refresh_store)
    response = _client().get("/dashboard")
    assert response.status_code == 200
    html = response.text
    assert "Active org_id" in html
    assert "polarisActiveOrg" in html
    assert "POLARIS Public Demo" in html
    assert "Global Intelligence" in html
    assert "Org Watchlist" in html
    assert "polarisViewMode" in html
    assert "currentViewMode()" in html
    assert 'scopedUrl("/api/items")' in html
    assert 'state.viewMode === "org" ? `${base}?${orgQuery()}` : base' in html
    assert 'safeJsonFetch(scopedUrl("/api/items")' in html
    assert "safeJsonFetch(`/api/watchlists?${orgQuery()}`" in html


def test_dashboard_watchlist_edit_alert_generation_and_telegram_controls(monkeypatch) -> None:
    async def fake_refresh_store(force: bool = False) -> dict[str, object]:
        return {"ok": True, "status": "TEST", "items": 0}

    monkeypatch.setattr("src.main.refresh_store", fake_refresh_store)
    html = _client().get("/dashboard").text
    assert "data-watchlist-edit" in html
    assert "Save watchlist" in html
    assert "Generate persistent alerts" in html
    assert "Created ${payload.created || 0} alerts, ${payload.existing || 0} already existed." in html
    assert "Preview — not persisted" in html
    assert "Telegram preview" in html
    assert "telegram-preview" in html


def test_optional_read_protection_requires_key_when_enabled(monkeypatch) -> None:
    protected = replace(settings, api_key="read-secret", protect_reads=True)
    monkeypatch.setattr(auth, "settings", protected)
    c = _client()

    for path in ["/api/items", "/api/alerts", "/api/brief/daily", "/api/sources", "/api/watchlists"]:
        assert c.get(path).status_code == 401
        assert c.get(path, headers={"X-Polaris-API-Key": "read-secret"}).status_code == 200
    assert c.get("/health").status_code == 200



def test_public_demo_stats_reports_global_and_org_counts(monkeypatch) -> None:
    _set_api_key(monkeypatch, "")

    async def seed() -> None:
        demo = Watchlist(id="wl-stats", name="Stats", org_id="demo", countries=["Ukraine"], sectors=["energy"])
        await add_watchlist(demo)
        item = analyze_item(
            "CISA warns CVE-2026-30303 is actively exploited in energy systems",
            "A critical exploit affects energy providers in Ukraine.",
            "https://www.cisa.gov/news-events/alerts/public-demo-stats",
            [demo],
        )
        await save_items([item])
        await save_alerts([*intelligence.alerts_from_items([item])])

    asyncio.run(seed())
    response = _client().get("/api/public-demo-stats", params={"org_id": "demo"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["global_items"] > 0
    for key in ["global_items", "org_items", "org_watchlists", "sources", "last_status"]:
        assert key in payload
    assert payload["org_items"] == 1
    assert payload["org_watchlists"] == 1


def test_public_demo_stats_respects_read_protection(monkeypatch) -> None:
    protected = replace(settings, api_key="read-secret", protect_reads=True)
    monkeypatch.setattr(auth, "settings", protected)
    c = _client()

    assert c.get("/api/public-demo-stats").status_code == 401
    assert c.get("/api/public-demo-stats", headers={"X-Polaris-API-Key": "read-secret"}).status_code == 200


def test_head_routes_return_200() -> None:
    c = _client()
    assert c.head("/").status_code == 200
    assert c.head("/health").status_code == 200


def test_read_endpoints_remain_public_by_default(monkeypatch) -> None:
    monkeypatch.setattr(auth, "settings", replace(settings, api_key="write-secret", protect_reads=False))
    c = _client()
    for path in ["/api/items", "/api/alerts", "/api/brief/daily", "/api/sources", "/api/watchlists"]:
        assert c.get(path).status_code == 200


def test_default_org_applies_to_omitted_watchlist_org(monkeypatch) -> None:
    custom = replace(settings, default_org="pilot-org")
    monkeypatch.setattr("src.routes.watchlists.settings", custom)
    monkeypatch.setattr("src.schemas.settings", custom)

    response = _client().post("/api/watchlists", json={"name": "Default org watchlist"})

    assert response.status_code == 201
    assert response.json()["org_id"] == "pilot-org"


def test_save_alerts_with_counts_does_not_count_old_alerts() -> None:
    async def run() -> tuple[int, int, int, int]:
        from src.database import save_alerts_with_counts

        existing = Alert(
            id="existing-alert",
            item_id="old-item",
            title="Old",
            risk_level="High",
            matched_watchlist_id="wl-old",
            matched_watchlist_name="Old",
            reason="old reason",
            recommended_action="Review.",
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        await save_alerts([existing])
        first = Alert(
            id="new-alert",
            item_id="new-item",
            title="New",
            risk_level="Critical",
            matched_watchlist_id="wl-new",
            matched_watchlist_name="New",
            reason="new reason",
            recommended_action="Escalate.",
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        result = await save_alerts_with_counts([first])
        duplicate = await save_alerts_with_counts([first])
        return result.created_count, result.existing_count, len(result.all_alerts), duplicate.existing_count

    created_count, existing_count, total_count, duplicate_existing = asyncio.run(run())
    assert created_count == 1
    assert existing_count == 0
    assert total_count == 2
    assert duplicate_existing == 1


def test_demo_reset_endpoint_only_in_demo_mode(monkeypatch) -> None:
    monkeypatch.setattr("src.database.settings", replace(settings, database_url=""))
    monkeypatch.setattr("src.routes.intelligence.settings", replace(settings, database_url=""))
    c = _client()
    created = c.post("/api/watchlists", json={"name": "Reset me", "org_id": "demo"})
    assert created.status_code == 201
    reset = c.post("/api/demo/reset")
    assert reset.status_code == 200
    assert c.get("/api/watchlists").json() == []


def test_demo_reset_returns_400_in_database_mode(monkeypatch) -> None:
    monkeypatch.setattr("src.database.settings", replace(settings, database_url="postgresql://example/db"))
    response = _client().post("/api/demo/reset")
    assert response.status_code == 400
    assert response.json()["detail"] == "Demo reset is disabled in database mode."
