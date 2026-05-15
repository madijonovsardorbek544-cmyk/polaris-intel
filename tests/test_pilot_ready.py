from __future__ import annotations

import asyncio
import importlib
import logging
from pathlib import Path

import pytest
from src.database import add_watchlist, delete_watchlist
from src.models import Watchlist
from src.services.briefing import generate_alerts, generate_daily_brief
from src.services.analysis import analyze_item, now_iso
from src.services.ingestion import fetch_feed


def test_dotenv_loading_reads_local_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".env").write_text("PORT=8765\nMAX_ITEMS=7\nFEEDS=https://example.com/rss.xml\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("MAX_ITEMS", raising=False)
    monkeypatch.delenv("FEEDS", raising=False)

    import src.config as config

    reloaded = importlib.reload(config)
    assert reloaded.settings.port == 8765
    assert reloaded.settings.max_items == 7
    assert reloaded.settings.feeds == ["https://example.com/rss.xml"]
    importlib.reload(config)


def test_source_failure_logging_behavior(caplog: pytest.LogCaptureFixture) -> None:
    class BrokenClient:
        async def get(self, *_args: object, **_kwargs: object) -> object:
            raise TimeoutError("network timeout")

    caplog.set_level(logging.WARNING)
    items = asyncio.run(fetch_feed(BrokenClient(), "https://bad.example/feed.xml"))  # type: ignore[arg-type]

    assert items == []
    assert "Feed fetch failed" in caplog.text
    assert "https://bad.example/feed.xml" in caplog.text
    assert "TimeoutError" in caplog.text
    assert "network timeout" in caplog.text


def test_risk_and_confidence_factors_generation() -> None:
    item = analyze_item(
        "CISA warns CVE-2026-22222 is actively exploited",
        "A critical remote code execution exploit targets government and energy networks in Ukraine.",
        "https://www.cisa.gov/news-events/alerts/example",
    )
    assert any("CISA" in factor and "+8" in factor for factor in item.risk_factors)
    assert any("CVE detected" in factor for factor in item.risk_factors)
    assert any("Active exploitation language +20" == factor for factor in item.risk_factors)
    assert any("High-impact sector" in factor for factor in item.risk_factors)
    assert any("Official source reliability +20" in factor for factor in item.confidence_factors)
    assert any("Structured entities detected" in factor for factor in item.confidence_factors)


def test_alert_generation_from_high_watchlist_matches() -> None:
    watchlist = Watchlist(id="wl-alert", name="Energy Ukraine", countries=["Ukraine"], sectors=["energy"])
    item = analyze_item(
        "CVE-2026-99999 actively exploited against energy providers",
        "A critical exploit affects energy organizations in Ukraine.",
        "https://www.cisa.gov/news-events/alerts/example-alert",
        [watchlist],
    )

    alerts = generate_alerts([item])

    assert alerts
    assert alerts[0]["item_id"] == item.id
    assert alerts[0]["risk_level"] in {"Critical", "High"}
    assert alerts[0]["matched_watchlist"] == "Energy Ukraine"
    assert "matched watchlist" in str(alerts[0]["reason"])


def test_daily_brief_generation() -> None:
    watchlist = Watchlist(id="wl-brief", name="Brief Watch", countries=["Ukraine"], sectors=["energy"], created_at=now_iso())
    item = analyze_item(
        "CISA warns CVE-2026-12345 is actively exploited in energy systems",
        "A critical remote code execution vulnerability affects energy organizations in Ukraine.",
        "https://www.cisa.gov/news-events/alerts/brief",
        [watchlist],
    )
    payload = generate_daily_brief([item], [])
    assert "headline_summary" in payload
    assert len(payload["top_5_risks"]) == 1
    assert payload["countries_affected"][0][0] == "Ukraine"
    assert payload["sectors_affected"][0][0] == "energy"
    assert payload["recommended_actions"]


def test_watchlist_update_and_detail() -> None:
    async def setup() -> str:
        watchlist = Watchlist(id="wl-update", name="Original", countries=["USA"], created_at=now_iso())
        await add_watchlist(watchlist)
        return watchlist.id

    watchlist_id = asyncio.run(setup())
    async def update_and_read() -> tuple[Watchlist | None, Watchlist | None]:
        from src.database import get_watchlist, update_watchlist

        before = await get_watchlist(watchlist_id)
        saved = await update_watchlist(
            watchlist_id,
            Watchlist(id=watchlist_id, name="Updated", countries=["Ukraine"], sectors=["energy"], created_at=before.created_at if before else now_iso()),
        )
        after = await get_watchlist(watchlist_id)
        return saved, after

    saved, after = asyncio.run(update_and_read())

    assert saved is not None
    assert saved.name == "Updated"
    assert after is not None
    assert after.countries == ["Ukraine"]

    asyncio.run(delete_watchlist(watchlist_id))


def test_empty_feed_tracks_empty_status_separately() -> None:
    from src.database import list_source_health, reset_memory_state
    from src.services.ingestion import fetch_feed_result

    class EmptyResponse:
        text = "<rss><channel></channel></rss>"

        def raise_for_status(self) -> None:
            return None

    class EmptyClient:
        async def get(self, *_args: object, **_kwargs: object) -> object:
            return EmptyResponse()

    async def run() -> tuple[object, object]:
        await reset_memory_state()
        result = await fetch_feed_result(EmptyClient(), "https://empty.example/rss.xml")  # type: ignore[arg-type]
        health = [source for source in await list_source_health() if source.source_url == "https://empty.example/rss.xml"][0]
        return result, health

    result, health = asyncio.run(run())

    assert result.ok is True
    assert result.empty is True
    assert health.status == "empty"
    assert health.empty_count == 1
    assert health.total_failure_count == 0
    assert health.consecutive_failure_count == 0
