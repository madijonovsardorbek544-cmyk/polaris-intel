from __future__ import annotations

import asyncio
import logging

from src.database import add_watchlist, list_source_health, reset_memory_state, save_items, update_watchlist
from src.models import Watchlist
from src.services.analysis import analyze_item, now_iso
from src.services.briefing import daily_brief, generate_alerts_from_items
from src.services.ingestion import fetch_feed


class FailingClient:
    async def get(self, *args, **kwargs):
        raise TimeoutError("network timeout")


def test_source_failure_logging_behavior(caplog) -> None:
    async def run() -> None:
        await reset_memory_state()
        with caplog.at_level(logging.WARNING):
            result = await fetch_feed(FailingClient(), "https://example.com/feed.xml")
        assert result.ok is False
        assert "Feed fetch failed" in caplog.text
        assert "https://example.com/feed.xml" in caplog.text
        assert "TimeoutError" in caplog.text
        sources = await list_source_health()
        assert sources[0].failure_count == 1
        assert "network timeout" in sources[0].last_error

    asyncio.run(run())


def test_risk_and_confidence_factors_generation() -> None:
    item = analyze_item(
        "CISA warns CVE-2026-12345 is actively exploited by ransomware",
        "A zero-day remote code execution exploit targets energy organizations in Ukraine with malware activity.",
        "https://www.cisa.gov/news-events/alerts/example",
    )

    assert any("CISA source reliability +22" in factor for factor in item.risk_factors)
    assert any("CVE detected" in factor for factor in item.risk_factors)
    assert any("Active exploitation language +20" in factor for factor in item.risk_factors)
    assert any("High-impact sector: energy +10" in factor for factor in item.risk_factors)
    assert any("Extracted entities" in factor for factor in item.confidence_factors)
    assert any("Matching risk signals" in factor for factor in item.confidence_factors)


def test_alert_generation_requires_high_or_critical_watchlist_match() -> None:
    watchlist = Watchlist(id="wl-1", name="Ukraine Energy", countries=["Ukraine"], sectors=["energy"], created_at=now_iso())
    item = analyze_item(
        "CVE-2026-99999 actively exploited against Ukraine energy operators",
        "Critical exploit and ransomware activity affects energy infrastructure in Ukraine.",
        "https://www.cisa.gov/news-events/alerts/example",
        [watchlist],
    )

    alerts = generate_alerts_from_items([item])

    assert len(alerts) == 1
    assert alerts[0].matched_watchlist == "Ukraine Energy"
    assert "country: Ukraine" in alerts[0].reason


def test_daily_brief_generation() -> None:
    async def run() -> None:
        await reset_memory_state()
        watchlist = Watchlist(id="wl-1", name="Ukraine Energy", countries=["Ukraine"], sectors=["energy"], created_at=now_iso())
        item = analyze_item(
            "CVE-2026-99999 actively exploited against Ukraine energy operators",
            "Critical exploit and ransomware activity affects energy infrastructure in Ukraine.",
            "https://www.cisa.gov/news-events/alerts/example",
            [watchlist],
        )
        await save_items([item])
        brief = await daily_brief()
        assert brief["headline_summary"].startswith("1 Critical/High")
        assert brief["countries_affected"] == ["Ukraine"]
        assert "energy" in brief["sectors_affected"]
        assert len(brief["top_5_risks"]) == 1
        assert brief["recommended_actions"]

    asyncio.run(run())


def test_watchlist_update_in_memory() -> None:
    async def run() -> None:
        await reset_memory_state()
        created = Watchlist(id="wl-1", name="Original", countries=["Ukraine"], created_at=now_iso(), updated_at=now_iso())
        await add_watchlist(created)
        updated = Watchlist(id="wl-1", name="Updated", countries=["Kazakhstan"], sectors=["energy"], created_at=created.created_at, updated_at=now_iso())
        saved = await update_watchlist("wl-1", updated)
        assert saved is not None
        assert saved.name == "Updated"
        assert saved.countries == ["Kazakhstan"]
        assert saved.sectors == ["energy"]

    asyncio.run(run())
