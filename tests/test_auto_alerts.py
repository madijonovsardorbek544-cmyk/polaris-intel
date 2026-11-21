from __future__ import annotations

import asyncio
from dataclasses import replace

import httpx

from src.config import settings
from src.database import list_alert_events, list_alerts, reset_memory_state
from src.models import Watchlist
from src.services import briefing
from src.services.analysis import analyze_item


def _items():
    watchlist = Watchlist(id="w1", name="Our stack", org_id="bank", keywords=["FortiOS"])
    critical = analyze_item("Actively exploited: CVE-2026-1111 in Fortinet FortiOS", "Remote code execution used by ransomware.", "https://www.cisa.gov/kev?q=1", [watchlist])
    unrelated = analyze_item("Actively exploited: CVE-2026-2222 in Other Product", "Remote code execution.", "https://www.cisa.gov/kev?q=2", [watchlist])
    return critical, unrelated


def test_auto_alert_persists_new_alerts_and_pushes_critical_once(monkeypatch) -> None:
    asyncio.run(reset_memory_state())
    sent: list[str] = []

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

    class FakeAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, **kwargs):
            sent.append(kwargs["json"]["text"])
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(briefing, "settings", replace(settings, telegram_bot_token="t", telegram_chat_id="c"))
    critical, unrelated = _items()
    assert critical.risk_level == "Critical"

    created = asyncio.run(briefing.auto_alert([critical, unrelated]))
    assert [a.org_id for a in created] == ["bank"]
    assert len(asyncio.run(list_alerts())) == 1
    assert len(sent) == 1 and "FortiOS" in sent[0]
    assert [e.event_type for e in asyncio.run(list_alert_events(created[0].id))] == ["telegram_sent"]

    assert asyncio.run(briefing.auto_alert([critical])) == []
    assert len(sent) == 1


def test_auto_alert_can_be_disabled(monkeypatch) -> None:
    asyncio.run(reset_memory_state())
    monkeypatch.setenv("POLARIS_AUTO_ALERTS", "false")
    assert asyncio.run(briefing.auto_alert(list(_items()))) == []
    assert asyncio.run(list_alerts()) == []
