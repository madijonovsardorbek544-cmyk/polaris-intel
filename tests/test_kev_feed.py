from __future__ import annotations

import json
from datetime import date, timedelta

from src.feeds import parse_feed
from src.models import Watchlist
from src.services.analysis import analyze_item

TODAY = date.today()
CATALOG = json.dumps({"vulnerabilities": [
    {"cveID": "CVE-2026-1111", "vendorProject": "Fortinet", "product": "FortiOS", "vulnerabilityName": "Fortinet FortiOS Heap Overflow",
     "dateAdded": TODAY.isoformat(), "shortDescription": "Allows remote code execution.", "requiredAction": "Apply vendor updates.",
     "dueDate": (TODAY + timedelta(days=21)).isoformat(), "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2019-0001", "vendorProject": "Old", "product": "Thing", "dateAdded": (TODAY - timedelta(days=400)).isoformat()},
]})


def test_kev_catalog_keeps_only_recent_additions() -> None:
    entries = parse_feed(CATALOG, "https://www.cisa.gov/kev.json")
    assert [e["title"] for e in entries] == ["Actively exploited: CVE-2026-1111 in Fortinet FortiOS"]
    assert "ransomware" in entries[0]["summary"]
    assert entries[0]["source_url"].startswith("https://www.cisa.gov/")


def test_kev_entry_matches_customer_tech_stack_watchlist_as_high_risk() -> None:
    entry = parse_feed(CATALOG, "https://www.cisa.gov/kev.json")[0]
    watchlist = Watchlist(id="w1", name="Our stack", org_id="bank", keywords=["FortiOS"])
    item = analyze_item(entry["title"], entry["summary"], entry["source_url"], [watchlist], entry["created_at"], {})
    assert item.watchlist_matches and item.watchlist_matches[0].org_id == "bank"
    assert "CVE-2026-1111" in item.entities["cves"]
    assert item.risk_level in {"High", "Critical"}


def test_escalation_terms_match_whole_words_only() -> None:
    from src.scoring import _escalation_hits

    assert _escalation_hits("new malware warns software firmware users") == []
    assert _escalation_hits("missile strikes near the border; war escalation") == ["missile", "strike", "border", "war", "escalation"]
