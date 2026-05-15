from src.database import deduplicate_items
from src.models import Watchlist
from src.services.analysis import analyze_item, watchlist_relevance


def test_watchlist_relevance_matches_countries_sectors_keywords_cves_and_actor() -> None:
    watchlist = Watchlist(
        id="wl-1",
        name="Priority",
        countries=["Ukraine"],
        sectors=["energy"],
        organizations=["Acme Bank"],
        keywords=["sanction"],
        cves=["CVE-2026-33333"],
        threat_actors=["Example Spider"],
    )
    item = analyze_item(
        "Example Spider uses CVE-2026-33333 against energy providers",
        "The campaign affects Ukraine and mentions possible sanction retaliation.",
        "https://example.com/item",
        [watchlist],
    )
    assert watchlist_relevance(item.title, item.summary, item.entities, [watchlist]) is True
    assert "watchlist" in item.tags


def test_deduplication_keeps_first_title_source_pair() -> None:
    first = analyze_item("Same title", "First summary", "https://example.com/a")
    second = analyze_item("Same title", "Second summary", "https://example.com/a")
    third = analyze_item("Different title", "Third summary", "https://example.com/a")
    assert deduplicate_items([first, second, third]) == [first, third]
