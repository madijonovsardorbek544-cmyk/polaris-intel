from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import feedparser
from sqlmodel import Session, func, select

from app.models import FeedSource, IntelItem


DEFAULT_SOURCES = [
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "category": "cyber"},
    {"name": "The Record", "url": "https://therecord.media/feed", "category": "cyber"},
    {"name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "category": "cyber"},
    {"name": "CSIS Publications", "url": "https://www.csis.org/feeds/publication_feed", "category": "geopolitics"},
]

KEYWORD_WEIGHTS = {
    "ransomware": 35,
    "wiper": 35,
    "supply chain": 28,
    "zero-day": 30,
    "critical": 20,
    "iran": 12,
    "china": 12,
    "russia": 12,
    "botnet": 20,
    "ddos": 16,
    "breach": 18,
    "espionage": 25,
    "sanctions": 14,
    "election": 14,
    "disinformation": 22,
}


def ensure_default_sources(session: Session) -> None:
    existing = {row.url for row in session.exec(select(FeedSource)).all()}
    for source in DEFAULT_SOURCES:
        if source["url"] not in existing:
            session.add(FeedSource(**source))
    session.commit()


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is not None:
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except Exception:
        return datetime.now(timezone.utc).replace(tzinfo=None)


def score_item(title: str, summary: str, category: str) -> tuple[int, str, str]:
    text = f"{title} {summary}".lower()
    score = 35 if category == "geopolitics" else 45
    tags: list[str] = []

    for phrase, weight in KEYWORD_WEIGHTS.items():
        if phrase in text:
            score += weight
            tags.append(phrase)

    score = max(0, min(100, score))
    if score >= 80:
        severity = "critical"
    elif score >= 65:
        severity = "high"
    elif score >= 45:
        severity = "medium"
    else:
        severity = "low"

    return score, severity, ", ".join(sorted(set(tags)))


def ingest_feed(session: Session, source: FeedSource) -> dict:
    parsed = feedparser.parse(source.url)
    created = 0

    for entry in parsed.entries[:25]:
        link = getattr(entry, "link", None)
        title = getattr(entry, "title", "Untitled")
        summary = getattr(entry, "summary", "")
        if not link:
            continue

        exists = session.exec(select(IntelItem).where(IntelItem.link == link)).first()
        if exists:
            continue

        risk_score, severity, tags = score_item(title, summary, source.category)
        item = IntelItem(
            source_name=source.name,
            title=title,
            link=link,
            summary=summary[:5000],
            category=source.category,
            published_at=_parse_datetime(getattr(entry, "published", None)),
            severity=severity,
            risk_score=risk_score,
            tags=tags,
        )
        session.add(item)
        created += 1

    source.last_checked_at = datetime.utcnow()
    session.add(source)
    session.commit()
    return {"source": source.name, "created": created, "entries_seen": len(parsed.entries)}


def ingest_all_sources(session: Session) -> dict:
    ensure_default_sources(session)
    sources = session.exec(select(FeedSource).where(FeedSource.enabled == True)).all()
    results = [ingest_feed(session, source) for source in sources]
    return {
        "sources": len(sources),
        "created": sum(result["created"] for result in results),
        "results": results,
    }


def ingest_source_by_id(session: Session, source_id: int) -> dict | None:
    source = session.get(FeedSource, source_id)
    if not source:
        return None
    return ingest_feed(session, source)


def make_dashboard_summary(session: Session) -> dict:
    items = session.exec(select(IntelItem)).all()
    total_items = len(items)
    high_priority = len([item for item in items if item.risk_score >= 65])
    critical_items = len([item for item in items if item.risk_score >= 80])
    cyber_items = len([item for item in items if item.category == "cyber"])
    geo_items = len([item for item in items if item.category == "geopolitics"])
    avg_risk = round(sum(item.risk_score for item in items) / total_items, 1) if items else 0.0
    last_ingested = session.exec(select(func.max(FeedSource.last_checked_at))).one()

    return {
        "total_items": total_items,
        "high_priority": high_priority,
        "critical_items": critical_items,
        "cyber_items": cyber_items,
        "geo_items": geo_items,
        "avg_risk": avg_risk,
        "last_ingested": last_ingested.isoformat() if last_ingested else None,
    }
