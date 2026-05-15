from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from ..entities import extract_entities, uniq_keep_order
from ..models import IntelligenceItem, Watchlist
from ..scoring import calculate_confidence_score, calculate_risk_score, matching_risk_signals, risk_level, source_domain


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_item_id(title: str, source_url: str) -> str:
    digest = hashlib.sha256(f"{source_url.strip().lower()}|{title.strip().lower()}".encode()).hexdigest()
    return digest[:16]


def classify_category(title: str, summary: str) -> str:
    text = f"{title or ''} {summary or ''}".lower()
    cyber = any(term in text for term in ["cve", "vulnerability", "exploit", "ransomware", "malware", "phishing", "breach", "zero-day", "ddos", "credential"])
    geopolitical = any(term in text for term in ["war", "missile", "drone", "sanction", "strike", "conflict", "invasion", "military", "border", "diplomatic", "election", "nato", "taiwan", "ukraine"])
    if cyber and geopolitical:
        return "Hybrid"
    if cyber:
        return "Cyber"
    if geopolitical:
        return "Geopolitics"
    return "General"


def watchlist_relevance(title: str, summary: str, entities: dict[str, list[str]], watchlists: list[Watchlist]) -> bool:
    text = f"{title or ''} {summary or ''}".lower()
    cves = {cve.lower() for cve in entities.get("cves", [])}
    countries = {country.lower() for country in entities.get("countries", [])}
    sectors = {sector.lower() for sector in entities.get("sectors", [])}

    for watchlist in watchlists:
        if any(country.lower() in countries for country in watchlist.countries):
            return True
        if any(sector.lower() in sectors for sector in watchlist.sectors):
            return True
        if any(cve.lower() in cves for cve in watchlist.cves):
            return True
        if any(keyword.lower() in text for keyword in watchlist.keywords):
            return True
        if any(org.lower() in text for org in watchlist.organizations):
            return True
        if any(actor.lower() in text for actor in watchlist.threat_actors):
            return True
    return False


def build_tags(category: str, entities: dict[str, list[str]], risk_signals: list[str], watchlist_relevant: bool) -> list[str]:
    tags = [category.lower()]
    tags.extend(entities.get("cves", [])[:5])
    tags.extend(entities.get("countries", [])[:5])
    tags.extend(entities.get("sectors", [])[:5])
    tags.extend(signal.replace(" ", "-") for signal in risk_signals[:6])
    if watchlist_relevant:
        tags.append("watchlist")
    return uniq_keep_order(tags)


def why_it_matters(category: str, risk: str, entities: dict[str, list[str]], watchlist_relevant: bool) -> str:
    countries = entities.get("countries", [])
    sectors = entities.get("sectors", [])
    cves = entities.get("cves", [])
    pieces: list[str] = []
    if cves:
        pieces.append(f"References {', '.join(cves[:3])}, which may require vulnerability triage.")
    if countries:
        pieces.append(f"Touches monitored geography: {', '.join(countries[:4])}.")
    if sectors:
        pieces.append(f"Potential sector exposure includes {', '.join(sectors[:4])}.")
    if category == "Hybrid":
        pieces.append("Combines cyber and geopolitical signals, increasing operational ambiguity.")
    if watchlist_relevant:
        pieces.append("Matches at least one configured watchlist.")
    if not pieces:
        pieces.append(f"Ranked as {risk} based on source reliability and textual risk signals.")
    return " ".join(pieces)


def recommended_action(risk: str, category: str, entities: dict[str, list[str]], watchlist_relevant: bool) -> str:
    if risk in {"Critical", "High"}:
        if entities.get("cves"):
            return "Validate asset exposure, prioritize patching or mitigations, and monitor exploitation reports."
        if category in {"Geopolitics", "Hybrid"}:
            return "Brief stakeholders, review country and sector exposure, and increase monitoring cadence."
        if watchlist_relevant:
            return "Escalate to the owner of the matching watchlist and collect corroborating sources."
        return "Review the source, confirm impact, and assign an owner for follow-up."
    if risk == "Medium":
        return "Monitor for corroboration and reassess if additional signals or watchlist matches appear."
    return "Track passively; no immediate action unless the item becomes relevant to a watchlist."


def analyze_item(title: str, summary: str, source_url: str, watchlists: list[Watchlist] | None = None, created_at: str | None = None) -> IntelligenceItem:
    watchlists = watchlists or []
    entities = extract_entities(title, summary)
    relevant = watchlist_relevance(title, summary, entities, watchlists)
    risk_signals = matching_risk_signals(title, summary)
    risk_score = calculate_risk_score(
        title=title,
        summary=summary,
        source_url=source_url,
        countries=entities["countries"],
        sectors=entities["sectors"],
        watchlist_relevant=relevant,
    )
    level = risk_level(risk_score)
    category = classify_category(title, summary)
    confidence = calculate_confidence_score(
        title=title,
        summary=summary,
        source_url=source_url,
        entities=entities,
        risk_signals=risk_signals,
    )
    return IntelligenceItem(
        id=stable_item_id(title, source_url),
        title=title,
        summary=summary,
        category=category,
        risk_score=risk_score,
        risk_level=level,
        confidence_score=confidence,
        source_url=source_url,
        source_domain=source_domain(source_url),
        tags=build_tags(category, entities, risk_signals, relevant),
        entities=entities,
        affected_countries=entities["countries"],
        affected_sectors=entities["sectors"],
        why_it_matters=why_it_matters(category, level, entities, relevant),
        recommended_action=recommended_action(level, category, entities, relevant),
        created_at=created_at or now_iso(),
        ingested_at=now_iso(),
    )
