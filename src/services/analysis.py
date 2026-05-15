from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from ..entities import extract_entities, uniq_keep_order
from ..models import IntelligenceItem, Watchlist
from ..scoring import (
    calculate_confidence_score_with_factors,
    calculate_risk_score_with_factors,
    matching_risk_signals,
    risk_level,
    source_domain,
)


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


def watchlist_match_explanations(title: str, summary: str, entities: dict[str, list[str]], watchlists: list[Watchlist]) -> list[dict[str, str]]:
    text = f"{title or ''} {summary or ''}".lower()
    cves = {cve.lower() for cve in entities.get("cves", [])}
    countries = {country.lower() for country in entities.get("countries", [])}
    sectors = {sector.lower() for sector in entities.get("sectors", [])}
    matches: list[dict[str, str]] = []

    for watchlist in watchlists:
        reasons: list[str] = []
        country_hits = [country for country in watchlist.countries if country.lower() in countries]
        sector_hits = [sector for sector in watchlist.sectors if sector.lower() in sectors]
        cve_hits = [cve.upper() for cve in watchlist.cves if cve.lower() in cves]
        keyword_hits = [keyword for keyword in watchlist.keywords if keyword.lower() in text]
        organization_hits = [org for org in watchlist.organizations if org.lower() in text]
        actor_hits = [actor for actor in watchlist.threat_actors if actor.lower() in text]

        if country_hits:
            reasons.append(f"country: {', '.join(country_hits)}")
        if sector_hits:
            reasons.append(f"sector: {', '.join(sector_hits)}")
        if cve_hits:
            reasons.append(f"CVE: {', '.join(cve_hits)}")
        if keyword_hits:
            reasons.append(f"keyword: {', '.join(keyword_hits)}")
        if organization_hits:
            reasons.append(f"organization: {', '.join(organization_hits)}")
        if actor_hits:
            reasons.append(f"threat actor: {', '.join(actor_hits)}")

        if reasons:
            matches.append(
                {
                    "watchlist_id": watchlist.id,
                    "watchlist_name": watchlist.name,
                    "reason": "; ".join(reasons),
                }
            )
    return matches


def watchlist_relevance(title: str, summary: str, entities: dict[str, list[str]], watchlists: list[Watchlist]) -> bool:
    return bool(watchlist_match_explanations(title, summary, entities, watchlists))


def build_tags(category: str, entities: dict[str, list[str]], risk_signals: list[str], watchlist_relevant: bool) -> list[str]:
    tags = [category.lower()]
    tags.extend(entities.get("cves", [])[:5])
    tags.extend(entities.get("countries", [])[:5])
    tags.extend(entities.get("sectors", [])[:5])
    tags.extend(signal.replace(" ", "-") for signal in risk_signals[:6])
    if watchlist_relevant:
        tags.append("watchlist")
    return uniq_keep_order(tags)


def why_it_matters(category: str, risk: str, entities: dict[str, list[str]], watchlist_matches: list[dict[str, str]]) -> str:
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
    if watchlist_matches:
        names = ", ".join(match["watchlist_name"] for match in watchlist_matches[:3])
        pieces.append(f"Matches watchlist coverage: {names}.")
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
    matches = watchlist_match_explanations(title, summary, entities, watchlists)
    relevant = bool(matches)
    risk_signals = matching_risk_signals(title, summary)
    risk_score, risk_factors = calculate_risk_score_with_factors(
        title=title,
        summary=summary,
        source_url=source_url,
        countries=entities["countries"],
        sectors=entities["sectors"],
        watchlist_relevant=relevant,
    )
    level = risk_level(risk_score)
    category = classify_category(title, summary)
    confidence, confidence_factors = calculate_confidence_score_with_factors(
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
        why_it_matters=why_it_matters(category, level, entities, matches),
        recommended_action=recommended_action(level, category, entities, relevant),
        created_at=created_at or now_iso(),
        ingested_at=now_iso(),
        risk_factors=risk_factors,
        confidence_factors=confidence_factors,
        watchlist_matches=matches,
    )
