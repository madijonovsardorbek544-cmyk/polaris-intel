from __future__ import annotations

from urllib.parse import urlparse

from .entities import extract_cves

SOURCE_RELIABILITY = {
    "cisa.gov": 22,
    "reuters": 14,
    "bbc": 12,
    "bleepingcomputer.com": 12,
    "darkreading.com": 10,
    "thehackernews.com": 10,
    "aljazeera.com": 8,
}

HIGH_ATTENTION_COUNTRIES = {"Russia", "Ukraine", "China", "Taiwan", "Iran", "Israel", "NATO", "USA"}
HIGH_IMPACT_SECTORS = {"government", "energy", "telecom", "healthcare", "banking", "defense"}
ACTIVE_EXPLOIT_TERMS = ["actively exploited", "active exploitation", "known exploited", "in the wild"]
GEOPOLITICAL_ESCALATION_TERMS = [
    "war", "airstrike", "strike", "missile", "drone", "invasion", "sanction",
    "escalation", "nuclear", "border", "military", "ceasefire", "conflict",
]
CYBER_RISK_TERMS = {
    "ransomware": 22,
    "zero-day": 22,
    "0day": 18,
    "remote code execution": 18,
    "rce": 14,
    "malware": 12,
    "credential leak": 12,
    "breach": 12,
    "phishing": 8,
    "ddos": 8,
    "exploit": 10,
    "critical": 14,
}


def clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


def source_domain(url: str) -> str:
    try:
        return urlparse(url or "").netloc.lower().removeprefix("www.")
    except Exception:
        return ""


def source_reliability_score(url: str) -> int:
    domain = source_domain(url)
    for key, score in SOURCE_RELIABILITY.items():
        if key in domain:
            return score
    return 5 if domain else 0


def risk_level(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def matching_risk_signals(title: str, summary: str) -> list[str]:
    text = f"{title or ''} {summary or ''}".lower()
    signals: list[str] = []
    if extract_cves(text):
        signals.append("cve")
    signals.extend(term for term in ACTIVE_EXPLOIT_TERMS if term in text)
    signals.extend(term for term in CYBER_RISK_TERMS if term in text)
    signals.extend(term for term in GEOPOLITICAL_ESCALATION_TERMS if term in text)
    return list(dict.fromkeys(signals))


def calculate_risk_score(
    *,
    title: str,
    summary: str,
    source_url: str,
    countries: list[str],
    sectors: list[str],
    watchlist_relevant: bool = False,
) -> int:
    text = f"{title or ''} {summary or ''}".lower()
    score = 15 + source_reliability_score(source_url)

    cves = extract_cves(text)
    if cves:
        score += min(25, 10 + len(cves) * 5)

    if any(term in text for term in ACTIVE_EXPLOIT_TERMS):
        score += 20

    for term, weight in CYBER_RISK_TERMS.items():
        if term in text:
            score += weight

    if any(country in HIGH_ATTENTION_COUNTRIES for country in countries):
        score += 8
    if any(sector in HIGH_IMPACT_SECTORS for sector in sectors):
        score += 10

    escalation_hits = sum(1 for term in GEOPOLITICAL_ESCALATION_TERMS if term in text)
    score += min(20, escalation_hits * 5)

    if watchlist_relevant:
        score += 12

    if "no evidence of exploitation" in text or "no imminent threat" in text:
        score -= 10

    return clamp(score)


def calculate_confidence_score(
    *,
    title: str,
    summary: str,
    source_url: str,
    entities: dict[str, list[str]],
    risk_signals: list[str],
) -> int:
    score = 30 + min(25, source_reliability_score(source_url))
    entity_count = sum(len(values) for values in entities.values())
    score += min(20, entity_count * 4)
    if len((title or "").split()) >= 5:
        score += 8
    if len((summary or "").split()) >= 20:
        score += 10
    elif summary:
        score += 5
    score += min(15, len(risk_signals) * 3)
    return clamp(score)
