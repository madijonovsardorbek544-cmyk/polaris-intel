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


CYBER_NEWS_DOMAINS = {"bleepingcomputer.com", "darkreading.com", "thehackernews.com"}
WORLD_NEWS_DOMAINS = {"reuters", "bbc", "aljazeera.com"}


def source_type(url: str) -> str:
    domain = source_domain(url)
    if "cisa.gov" in domain:
        return "official"
    if any(key in domain for key in CYBER_NEWS_DOMAINS):
        return "cyber-news"
    if any(key in domain for key in WORLD_NEWS_DOMAINS):
        return "world-news"
    return "custom"


def source_reliability_tier(url: str) -> str:
    domain = source_domain(url)
    if "cisa.gov" in domain:
        return "High"
    if any(key in domain for key in {"bleepingcomputer.com", "darkreading.com"}):
        return "High"
    if any(key in domain for key in CYBER_NEWS_DOMAINS | WORLD_NEWS_DOMAINS):
        return "Medium"
    return "Medium" if domain else "Low"


def evidence_summary_for_source(url: str, title: str, summary: str) -> str:
    stype = source_type(url)
    tier = source_reliability_tier(url)
    domain = source_domain(url) or "the reported source"
    return f"{tier} reliability {stype} source ({domain}) provides the primary evidence for this signal."

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


def source_reliability_label(url: str) -> str:
    domain = source_domain(url)
    for key in SOURCE_RELIABILITY:
        if key in domain:
            return key.upper() if key == "cisa.gov" else key
    return domain or "Unknown source"


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


def calculate_risk_score_with_factors(
    *,
    title: str,
    summary: str,
    source_url: str,
    countries: list[str],
    sectors: list[str],
    watchlist_relevant: bool = False,
) -> tuple[int, list[str]]:
    text = f"{title or ''} {summary or ''}".lower()
    factors = ["Base intelligence signal +15"]
    score = 15

    reliability = min(8, source_reliability_score(source_url))
    if reliability:
        score += reliability
        factors.append(f"{source_reliability_label(source_url)} source reliability +{reliability}")

    cves = extract_cves(text)
    if cves:
        weight = min(25, 10 + len(cves) * 5)
        score += weight
        factors.append(f"CVE detected +{weight}")

    if any(term in text for term in ACTIVE_EXPLOIT_TERMS):
        score += 20
        factors.append("Active exploitation language +20")

    for term, weight in CYBER_RISK_TERMS.items():
        if term in text:
            score += weight
            factors.append(f"Cyber risk term: {term} +{weight}")

    matched_countries = [country for country in countries if country in HIGH_ATTENTION_COUNTRIES]
    if matched_countries:
        score += 8
        factors.append(f"High-attention geography: {', '.join(matched_countries[:3])} +8")

    matched_sectors = [sector for sector in sectors if sector in HIGH_IMPACT_SECTORS]
    if matched_sectors:
        score += 10
        factors.append(f"High-impact sector: {', '.join(matched_sectors[:3])} +10")

    escalation_hits = [term for term in GEOPOLITICAL_ESCALATION_TERMS if term in text]
    if escalation_hits:
        weight = min(20, len(escalation_hits) * 5)
        score += weight
        factors.append(f"Geopolitical escalation language +{weight}")

    if watchlist_relevant:
        score += 12
        factors.append("Watchlist match +12")

    if "no evidence of exploitation" in text or "no imminent threat" in text:
        score -= 10
        factors.append("De-escalating language -10")

    return clamp(score), factors


def calculate_risk_score(
    *,
    title: str,
    summary: str,
    source_url: str,
    countries: list[str],
    sectors: list[str],
    watchlist_relevant: bool = False,
) -> int:
    score, _ = calculate_risk_score_with_factors(
        title=title,
        summary=summary,
        source_url=source_url,
        countries=countries,
        sectors=sectors,
        watchlist_relevant=watchlist_relevant,
    )
    return score


def calculate_confidence_score_with_factors(
    *,
    title: str,
    summary: str,
    source_url: str,
    entities: dict[str, list[str]],
    risk_signals: list[str],
) -> tuple[int, list[str]]:
    factors = ["Base confidence +30"]
    score = 30
    stype = source_type(source_url)
    tier = source_reliability_tier(source_url)
    reliability = {"High": 20, "Medium": 12, "Low": 4}.get(tier, 8)
    if reliability:
        score += reliability
        if stype == "official":
            factors.append("Official source reliability +20")
        elif stype == "cyber-news":
            factors.append("Cyber news source +12")
        else:
            factors.append(f"{source_reliability_label(source_url)} source corroboration +{reliability}")

    entity_count = sum(len(values) for values in entities.values())
    if entity_count:
        weight = min(20, entity_count * 4)
        score += weight
        factors.append(f"Structured entities detected +{weight}")

    if len((title or "").split()) >= 5:
        score += 8
        factors.append("Specific title context +8")

    if len((summary or "").split()) >= 20:
        score += 10
        factors.append("Detailed summary +10")
    elif summary:
        score += 5
        factors.append("Brief summary +5")

    if risk_signals:
        weight = min(15, len(risk_signals) * 3)
        score += weight
        factors.append(f"Risk signal density +{weight}")

    return clamp(score), factors


def calculate_confidence_score(
    *,
    title: str,
    summary: str,
    source_url: str,
    entities: dict[str, list[str]],
    risk_signals: list[str],
) -> int:
    score, _ = calculate_confidence_score_with_factors(
        title=title,
        summary=summary,
        source_url=source_url,
        entities=entities,
        risk_signals=risk_signals,
    )
    return score
