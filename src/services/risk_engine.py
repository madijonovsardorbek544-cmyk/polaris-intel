from __future__ import annotations

import re

from src.utils.text import host_of, uniq_keep_order

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

CYBER_KEYWORDS = (
    "cve",
    "vulnerability",
    "exploit",
    "ransomware",
    "malware",
    "phishing",
    "credential",
    "breach",
    "leak",
    "patch",
    "advisory",
    "cisa",
    "ics",
    "scada",
    "ddos",
    "zero-day",
    "0day",
)

GEOPOLITICAL_KEYWORDS = (
    "war",
    "missile",
    "drone",
    "sanction",
    "strike",
    "airstrike",
    "ceasefire",
    "conflict",
    "invasion",
    "military",
    "border",
    "diplomatic",
    "election",
    "geopolitical",
    "tension",
    "attack",
)

KEYWORD_TAGS = {
    "ransomware": "ransomware",
    "phishing": "phishing",
    "credential": "credentials",
    "leak": "leak",
    "breach": "breach",
    "exploit": "exploit",
    "zero-day": "0day",
    "ddos": "ddos",
    "sanction": "sanctions",
    "ceasefire": "ceasefire",
    "missile": "missile",
    "drone": "drone",
    "election": "election",
    "diplomatic": "diplomacy",
    "iran": "iran",
    "israel": "israel",
    "russia": "russia",
    "ukraine": "ukraine",
}

SOURCE_TAGS = {
    "cisa.gov": "cisa",
    "thehackernews.com": "thn",
    "bleepingcomputer.com": "bleepingcomputer",
    "aljazeera.com": "aljazeera",
    "bbc": "bbc",
    "reuters": "reuters",
}

CYBER_WEIGHTS = {
    "critical": 28,
    "high severity": 18,
    "actively exploited": 28,
    "known exploited": 24,
    "zero-day": 26,
    "ransomware": 26,
    "remote code execution": 26,
    "rce": 22,
    "malware": 16,
    "breach": 18,
    "leak": 12,
    "credential": 12,
    "phishing": 10,
    "ddos": 10,
    "exploit": 16,
    "vulnerability": 8,
    "advisory": 8,
}

GEOPOLITICAL_WEIGHTS = {
    "war": 20,
    "airstrike": 18,
    "strike": 12,
    "missile": 16,
    "drone": 12,
    "attack": 12,
    "invasion": 22,
    "military": 10,
    "sanction": 8,
    "ceasefire": 6,
    "tension": 8,
    "escalation": 16,
    "nuclear": 20,
}

MAJOR_ACTORS = ("iran", "israel", "russia", "ukraine", "china", "taiwan", "nato", "u.s.", "us ")


def classify_category(title: str, summary: str, source: str) -> str:
    text = f"{title} {summary} {source}".lower()
    has_cyber_signal = any(keyword in text for keyword in CYBER_KEYWORDS)
    has_geopolitical_signal = any(keyword in text for keyword in GEOPOLITICAL_KEYWORDS)

    if has_cyber_signal and has_geopolitical_signal:
        return "Hybrid"
    if has_cyber_signal:
        return "Cyber"
    if has_geopolitical_signal:
        return "Geopolitics"
    return "General"


def extract_tags(title: str, summary: str, source: str) -> list[str]:
    combined_text = f"{title} {summary}"
    lower_text = combined_text.lower()
    tags = [cve.upper() for cve in CVE_RE.findall(combined_text)[:6]]

    for keyword, tag in KEYWORD_TAGS.items():
        if keyword in lower_text:
            tags.append(tag)

    host = host_of(source)
    for source_key, tag in SOURCE_TAGS.items():
        if source_key in host:
            tags.append(tag)
            break

    return uniq_keep_order(tags)


def _clamp_score(score: int) -> int:
    return max(0, min(100, score))


def score_risk(title: str, summary: str, source: str, category: str) -> int:
    combined_text = f"{title} {summary}".lower()
    host = host_of(source)
    score = 18

    if "cisa.gov" in host:
        score += 18
    if any(source_name in host for source_name in ("thehackernews.com", "bleepingcomputer.com", "darkreading.com")):
        score += 8
    if any(source_name in host for source_name in ("reuters", "bbc", "aljazeera")):
        score += 6

    cve_count = len(CVE_RE.findall(f"{title} {summary}"))
    if cve_count:
        score += min(24, 10 + cve_count * 5)

    for keyword, weight in CYBER_WEIGHTS.items():
        if keyword in combined_text:
            score += weight

    for keyword, weight in GEOPOLITICAL_WEIGHTS.items():
        if keyword in combined_text:
            score += weight

    if any(actor in combined_text for actor in MAJOR_ACTORS):
        score += 8

    category_weights = {"Cyber": 6, "Geopolitics": 4, "Hybrid": 10}
    score += category_weights.get(category, 0)

    if "no imminent threat" in combined_text:
        score -= 10

    return _clamp_score(score)


def risk_level(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"
