from __future__ import annotations

import re
from collections.abc import Iterable

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

COUNTRY_TERMS = [
    "Uzbekistan", "Kazakhstan", "Russia", "Ukraine", "China", "Taiwan",
    "USA", "Iran", "Israel", "NATO", "EU",
]

SECTOR_TERMS = [
    "banking", "education", "government", "energy", "telecom", "healthcare",
    "logistics", "defense",
]

CYBER_TERMS = [
    "ransomware", "phishing", "malware", "exploit", "zero-day", "DDoS",
    "credential leak", "breach",
]

COUNTRY_ALIASES = {
    "USA": ["USA", "U.S.", "US ", "United States", "America"],
    "EU": ["EU", "European Union"],
}

SECTOR_ALIASES = {
    "telecom": ["telecom", "telecommunications"],
    "government": ["government", "public sector", "federal"],
    "defense": ["defense", "defence", "military"],
}


def uniq_keep_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        clean = (value or "").strip()
        if not clean:
            continue
        key = clean.lower()
        if key in seen:
            continue
        seen.add(key)
        output.append(clean)
    return output


def _contains_term(text: str, term: str) -> bool:
    if term.upper() in {"EU", "US", "USA", "U.S.", "NATO"}:
        return re.search(rf"(?<![A-Za-z]){re.escape(term)}(?![A-Za-z])", text, re.IGNORECASE) is not None
    return re.search(rf"\b{re.escape(term)}\b", text, re.IGNORECASE) is not None


def extract_cves(text: str) -> list[str]:
    return uniq_keep_order(cve.upper() for cve in CVE_RE.findall(text or ""))


def extract_countries(text: str) -> list[str]:
    matches: list[str] = []
    for country in COUNTRY_TERMS:
        aliases = COUNTRY_ALIASES.get(country, [country])
        if any(_contains_term(text or "", alias) for alias in aliases):
            matches.append(country)
    return uniq_keep_order(matches)


def extract_sectors(text: str) -> list[str]:
    matches: list[str] = []
    for sector in SECTOR_TERMS:
        aliases = SECTOR_ALIASES.get(sector, [sector])
        if any(_contains_term(text or "", alias) for alias in aliases):
            matches.append(sector)
    return uniq_keep_order(matches)


def extract_cyber_terms(text: str) -> list[str]:
    return uniq_keep_order(term for term in CYBER_TERMS if _contains_term(text or "", term))


def extract_entities(title: str, summary: str) -> dict[str, list[str]]:
    text = f"{title or ''} {summary or ''}"
    return {
        "cves": extract_cves(text),
        "countries": extract_countries(text),
        "sectors": extract_sectors(text),
        "cyber_terms": extract_cyber_terms(text),
    }
