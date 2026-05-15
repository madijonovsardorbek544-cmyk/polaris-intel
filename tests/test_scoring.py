from src.scoring import calculate_confidence_score, calculate_risk_score, risk_level


def test_risk_scoring_prioritizes_cves_active_exploitation_and_ransomware() -> None:
    score = calculate_risk_score(
        title="CVE-2026-22222 actively exploited by ransomware operators",
        summary="A zero-day remote code execution exploit targets government and energy networks in Ukraine.",
        source_url="https://www.cisa.gov/news-events/cybersecurity-advisories/example",
        countries=["Ukraine"],
        sectors=["government", "energy"],
    )
    assert score >= 85
    assert risk_level(score) == "Critical"


def test_risk_level_thresholds() -> None:
    assert risk_level(10) == "Low"
    assert risk_level(40) == "Medium"
    assert risk_level(65) == "High"
    assert risk_level(85) == "Critical"


def test_watchlist_relevance_increases_risk() -> None:
    base = calculate_risk_score(
        title="Phishing campaign targets education users",
        summary="Credential leak reported in education sector.",
        source_url="https://example.com/report",
        countries=[],
        sectors=["education"],
        watchlist_relevant=False,
    )
    boosted = calculate_risk_score(
        title="Phishing campaign targets education users",
        summary="Credential leak reported in education sector.",
        source_url="https://example.com/report",
        countries=[],
        sectors=["education"],
        watchlist_relevant=True,
    )
    assert boosted - base == 12


def test_confidence_uses_source_entities_clarity_and_signals() -> None:
    confidence = calculate_confidence_score(
        title="CISA warns critical vulnerability is actively exploited",
        summary="This report includes clear details about affected government systems in Ukraine and recommended mitigations for defenders.",
        source_url="https://www.cisa.gov/news-events/alerts/example",
        entities={"cves": ["CVE-2026-11111"], "countries": ["Ukraine"], "sectors": ["government"], "cyber_terms": ["exploit"]},
        risk_signals=["cve", "actively exploited", "critical", "exploit"],
    )
    assert confidence >= 80
