from src.entities import extract_countries, extract_cves, extract_sectors


def test_cve_extraction_normalizes_and_deduplicates() -> None:
    text = "Critical exploit for cve-2026-12345 and CVE-2026-12345"
    assert extract_cves(text) == ["CVE-2026-12345"]


def test_country_extraction_includes_required_terms_and_aliases() -> None:
    text = "Russia, Ukraine, NATO, the EU, and the United States discussed Taiwan risk."
    assert extract_countries(text) == ["Russia", "Ukraine", "Taiwan", "USA", "NATO", "EU"]


def test_sector_extraction_supports_aliases() -> None:
    text = "The attack affected government, telecommunications, healthcare, logistics, and defence networks."
    assert extract_sectors(text) == ["government", "telecom", "healthcare", "logistics", "defense"]
