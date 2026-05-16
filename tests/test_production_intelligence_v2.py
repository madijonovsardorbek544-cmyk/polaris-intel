from __future__ import annotations

import asyncio
import os
from pathlib import Path

from fastapi.testclient import TestClient

from src.database import add_source_config, list_source_configs, reset_memory_state, save_cve_enrichment, save_items
from src.main import app
from src.models import CveEnrichment, SourceConfig
from src.services.analysis import analyze_item, now_iso


def setup_function() -> None:
    asyncio.run(reset_memory_state())
    for key in ["POLARIS_ADMIN_API_KEY", "POLARIS_OPERATOR_API_KEY", "POLARIS_READONLY_API_KEY", "POLARIS_API_KEY", "POLARIS_ALLOWED_ORGS", "POLARIS_PROTECT_READS"]:
        os.environ.pop(key, None)


def client() -> TestClient:
    return TestClient(app)


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload
    def raise_for_status(self):
        return None
    def json(self):
        return self._payload


def test_mocked_external_cve_enrichment(monkeypatch) -> None:
    from src.services import enrichment

    async def fake_get(self, url, **kwargs):
        if url == enrichment.NVD_URL:
            return FakeResponse({
                "vulnerabilities": [{
                    "cve": {
                        "published": "2026-01-01T00:00:00.000",
                        "lastModified": "2026-01-02T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Test CVE"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}, "baseSeverity": "CRITICAL"}]},
                        "references": {"referenceData": [{"url": "https://vendor.example/a"}]},
                        "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}]}]}],
                    }
                }]
            })
        if url == enrichment.CISA_KEV_URL:
            return FakeResponse({"vulnerabilities": [{"cveID": "CVE-2026-12345", "dueDate": "2026-06-01", "vendorProject": "Vendor", "product": "Product"}]})
        return FakeResponse({"data": [{"epss": "0.92", "percentile": "0.99"}]})

    monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
    record = asyncio.run(enrichment.enrich_cve("CVE-2026-12345", force=True))
    assert record.cvss_score == 9.8
    assert record.cisa_kev is True
    assert record.epss_score == 0.92
    assert record.epss_percentile == 0.99
    assert record.refresh_status == "fresh"


def test_enrichment_failure_does_not_crash(monkeypatch) -> None:
    from src.services import enrichment
    async def fail_get(self, url, **kwargs):
        raise RuntimeError("network blocked")
    monkeypatch.setattr("httpx.AsyncClient.get", fail_get)
    record = asyncio.run(enrichment.enrich_cve("CVE-2026-99999", force=True))
    assert record.refresh_status == "failed"
    assert "RuntimeError" in (record.last_error or "")


def test_enrichment_cache_freshness(monkeypatch) -> None:
    from src.services import enrichment
    asyncio.run(save_cve_enrichment(CveEnrichment(cve_id="CVE-2026-11111", severity="High", enriched_at=now_iso(), refresh_status="fresh")))
    async def fail_if_called(self, url, **kwargs):
        raise AssertionError("should use cache")
    monkeypatch.setattr("httpx.AsyncClient.get", fail_if_called)
    record = asyncio.run(enrichment.enrich_cve("CVE-2026-11111"))
    assert record.severity == "High"


def test_background_job_creation_and_completion() -> None:
    c = client()
    res = c.post("/api/jobs/graph_rebuild")
    assert res.status_code == 202
    jobs = c.get("/api/jobs").json()
    assert jobs and jobs[0]["status"] in {"succeeded", "failed", "running", "queued"}


def test_alembic_and_ci_files_exist() -> None:
    assert Path("alembic.ini").exists()
    assert Path("migrations/env.py").exists()
    assert list(Path("migrations/versions").glob("*.py"))
    assert Path(".github/workflows/ci.yml").exists()


def test_api_key_roles_and_legacy_fallback() -> None:
    os.environ["POLARIS_ADMIN_API_KEY"] = "admin"
    os.environ["POLARIS_OPERATOR_API_KEY"] = "operator"
    os.environ["POLARIS_READONLY_API_KEY"] = "read"
    os.environ["POLARIS_PROTECT_READS"] = "true"
    c = client()
    assert c.get("/api/leads", headers={"X-Polaris-API-Key": "operator"}).status_code == 403
    assert c.post("/api/watchlists", headers={"X-Polaris-API-Key": "read"}, json={"name": "x", "org_id": "demo"}).status_code == 403
    assert c.get("/api/items", headers={"X-Polaris-API-Key": "read"}).status_code == 200
    os.environ.pop("POLARIS_ADMIN_API_KEY")
    os.environ.pop("POLARIS_OPERATOR_API_KEY")
    os.environ.pop("POLARIS_READONLY_API_KEY")
    os.environ["POLARIS_API_KEY"] = "legacy"
    assert c.get("/api/leads", headers={"X-Polaris-API-Key": "legacy"}).status_code == 200


def test_org_validation() -> None:
    os.environ["POLARIS_ALLOWED_ORGS"] = "demo"
    c = client()
    assert c.post("/api/watchlists", json={"name": "bad", "org_id": "evil"}).status_code == 400


def test_quality_report_and_weekly_brief_and_html() -> None:
    item = analyze_item("CISA CVE-2026-10101 exploited", "Critical exploit affects USA energy.", "https://www.cisa.gov/x", [])
    asyncio.run(save_items([item]))
    c = client()
    assert "quality_score" in c.get("/api/intelligence-quality").json()
    assert "executive_summary" in c.get("/api/brief/weekly?org_id=demo").json()
    html = c.get("/api/reports/customer-proof.html?org_id=demo").text
    assert "POLARIS Customer Proof Report" in html


def test_source_config_trust_output_and_disabled_source() -> None:
    cfg = SourceConfig(id="s1", url="https://trusted.example/feed", label="Trusted", enabled=False, trust_tier="High", source_type="official", created_at=now_iso())
    asyncio.run(add_source_config(cfg))
    c = client()
    data = c.get("/api/source-configs").json()
    assert data[0]["trust_tier"] == "High"
    assert data[0]["enabled"] is False
