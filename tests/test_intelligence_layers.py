from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from src.database import add_item_feedback, reset_memory_state, save_items
from src.main import app
from src.models import ItemFeedback
from src.services.analysis import analyze_item, now_iso


def setup_function() -> None:
    asyncio.run(reset_memory_state())


def client() -> TestClient:
    return TestClient(app)


def _seed_cve_items() -> list[str]:
    items = [
        analyze_item(
            "CISA warns CVE-2026-11111 is actively exploited in energy",
            "Known exploited vulnerability affects USA energy operators.",
            "https://www.cisa.gov/news-events/alerts/cve-2026-11111",
            [],
        ),
        analyze_item(
            "Vendor bulletin CVE-2026-11111 affects energy products",
            "Patch guidance for a critical exploit affecting USA energy teams.",
            "https://vendor.example/advisory/cve-2026-11111",
            [],
        ),
        analyze_item(
            "Researchers track CVE-2026-11111 exploitation",
            "Ransomware crews discuss exploit impact in the USA energy sector.",
            "https://research.example/blog/cve-2026-11111",
            [],
        ),
    ]
    asyncio.run(save_items(items))
    return [item.id for item in items]


def test_cve_enrichment_endpoints_and_item_attachment() -> None:
    _seed_cve_items()
    c = client()
    enriched = c.post("/api/cves/enrich")
    assert enriched.status_code == 200
    payload = enriched.json()
    assert payload["items_scanned"] == 3
    assert payload["cves_found"] == 1
    assert payload["cves_enriched"] == 1
    assert payload["enriched"] == 1

    records = c.get("/api/cves").json()
    assert records[0]["cve_id"] == "CVE-2026-11111"
    assert records[0]["exploit_status"] == "reported_exploitation"
    assert records[0]["cisa_kev"] is True
    assert records[0]["sources"]

    item = c.get("/api/items").json()[0]
    assert item["cve_enrichments"][0]["cve_id"] == "CVE-2026-11111"
    assert c.get("/api/cves/CVE-2026-11111").json()["severity"] in {"Critical", "High", "Medium", "Low"}



def test_cve_enrichment_detects_in_the_wild_exploitation_phrase() -> None:
    item = analyze_item(
        "Vendor warns CVE-2026-22222 exploited in the wild",
        "Exploit activity against USA energy systems has been observed in the wild.",
        "https://vendor.example/advisory/cve-2026-22222",
        [],
    )
    asyncio.run(save_items([item]))
    c = client()
    response = c.post("/api/cves/enrich")
    assert response.status_code == 200
    record = c.get("/api/cves/CVE-2026-22222").json()
    assert record["exploit_status"] == "reported_exploitation"

def test_graph_rebuild_creates_expected_entities_and_edges() -> None:
    _seed_cve_items()
    c = client()
    rebuilt = c.post("/api/graph/rebuild").json()
    assert rebuilt["entities"] >= 4
    assert rebuilt["edges"] >= 1
    entities = c.get("/api/graph/entities").json()
    entity_types = {entity["type"] for entity in entities}
    assert {"cve", "country", "sector", "source"}.issubset(entity_types)
    edges = c.get("/api/graph/edges").json()
    assert any(edge["relationship"] in {"mentions", "affects", "sourced_from"} for edge in edges)


def test_clusters_corroboration_and_confidence_without_risk_inflation() -> None:
    _seed_cve_items()
    c = client()
    before = {item["id"]: item["risk_score"] for item in c.get("/api/items").json()}
    payload = c.post("/api/clusters/rebuild").json()
    assert payload["clusters"] >= 1
    clusters = c.get("/api/clusters").json()
    strong = next(cluster for cluster in clusters if "CVE-2026-11111" in cluster["key_entities"])
    assert strong["corroboration_level"] == "strong"
    assert len(strong["source_domains"]) >= 3
    after = c.get("/api/items").json()
    assert {item["id"]: item["risk_score"] for item in after} == before
    assert any("Strong source corroboration +18" in item["confidence_factors"] for item in after)


def test_review_queue_generation_patch_and_false_positive_reason() -> None:
    item_ids = _seed_cve_items()
    async def add_feedback() -> None:
        await add_item_feedback(ItemFeedback(id="fb1", item_id=item_ids[0], relevance="false_positive", severity_feedback="too_high", org_id="demo", created_at=now_iso()))
    asyncio.run(add_feedback())

    c = client()
    c.post("/api/cves/enrich")
    c.post("/api/clusters/rebuild")
    generated = c.post("/api/review/generate").json()
    assert generated["created"] >= 1
    reviews = c.get("/api/review").json()
    assert any("reported exploitation" in review["reason"] for review in reviews)
    assert any("false_positive" in review["reason"] for review in reviews)
    patched = c.patch(f"/api/review/{reviews[0]['id']}", json={"status": "reviewed"})
    assert patched.status_code == 200
    assert patched.json()["status"] == "reviewed"


def test_intelligence_maturity_score_improves_after_layer_builds() -> None:
    _seed_cve_items()
    c = client()
    initial = c.get("/api/intelligence-maturity").json()
    c.post("/api/cves/enrich")
    c.post("/api/graph/rebuild")
    c.post("/api/clusters/rebuild")
    c.post("/api/review/generate")
    mature = c.get("/api/intelligence-maturity").json()
    assert mature["score"] > initial["score"]
    assert "levels" in mature
    assert isinstance(mature["blocking_gaps"], list)


def test_dashboard_contains_intelligence_layer_panels() -> None:
    html = client().get("/dashboard").text
    assert "Intelligence graph" in html
    assert "Incident clusters" in html
    assert "Analyst review queue" in html
    assert "Intelligence maturity" in html
