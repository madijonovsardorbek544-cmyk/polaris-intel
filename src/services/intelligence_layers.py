from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import asdict

from ..entities import extract_cves, uniq_keep_order
from ..models import CveEnrichment, IntelCluster, IntelEdge, IntelEntity, IntelligenceItem, ReviewQueueItem
from ..scoring import CYBER_RISK_TERMS
from .analysis import now_iso

EXPLOIT_REPORTED_TERMS = ("actively exploited", "known exploited", "in the wild")


def stable_id(*parts: str, length: int = 18) -> str:
    return hashlib.sha256("|".join(parts).lower().encode()).hexdigest()[:length]


def item_text(item: IntelligenceItem) -> str:
    return f"{item.title or ''} {item.summary or ''} {' '.join(item.tags or [])}"


def item_cves(item: IntelligenceItem) -> list[str]:
    return uniq_keep_order([*item.entities.get("cves", []), *extract_cves(item_text(item))])


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def exploit_status_for_item(item: IntelligenceItem) -> str:
    return "reported_exploitation" if any(term in item_text(item).lower() for term in EXPLOIT_REPORTED_TERMS) else "unknown"


def build_cve_enrichments(items: list[IntelligenceItem]) -> list[CveEnrichment]:
    grouped: dict[str, list[IntelligenceItem]] = defaultdict(list)
    for item in items:
        for cve in item_cves(item):
            grouped[cve.upper()].append(item)
    enriched_at = now_iso()
    records: list[CveEnrichment] = []
    for cve_id, cve_items in grouped.items():
        max_item = max(cve_items, key=lambda i: i.risk_score)
        reported = any(exploit_status_for_item(i) == "reported_exploitation" for i in cve_items)
        cisa_kev = any("cisa" in (i.source_domain or i.source_url).lower() for i in cve_items) and reported
        sources = uniq_keep_order([link for i in cve_items for link in ([i.source_url] + list(i.evidence_links or [])) if link])
        records.append(CveEnrichment(cve_id=cve_id, severity=severity_from_score(max_item.risk_score), cvss_score=None, epss_score=None, cisa_kev=cisa_kev, affected_products=[], vendor_advisory_links=[], exploit_status="reported_exploitation" if reported else "unknown", patch_status="unknown", enriched_at=enriched_at, sources=sources))
    return sorted(records, key=lambda r: r.cve_id)


def enrichment_dict(enrichment: CveEnrichment) -> dict[str, object]:
    return asdict(enrichment)


def attach_enrichments(item: IntelligenceItem, enrichments: dict[str, CveEnrichment], clusters: list[IntelCluster] | None = None) -> dict[str, object]:
    from .ingestion import item_to_dict
    data = item_to_dict(item)
    data["cve_enrichments"] = [enrichment_dict(enrichments[cve]) for cve in item_cves(item) if cve in enrichments]
    if clusters:
        cluster = next((c for c in clusters if item.id in c.item_ids), None)
        if cluster:
            data["cluster_id"] = cluster.id
            data["cluster_title"] = cluster.title
    return data


def apply_cluster_confidence(items: list[IntelligenceItem], clusters: list[IntelCluster]) -> list[IntelligenceItem]:
    by_item = {item_id: cluster for cluster in clusters for item_id in cluster.item_ids}
    changed: list[IntelligenceItem] = []
    for item in items:
        cluster = by_item.get(item.id)
        if not cluster or cluster.corroboration_level == "single_source":
            continue
        factors = list(item.confidence_factors or [])
        if cluster.corroboration_level == "strong" and len(cluster.source_domains) >= 3:
            label, boost = "Strong source corroboration +18", 18
        else:
            label, boost = "Corroborated by multiple sources +10", 10
        if label in factors:
            continue
        item.confidence_score = min(100, item.confidence_score + boost)
        factors.append(label)
        item.confidence_factors = factors
        changed.append(item)
    return changed


def entity_id(entity_type: str, value: str) -> str:
    return stable_id("entity", entity_type, value)


def build_graph(items: list[IntelligenceItem], watchlists: list[object], alerts: list[object], sources: list[object]) -> tuple[list[IntelEntity], list[IntelEdge]]:
    now = now_iso()
    entities: dict[str, IntelEntity] = {}
    edges: dict[str, IntelEdge] = {}

    def upsert(entity_type: str, value: str, display: str | None = None, seen_at: str | None = None) -> str:
        value = value.strip()
        eid = entity_id(entity_type, value)
        at = seen_at or now
        if eid not in entities:
            entities[eid] = IntelEntity(id=eid, type=entity_type, value=value, display_name=display or value, first_seen_at=at, last_seen_at=at)
        else:
            entities[eid].last_seen_at = max(entities[eid].last_seen_at, at)
        return eid

    def add_edge(src: str, dst: str, rel: str, item_id: str | None = None, weight: float = 1.0) -> None:
        edge_id = stable_id("edge", src, dst, rel, item_id or "")
        edges[edge_id] = IntelEdge(id=edge_id, source_entity_id=src, target_entity_id=dst, relationship=rel, evidence_item_id=item_id, weight=weight, created_at=now)

    for item in items:
        source_e = upsert("source", item.source_domain or item.source_url, item.source_domain or item.source_url, item.ingested_at)
        cve_ids = [upsert("cve", cve, cve, item.ingested_at) for cve in item_cves(item)]
        country_ids = [upsert("country", c, c, item.ingested_at) for c in item.affected_countries]
        sector_ids = [upsert("sector", s, s.title(), item.ingested_at) for s in item.affected_sectors]
        org_ids = [upsert("organization", o, o, item.ingested_at) for o in item.entities.get("organizations", [])]
        for target in [*cve_ids, *country_ids, *sector_ids, *org_ids]:
            add_edge(source_e, target, "mentions", item.id)
        for cve in cve_ids:
            add_edge(cve, source_e, "sourced_from", item.id)
            for sector in sector_ids:
                add_edge(cve, sector, "affects", item.id, 1.3)
            for country in country_ids:
                add_edge(cve, country, "touches_country", item.id, 1.1)
        for sector in sector_ids:
            for country in country_ids:
                add_edge(sector, country, "touches_country", item.id)
        for match in item.watchlist_matches:
            wl = upsert("watchlist", match.watchlist_id, match.watchlist_name, item.ingested_at)
            for target in [*cve_ids, *country_ids, *sector_ids] or [source_e]:
                add_edge(wl, target, "matched_watchlist", item.id, 1.5)
    for alert in alerts:
        alert_e = upsert("alert", getattr(alert, "id", ""), getattr(alert, "title", "alert"), getattr(alert, "created_at", now))
        item = next((i for i in items if i.id == getattr(alert, "item_id", "")), None)
        if item:
            for cve in item_cves(item):
                add_edge(alert_e, entity_id("cve", cve), "generated_alert", item.id, 1.8)
    for source in sources:
        upsert("source", getattr(source, "source_url", ""), getattr(source, "source_url", ""), getattr(source, "last_success_at", None) or now)
    return list(entities.values()), list(edges.values())


def normalize_title(title: str) -> str:
    text = re.sub(r"CVE-\d{4}-\d{4,7}", "cve", title or "", flags=re.I).lower()
    text = re.sub(r"[^a-z0-9 ]+", " ", text)
    words = [w for w in text.split() if w not in {"the", "a", "an", "to", "of", "in", "on", "for", "and", "warns"}]
    return " ".join(words[:8])


def cluster_keys(item: IntelligenceItem) -> list[str]:
    keys = [f"cve:{cve}" for cve in item_cves(item)]
    nt = normalize_title(item.title)
    if nt:
        keys.append(f"title:{nt}")
    term = next((term for term in CYBER_RISK_TERMS if term in item_text(item).lower()), "")
    if item.affected_countries and item.affected_sectors and term:
        keys.append(f"triad:{item.affected_countries[0].lower()}:{item.affected_sectors[0].lower()}:{term}")
    return keys or [f"item:{item.id}"]


def build_clusters(items: list[IntelligenceItem]) -> list[IntelCluster]:
    parent = {item.id: item.id for item in items}
    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb: parent[rb] = ra
    by_key: dict[str, list[str]] = defaultdict(list)
    for item in items:
        for key in cluster_keys(item):
            by_key[key].append(item.id)
    for ids in by_key.values():
        for other in ids[1:]:
            union(ids[0], other)
    groups: dict[str, list[IntelligenceItem]] = defaultdict(list)
    by_id = {i.id: i for i in items}
    for item_id in parent:
        groups[find(item_id)].append(by_id[item_id])
    clusters: list[IntelCluster] = []
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    for group in groups.values():
        group = sorted(group, key=lambda i: (i.risk_score, i.ingested_at), reverse=True)
        domains = uniq_keep_order([i.source_domain or i.source_url for i in group if i.source_domain or i.source_url])
        corroboration = "strong" if len(domains) >= 3 else "multi_source" if len(domains) >= 2 else "single_source"
        risk = max((i.risk_level for i in group), key=lambda r: order.get(r, 0), default="Low")
        key_entities = uniq_keep_order([entity for i in group for entity in [*item_cves(i), *i.affected_countries, *i.affected_sectors]])[:12]
        first = min((i.ingested_at for i in group if i.ingested_at), default=now_iso())
        last = max((i.ingested_at for i in group if i.ingested_at), default=first)
        confidence = min(100, round(sum(i.confidence_score for i in group) / len(group)) + (18 if corroboration == "strong" else 10 if corroboration == "multi_source" else 0))
        cid = stable_id("cluster", *(sorted([i.id for i in group])))
        clusters.append(IntelCluster(id=cid, title=group[0].title, summary=f"{len(group)} related intelligence items across {len(domains)} source domain(s).", item_ids=[i.id for i in group], source_domains=domains, risk_level=risk, confidence_score=confidence, first_seen_at=first, last_seen_at=last, key_entities=key_entities, corroboration_level=corroboration, evidence_count=sum(max(1, len(i.evidence_links or [])) for i in group)))
    return sorted(clusters, key=lambda c: (len(c.item_ids), c.confidence_score), reverse=True)


def generate_review_items(items: list[IntelligenceItem], enrichments: dict[str, CveEnrichment], clusters: list[IntelCluster], feedback: list[object]) -> list[ReviewQueueItem]:
    now = now_iso()
    by_item_cluster = {item_id: c for c in clusters for item_id in c.item_ids}
    output: dict[str, ReviewQueueItem] = {}
    def add(item: IntelligenceItem, reason: str, priority: str, org_id: str | None = None) -> None:
        cluster = by_item_cluster.get(item.id)
        rid = stable_id("review", item.id, reason, org_id or "")
        output[rid] = ReviewQueueItem(id=rid, item_id=item.id, cluster_id=cluster.id if cluster else None, org_id=org_id, priority=priority, reason=reason, status="pending", created_at=now, updated_at=now)
    for item in items:
        if item.risk_level == "Critical":
            add(item, "Critical intelligence item requires analyst validation", "urgent")
        if any(enrichments.get(cve) and enrichments[cve].exploit_status == "reported_exploitation" for cve in item_cves(item)):
            add(item, "CVE has reported exploitation", "urgent" if item.risk_level in {"Critical", "High"} else "high")
        cluster = by_item_cluster.get(item.id)
        if cluster and cluster.corroboration_level == "strong":
            add(item, "Strongly corroborated incident cluster", "high")
        if item.source_reliability == "Low" and item.risk_level in {"High", "Critical"}:
            add(item, "Low-reliability source carrying high-risk claim", "high")
    items_by_id = {i.id: i for i in items}
    for fb in feedback:
        if getattr(fb, "relevance", "") == "false_positive" and getattr(fb, "item_id", "") in items_by_id:
            add(items_by_id[fb.item_id], "Customer marked item as false_positive", "medium", getattr(fb, "org_id", None))
    return list(output.values())


def maturity_score(counts: dict[str, int | bool]) -> dict[str, object]:
    levels = {
        "sources": min(15, 15 if counts.get("sources", 0) else 0),
        "cve_enrichment": 15 if counts.get("cves", 0) else 0,
        "entity_graph": 15 if counts.get("entities", 0) and counts.get("edges", 0) else 0,
        "clusters": 15 if counts.get("clusters", 0) else 0,
        "review_queue": 10 if counts.get("reviews", 0) else 0,
        "customer_workflow": 15 if counts.get("watchlists", 0) and counts.get("alerts", 0) else 5 if counts.get("watchlists", 0) else 0,
        "deployment_safety": 15 if counts.get("database") and counts.get("api_key") and counts.get("protect_reads") else 5 if counts.get("api_key") else 0,
    }
    score = int(sum(levels.values()))
    gaps = []
    actions = []
    gap_actions = {
        "cve_enrichment": "Run POST /api/cves/enrich after ingesting CVE-bearing items.",
        "entity_graph": "Run POST /api/graph/rebuild to connect entities, sources, watchlists, and alerts.",
        "clusters": "Run POST /api/clusters/rebuild to corroborate incident stories.",
        "review_queue": "Run POST /api/review/generate and review generated analyst tasks.",
        "deployment_safety": "Set DATABASE_URL, POLARIS_API_KEY, and POLARIS_PROTECT_READS=true before real pilots.",
    }
    for key, value in levels.items():
        if value == 0:
            gaps.append(f"{key} is not active yet")
            if key in gap_actions:
                actions.append(gap_actions[key])
    if not actions:
        actions.append("Continue adding authoritative sources and pilot-specific watchlists.")
    return {"score": score, "levels": levels, "blocking_gaps": gaps, "next_actions": actions}
