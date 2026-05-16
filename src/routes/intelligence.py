from __future__ import annotations

import asyncio
import csv
import io
import logging
import uuid
from collections import Counter, defaultdict, deque
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from ..auth import require_api_key, require_read_api_key
from ..config import settings
from ..database import add_admin_audit_event, add_alert_event, add_item_feedback, add_pilot_lead, add_source_config, database_enabled, delete_source_config, get_alert, get_cve_enrichment, get_intel_cluster, get_intel_entity, get_item, get_org_profile, get_public_metrics, increment_public_metric, list_admin_audit_events, list_alert_events, list_alerts, list_cve_enrichments, list_intel_clusters, list_intel_edges, list_intel_entities, list_item_feedback, list_items, list_pilot_leads, list_review_queue, list_source_configs, list_source_health, list_watchlists, put_org_profile, replace_intel_clusters, replace_intel_graph, reset_memory_state, save_alerts_with_counts, save_cve_enrichment, save_items, save_review_queue_item, update_alert, update_pilot_lead_status, update_review_queue_item, update_source_config
from ..models import AdminAuditEvent, Alert, AlertEvent, IntelligenceItem, ItemFeedback, OrgScoringProfile, PilotLead, SourceConfig
from ..schemas import AlertUpdate, ItemFeedbackCreate, OrgScoringProfileIn, PilotLeadCreate, PilotLeadUpdate, SourceConfigCreate, SourceConfigUpdate
from ..services.analysis import analyze_item, now_iso
from ..services.briefing import alert_to_dict, alerts_from_items, format_alert_for_telegram, generate_alerts, generate_daily_brief
from ..services.ingestion import item_to_dict, refresh_status, refresh_store, seed_demo_items
from ..services.intelligence_layers import apply_cluster_confidence, attach_enrichments, build_clusters, build_cve_enrichments, build_graph, generate_review_items, item_cves, maturity_score

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")

_LEAD_RATE_WINDOW_SECONDS = 60 * 60
_LEAD_IP_LIMIT = 5
_LEAD_EMAIL_LIMIT = 2
_LEAD_IP_SUBMISSIONS: dict[str, deque[float]] = defaultdict(deque)
_LEAD_EMAIL_SUBMISSIONS: dict[str, deque[float]] = defaultdict(deque)


def clear_lead_rate_limits() -> None:
    _LEAD_IP_SUBMISSIONS.clear()
    _LEAD_EMAIL_SUBMISSIONS.clear()


def _prune_rate_bucket(bucket: deque[float], now: float) -> None:
    cutoff = now - _LEAD_RATE_WINDOW_SECONDS
    while bucket and bucket[0] <= cutoff:
        bucket.popleft()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client and request.client.host else "unknown"


def _check_lead_rate_limit(request: Request, email: str) -> None:
    loop = asyncio.get_running_loop()
    now = loop.time()
    ip_bucket = _LEAD_IP_SUBMISSIONS[_client_ip(request)]
    email_bucket = _LEAD_EMAIL_SUBMISSIONS[email.strip().lower()]
    _prune_rate_bucket(ip_bucket, now)
    _prune_rate_bucket(email_bucket, now)
    if len(ip_bucket) >= _LEAD_IP_LIMIT or len(email_bucket) >= _LEAD_EMAIL_LIMIT:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many pilot requests. Please try again later.")
    ip_bucket.append(now)
    email_bucket.append(now)


async def _audit(action: str, resource_type: str, resource_id: str, *, org_id: str | None = None, message: str = "") -> None:
    await add_admin_audit_event(AdminAuditEvent(id=str(uuid.uuid4()), action=action, resource_type=resource_type, resource_id=resource_id, org_id=org_id, message=message, created_at=now_iso()))


def _item_matches_org(item: IntelligenceItem, org_id: str | None) -> bool:
    if not org_id:
        return True
    return any(match.org_id == org_id for match in item.watchlist_matches)


def _alert_matches_org(alert: Alert | dict[str, object], org_id: str | None) -> bool:
    if not org_id:
        return True
    if isinstance(alert, Alert):
        return alert.org_id == org_id
    return alert.get("org_id") == org_id


async def _dashboard_check(name: str, operation) -> tuple[str, dict[str, object], str | None]:
    try:
        result = await operation()
        check: dict[str, object] = {"ok": True}
        if isinstance(result, int):
            check["count"] = result
        return name, check, None
    except Exception as exc:
        logger.warning("Dashboard health check failed check=%s error_type=%s message=%s", name, type(exc).__name__, str(exc))
        return name, {"ok": False, "error": type(exc).__name__}, f"{name} failed: {type(exc).__name__}"



async def _enrichment_map() -> dict[str, object]:
    return {record.cve_id: record for record in await list_cve_enrichments(limit=1000)}


async def _item_output(item: IntelligenceItem) -> dict[str, object]:
    return attach_enrichments(item, await _enrichment_map(), await list_intel_clusters(limit=1000))


async def _items_output(items: list[IntelligenceItem]) -> list[dict[str, object]]:
    enrichments = await _enrichment_map()
    clusters = await list_intel_clusters(limit=1000)
    return [attach_enrichments(item, enrichments, clusters) for item in items]


@router.post("/leads", status_code=status.HTTP_201_CREATED)
async def create_lead(payload: PilotLeadCreate, request: Request) -> dict[str, object]:
    if payload.website.strip():
        return {"ok": True, "message": "Pilot request received."}
    _check_lead_rate_limit(request, payload.email)
    lead = PilotLead(
        id=str(uuid.uuid4()),
        name=payload.name.strip(),
        organization=payload.organization.strip(),
        role=payload.role.strip(),
        email=payload.email.strip(),
        country=payload.country.strip(),
        organization_type=payload.organization_type.strip(),
        problem_description=payload.problem_description.strip(),
        preferred_contact_method=payload.preferred_contact_method.strip(),
        created_at=now_iso(),
        status="new",
    )
    saved = await add_pilot_lead(lead)
    await increment_public_metric("pilot_form_submissions")
    return {"ok": True, "lead_id": saved.id, "message": "Pilot request received."}


@router.get("/leads", dependencies=[Depends(require_api_key)])
async def leads(status: str | None = Query(default=None, pattern="^(new|contacted|qualified|rejected)$"), limit: int = Query(default=50, ge=1, le=200)) -> list[dict[str, object]]:
    return [asdict(lead) for lead in await list_pilot_leads(limit, status=status)]


@router.patch("/leads/{lead_id}", dependencies=[Depends(require_api_key)])
async def patch_lead(lead_id: str, payload: PilotLeadUpdate) -> dict[str, object]:
    lead = await update_pilot_lead_status(lead_id, payload.status)
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")
    await _audit("lead_status_update", "pilot_lead", lead.id, message=f"Lead status updated to {lead.status}")
    return asdict(lead)


@router.get("/public-metrics", dependencies=[Depends(require_api_key)])
async def public_metrics() -> dict[str, int]:
    return asdict(await get_public_metrics())


@router.get("/dashboard-health", dependencies=[Depends(require_read_api_key)])
async def dashboard_health(org_id: str = Query(default=settings.default_org)) -> dict[str, object]:
    async def items_count() -> int:
        return len([item for item in await list_items(settings.max_items) if _item_matches_org(item, org_id)])

    async def alerts_count() -> int:
        return len([alert for alert in await list_alerts() if _alert_matches_org(alert, org_id)])

    async def sources_count() -> int:
        return len(await list_source_health())

    async def brief_ok() -> None:
        all_items = await list_items(settings.max_items)
        generate_daily_brief([item for item in all_items if _item_matches_org(item, org_id)], await list_source_health())

    async def watchlists_count() -> int:
        return len([watchlist for watchlist in await list_watchlists() if watchlist.org_id == org_id])

    async def onboarding_ok() -> None:
        if not ONBOARDING_TEMPLATES:
            raise RuntimeError("No onboarding templates configured")

    async def value_report_ok() -> None:
        await build_value_report(org_id, 7)

    async def source_configs_count() -> int:
        return len(await list_source_configs())

    checks = await asyncio.gather(
        _dashboard_check("items", items_count),
        _dashboard_check("alerts", alerts_count),
        _dashboard_check("sources", sources_count),
        _dashboard_check("brief", brief_ok),
        _dashboard_check("watchlists", watchlists_count),
        _dashboard_check("onboarding", onboarding_ok),
        _dashboard_check("value_report", value_report_ok),
        _dashboard_check("source_configs", source_configs_count),
    )
    check_map = {name: check for name, check, _ in checks}
    errors = [error for _, _, error in checks if error]
    return {"ok": not errors, "checks": check_map, "errors": errors}


@router.get("/pilot-readiness")
async def pilot_readiness() -> dict[str, object]:
    source_health = await list_source_health()
    source_configs = await list_source_configs()
    items_available = bool(await list_items(1))
    sources_available = bool(source_health or source_configs or settings.feeds)
    checks = {
        "database_enabled": database_enabled(),
        "api_key_configured": bool(settings.api_key.strip()),
        "read_protection_enabled": bool(settings.protect_reads),
        "lead_endpoint_working": True,
        "items_available": items_available,
        "sources_available": sources_available,
        "telegram_configured": bool(settings.telegram_bot_token and settings.telegram_chat_id),
        "demo_memory_warning": not database_enabled(),
    }
    blocking_issues: list[str] = []
    recommended_actions: list[str] = []
    if not checks["database_enabled"]:
        blocking_issues.append("DATABASE_URL is missing; memory mode can lose customer data.")
        recommended_actions.append("Provision PostgreSQL and set DATABASE_URL before handling real pilot data.")
    if not checks["api_key_configured"]:
        blocking_issues.append("POLARIS_API_KEY is missing; admin write endpoints are not protected.")
        recommended_actions.append("Set a strong POLARIS_API_KEY and keep it out of URLs and client-side code.")
    if not checks["read_protection_enabled"]:
        blocking_issues.append("POLARIS_PROTECT_READS is false; sensitive read endpoints may be public.")
        recommended_actions.append("Set POLARIS_PROTECT_READS=true before sharing the deployment.")
    if not checks["items_available"]:
        blocking_issues.append("No intelligence items are available.")
        recommended_actions.append("Run feed refresh or seed demo items, then verify item ingestion succeeds.")
    if not checks["sources_available"]:
        blocking_issues.append("No sources are configured or reporting health.")
        recommended_actions.append("Configure at least one enabled RSS source and verify source health.")
    if not checks["telegram_configured"]:
        recommended_actions.append("Optional: configure Telegram credentials if pilot users expect chat alerts.")
    return {
        "ready_for_real_pilot": not blocking_issues,
        "checks": checks,
        "blocking_issues": blocking_issues,
        "recommended_actions": recommended_actions,
    }


@router.post("/rematch", dependencies=[Depends(require_api_key)])
async def rematch(org_id: str | None = None, limit: int = Query(default=200, ge=1, le=1000)) -> dict[str, object]:
    all_items = await list_items(limit)
    all_watchlists = await list_watchlists()
    if org_id:
        all_watchlists = [watchlist for watchlist in all_watchlists if watchlist.org_id == org_id]
    profile_ids = {watchlist.org_id for watchlist in all_watchlists}
    org_profiles = {profile_id: await get_org_profile(profile_id) for profile_id in profile_ids}
    updated_items: list[IntelligenceItem] = []
    matched_count = 0
    for item in all_items[:limit]:
        rematched = analyze_item(item.title, item.summary, item.source_url, all_watchlists, created_at=item.created_at, org_profiles=org_profiles)
        rematched.id = item.id
        rematched.ingested_at = item.ingested_at
        rematched.confidence_score = item.confidence_score
        rematched.confidence_factors = item.confidence_factors
        rematched.evidence_links = item.evidence_links
        rematched.evidence_summary = item.evidence_summary
        rematched.source_reliability = item.source_reliability
        rematched.source_type = item.source_type
        updated_items.append(rematched)
        if rematched.watchlist_matches:
            matched_count += 1
    await save_items(updated_items)
    await _audit("rematch_run", "intelligence_item", org_id or "all", org_id=org_id, message=f"Rematched {len(updated_items)} items; {matched_count} matched.")
    return {"ok": True, "items_checked": len(updated_items), "items_matched": matched_count, "org_id": org_id}


@router.get("/audit", dependencies=[Depends(require_api_key)])
async def audit_events(org_id: str | None = Query(default=None, min_length=1, max_length=80), action: str | None = Query(default=None, min_length=1, max_length=120), limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, object]]:
    return [asdict(event) for event in await list_admin_audit_events(limit, org_id=org_id, action=action)]


@router.get("/latest", dependencies=[Depends(require_read_api_key)])
async def latest() -> list[dict[str, object]]:
    return await _items_output(await list_items(settings.max_items))


@router.get("/items", dependencies=[Depends(require_read_api_key)])
async def items(
    q: str | None = None,
    category: str | None = None,
    risk_level: str | None = None,
    country: str | None = None,
    sector: str | None = None,
    org_id: str | None = None,
    limit: int = Query(default=60, ge=1, le=200),
) -> list[dict[str, object]]:
    results = await list_items(limit)
    if org_id:
        results = [item for item in results if _item_matches_org(item, org_id)]
    if q:
        needle = q.lower()
        results = [item for item in results if needle in f"{item.title} {item.summary} {' '.join(item.tags)}".lower()]
    if category:
        results = [item for item in results if item.category.lower() == category.lower()]
    if risk_level:
        results = [item for item in results if item.risk_level.lower() == risk_level.lower()]
    if country:
        results = [item for item in results if country.lower() in {c.lower() for c in item.affected_countries}]
    if sector:
        results = [item for item in results if sector.lower() in {s.lower() for s in item.affected_sectors}]
    return await _items_output(results)


@router.get("/items/{item_id}", dependencies=[Depends(require_read_api_key)])
async def item_detail(item_id: str) -> dict[str, object]:
    item = await get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Intelligence item not found")
    return await _item_output(item)


@router.post("/refresh", dependencies=[Depends(require_api_key)])
async def refresh() -> dict[str, object]:
    return await refresh_store(force=True)


@router.post("/seed", dependencies=[Depends(require_api_key)])
async def seed() -> dict[str, object]:
    seeded = await seed_demo_items()
    return {"ok": True, "seeded": len(seeded)}


@router.get("/public-demo-stats", dependencies=[Depends(require_read_api_key)])
async def public_demo_stats(org_id: str = Query(default=settings.default_org)) -> dict[str, object]:
    all_items = await list_items(settings.max_items)
    source_health = await list_source_health()
    watchlists = [watchlist for watchlist in await list_watchlists() if watchlist.org_id == org_id]
    org_items = [item for item in all_items if _item_matches_org(item, org_id)]
    org_alerts = [alert for alert in await list_alerts() if _alert_matches_org(alert, org_id)]
    high_critical = [item for item in all_items if item.risk_level in {"Critical", "High"}]
    return {
        "global_items": len(all_items),
        "global_high_critical": len(high_critical),
        "sources": len(source_health) or len(settings.feeds),
        "active_org": org_id,
        "org_items": len(org_items),
        "org_watchlists": len(watchlists),
        "org_alerts": len(org_alerts),
        "last_status": refresh_status(),
    }


@router.get("/sources", dependencies=[Depends(require_read_api_key)])
async def sources() -> list[dict[str, object]]:
    return [asdict(source) for source in await list_source_health()]


@router.get("/alerts", dependencies=[Depends(require_read_api_key)])
async def alerts(org_id: str | None = None) -> dict[str, object]:
    persisted = [alert for alert in await list_alerts() if _alert_matches_org(alert, org_id)]
    generated_preview = [alert for alert in generate_alerts(await list_items(settings.max_items)) if _alert_matches_org(alert, org_id)]
    return {
        "persisted": [alert_to_dict(alert) for alert in persisted],
        "generated_preview": generated_preview,
        "total_persisted": len(persisted),
        "total_generated_preview": len(generated_preview),
    }


@router.get("/alerts/flat", dependencies=[Depends(require_read_api_key)])
async def alerts_flat(org_id: str | None = None) -> list[dict[str, object]]:
    persisted = [alert for alert in await list_alerts() if _alert_matches_org(alert, org_id)]
    if persisted:
        return [alert_to_dict(alert) for alert in persisted]
    return [alert for alert in generate_alerts(await list_items(settings.max_items)) if _alert_matches_org(alert, org_id)]


@router.get("/alerts/{alert_id}", dependencies=[Depends(require_read_api_key)])
async def alert_detail(alert_id: str) -> dict[str, object]:
    alert = await get_alert(alert_id)
    if not alert:
        generated = generate_alerts(await list_items(settings.max_items))
        for candidate in generated:
            if candidate["id"] == alert_id:
                return candidate
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_to_dict(alert)


@router.post("/alerts/generate", dependencies=[Depends(require_api_key)])
async def generate_persistent_alerts(org_id: str | None = None) -> dict[str, object]:
    all_items = await list_items(settings.max_items)
    if org_id:
        all_items = [item for item in all_items if _item_matches_org(item, org_id)]
    candidates = alerts_from_items(all_items)
    result = await save_alerts_with_counts(candidates)
    await _audit("alert_generation", "alert", org_id or "all", org_id=org_id, message=f"Generated {result.created_count} alerts; {result.existing_count} already existed.")
    return {
        "ok": True,
        "created": result.created_count,
        "existing": result.existing_count,
        "created_alerts": [alert_to_dict(alert) for alert in result.created_alerts],
        "alerts": [alert_to_dict(alert) for alert in result.all_alerts],
    }


@router.patch("/alerts/{alert_id}", dependencies=[Depends(require_api_key)])
async def patch_alert(alert_id: str, payload: AlertUpdate) -> dict[str, object]:
    before = await get_alert(alert_id)
    if not before:
        raise HTTPException(status_code=404, detail="Alert not found")
    before_values = {field: getattr(before, field) for field in ["status", "owner", "notes", "resolution_summary", "severity_override"]}
    alert = await update_alert(
        alert_id,
        status=payload.status,
        notes=payload.notes,
        owner=payload.owner,
        due_at=payload.due_at,
        severity_override=payload.severity_override,
        resolution_summary=payload.resolution_summary,
        updated_at=now_iso(),
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    event_map = {
        "status": "status_changed",
        "owner": "owner_changed",
        "notes": "notes_updated",
        "resolution_summary": "resolution_updated",
        "severity_override": "severity_override_changed",
    }
    changed_fields = []
    for field, event_type in event_map.items():
        new_value = getattr(payload, field)
        if new_value is not None and before_values.get(field) != new_value:
            changed_fields.append(field)
            await add_alert_event(AlertEvent(id=str(uuid.uuid4()), alert_id=alert_id, event_type=event_type, message=f"{field} updated", created_at=now_iso()))
    if changed_fields:
        await _audit("alert_patch", "alert", alert_id, org_id=alert.org_id, message=f"Updated alert fields: {', '.join(changed_fields)}")
    return alert_to_dict(alert)


@router.get("/alerts/{alert_id}/events", dependencies=[Depends(require_read_api_key)])
async def alert_events(alert_id: str) -> list[dict[str, object]]:
    if not await get_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    return [asdict(event) for event in await list_alert_events(alert_id)]


@router.post("/alerts/{alert_id}/telegram-preview", dependencies=[Depends(require_api_key)])
async def telegram_preview(alert_id: str) -> dict[str, object]:
    alert = await get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"message": format_alert_for_telegram(alert)}


@router.post("/demo/reset", dependencies=[Depends(require_api_key)])
async def demo_reset() -> dict[str, object]:
    if database_enabled():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Demo reset is disabled in database mode.")
    await reset_memory_state()
    return {"ok": True, "detail": "Demo memory state reset."}


@router.get("/brief/daily", dependencies=[Depends(require_read_api_key)])
async def daily_brief(org_id: str | None = None) -> dict[str, object]:
    all_items = await list_items(settings.max_items)
    if org_id:
        all_items = [item for item in all_items if _item_matches_org(item, org_id)]
    return generate_daily_brief(all_items, await list_source_health())

@router.get("/cves", dependencies=[Depends(require_read_api_key)])
async def cves(limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, object]]:
    return [asdict(record) for record in await list_cve_enrichments(limit)]


@router.get("/cves/{cve_id}", dependencies=[Depends(require_read_api_key)])
async def cve_detail(cve_id: str) -> dict[str, object]:
    record = await get_cve_enrichment(cve_id.upper())
    if not record:
        raise HTTPException(status_code=404, detail="CVE enrichment not found")
    return asdict(record)


@router.post("/cves/enrich", dependencies=[Depends(require_api_key)])
async def enrich_cves() -> dict[str, object]:
    records = build_cve_enrichments(await list_items(settings.max_items))
    for record in records:
        await save_cve_enrichment(record)
    await _audit("cve_enrichment", "cve_enrichment", "all", message=f"Enriched {len(records)} CVEs from current items.")
    return {"ok": True, "enriched": len(records), "cves": [record.cve_id for record in records]}


@router.post("/graph/rebuild", dependencies=[Depends(require_api_key)])
async def rebuild_graph() -> dict[str, object]:
    entities, edges = build_graph(await list_items(settings.max_items), await list_watchlists(), await list_alerts(), await list_source_health())
    await replace_intel_graph(entities, edges)
    await _audit("graph_rebuild", "intel_graph", "all", message=f"Rebuilt graph with {len(entities)} entities and {len(edges)} edges.")
    return {"ok": True, "entities": len(entities), "edges": len(edges)}


@router.get("/graph/entities", dependencies=[Depends(require_read_api_key)])
async def graph_entities(entity_type: str | None = None, limit: int = Query(default=500, ge=1, le=2000)) -> list[dict[str, object]]:
    return [asdict(entity) for entity in await list_intel_entities(limit, entity_type=entity_type)]


@router.get("/graph/edges", dependencies=[Depends(require_read_api_key)])
async def graph_edges(limit: int = Query(default=1000, ge=1, le=3000)) -> list[dict[str, object]]:
    return [asdict(edge) for edge in await list_intel_edges(limit)]


@router.get("/graph/entity/{entity_id}", dependencies=[Depends(require_read_api_key)])
async def graph_entity(entity_id: str) -> dict[str, object]:
    entity = await get_intel_entity(entity_id)
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    edges = [edge for edge in await list_intel_edges(limit=3000) if entity_id in {edge.source_entity_id, edge.target_entity_id}]
    return {"entity": asdict(entity), "edges": [asdict(edge) for edge in edges]}


@router.post("/clusters/rebuild", dependencies=[Depends(require_api_key)])
async def rebuild_clusters() -> dict[str, object]:
    all_items = await list_items(settings.max_items)
    clusters = build_clusters(all_items)
    await replace_intel_clusters(clusters)
    changed = apply_cluster_confidence(all_items, clusters)
    if changed:
        await save_items(changed)
    await _audit("cluster_rebuild", "intel_cluster", "all", message=f"Rebuilt {len(clusters)} incident clusters.")
    return {"ok": True, "clusters": len(clusters), "confidence_updated": len(changed)}


@router.get("/clusters", dependencies=[Depends(require_read_api_key)])
async def clusters(limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, object]]:
    return [asdict(cluster) for cluster in await list_intel_clusters(limit)]


@router.get("/clusters/{cluster_id}", dependencies=[Depends(require_read_api_key)])
async def cluster_detail(cluster_id: str) -> dict[str, object]:
    cluster = await get_intel_cluster(cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")
    items_by_id = {item.id: item for item in await list_items(settings.max_items)}
    return {"cluster": asdict(cluster), "items": [item_to_dict(items_by_id[item_id]) for item_id in cluster.item_ids if item_id in items_by_id]}


@router.post("/review/generate", dependencies=[Depends(require_api_key)])
async def generate_review_queue() -> dict[str, object]:
    enrichments = await _enrichment_map()
    reviews = generate_review_items(await list_items(settings.max_items), enrichments, await list_intel_clusters(limit=1000), await list_item_feedback(limit=1000))
    existing = {review.id for review in await list_review_queue(limit=5000)}
    created = 0
    for review in reviews:
        if review.id not in existing:
            created += 1
        await save_review_queue_item(review)
    await _audit("review_generate", "review_queue", "all", message=f"Generated {created} new review items.")
    return {"ok": True, "created": created, "total_candidates": len(reviews)}


@router.get("/review", dependencies=[Depends(require_read_api_key)])
async def review_queue(status_filter: str | None = Query(default=None, alias="status"), limit: int = Query(default=200, ge=1, le=500)) -> list[dict[str, object]]:
    return [asdict(item) for item in await list_review_queue(limit=limit, status=status_filter)]


@router.patch("/review/{review_id}", dependencies=[Depends(require_api_key)])
async def patch_review(review_id: str, payload: dict[str, object]) -> dict[str, object]:
    status_value = payload.get("status") if isinstance(payload, dict) else None
    priority_value = payload.get("priority") if isinstance(payload, dict) else None
    allowed_status = {"pending", "reviewed", "dismissed", "escalated"}
    allowed_priority = {"low", "medium", "high", "urgent"}
    if status_value is not None and status_value not in allowed_status:
        raise HTTPException(status_code=422, detail="Invalid review status")
    if priority_value is not None and priority_value not in allowed_priority:
        raise HTTPException(status_code=422, detail="Invalid review priority")
    review = await update_review_queue_item(review_id, status=status_value, priority=priority_value, reason=payload.get("reason") if isinstance(payload.get("reason"), str) else None, updated_at=now_iso())
    if not review:
        raise HTTPException(status_code=404, detail="Review item not found")
    await _audit("review_patch", "review_queue", review_id, org_id=review.org_id, message=f"Review status is {review.status}.")
    return asdict(review)


@router.get("/intelligence-maturity", dependencies=[Depends(require_read_api_key)])
async def intelligence_maturity() -> dict[str, object]:
    entities = await list_intel_entities(limit=1)
    edges = await list_intel_edges(limit=1)
    clusters_ = await list_intel_clusters(limit=1)
    reviews = await list_review_queue(limit=1)
    cves_ = await list_cve_enrichments(limit=1)
    return maturity_score({
        "sources": len(await list_source_health()),
        "cves": len(cves_),
        "entities": len(entities),
        "edges": len(edges),
        "clusters": len(clusters_),
        "reviews": len(reviews),
        "watchlists": len(await list_watchlists()),
        "alerts": len(await list_alerts()),
        "database": database_enabled(),
        "api_key": bool(settings.api_key.strip()),
        "protect_reads": bool(settings.protect_reads),
    })


@router.get("/stats", dependencies=[Depends(require_read_api_key)])
async def stats() -> dict[str, object]:
    all_items = await list_items(settings.max_items)
    categories = Counter(item.category for item in all_items)
    risks = Counter(item.risk_level for item in all_items)
    countries = Counter(country for item in all_items for country in item.affected_countries)
    sectors = Counter(sector for item in all_items for sector in item.affected_sectors)
    average_risk = round(sum(item.risk_score for item in all_items) / len(all_items), 1) if all_items else 0
    return {
        "total_items": len(all_items),
        "average_risk_score": average_risk,
        "by_category": dict(categories),
        "by_risk_level": dict(risks),
        "top_countries": countries.most_common(8),
        "top_sectors": sectors.most_common(8),
    }


@router.get("/summary", dependencies=[Depends(require_read_api_key)])
async def summary() -> dict[str, object]:
    all_items = await list_items(settings.max_items)
    high_priority = [item for item in all_items if item.risk_level in {"Critical", "High"}]
    return {
        "headline": f"{len(high_priority)} high-priority items across {len(all_items)} total intelligence items.",
        "critical_or_high": len(high_priority),
        "top_items": [item_to_dict(item) for item in high_priority[:5]],
        "recommended_focus": [item.recommended_action for item in high_priority[:3]],
    }


ONBOARDING_TEMPLATES: dict[str, dict[str, object]] = {
    "school": {"suggested_sectors": ["education", "government"], "suggested_countries": ["USA"], "suggested_keywords": ["ransomware", "student data", "phishing"], "suggested_cves": [], "suggested_threat_actors": [], "explanation": "Schools should prioritize ransomware, data exposure, and public-sector dependencies."},
    "NGO": {"suggested_sectors": ["government", "logistics"], "suggested_countries": ["Ukraine", "USA"], "suggested_keywords": ["sanctions", "aid", "disinformation", "phishing"], "suggested_cves": [], "suggested_threat_actors": [], "explanation": "NGOs often face geopolitical targeting, disinformation, and credential attacks."},
    "logistics": {"suggested_sectors": ["logistics", "energy"], "suggested_countries": ["USA", "Ukraine"], "suggested_keywords": ["supply chain", "port", "rail", "ransomware"], "suggested_cves": [], "suggested_threat_actors": [], "explanation": "Logistics operators need disruption, route, port, rail, and ransomware monitoring."},
    "bank": {"suggested_sectors": ["finance"], "suggested_countries": ["USA", "United Kingdom"], "suggested_keywords": ["banking trojan", "credential", "fraud", "sanctions"], "suggested_cves": [], "suggested_threat_actors": [], "explanation": "Banks should track financial malware, credential theft, fraud, and sanctions exposure."},
    "energy": {"suggested_sectors": ["energy", "government"], "suggested_countries": ["USA", "Ukraine"], "suggested_keywords": ["ICS", "grid", "pipeline", "drone", "ransomware"], "suggested_cves": [], "suggested_threat_actors": [], "explanation": "Energy organizations need ICS, grid, pipeline, and conflict spillover monitoring."},
    "telecom": {"suggested_sectors": ["telecom", "government"], "suggested_countries": ["USA", "Taiwan"], "suggested_keywords": ["DDoS", "router", "espionage", "outage"], "suggested_cves": [], "suggested_threat_actors": [], "explanation": "Telecoms should track outages, network exploitation, DDoS, and espionage indicators."},
    "government": {"suggested_sectors": ["government", "energy", "telecom"], "suggested_countries": ["USA", "Ukraine", "Taiwan"], "suggested_keywords": ["espionage", "election", "sanctions", "critical infrastructure"], "suggested_cves": [], "suggested_threat_actors": [], "explanation": "Government teams need cyber, election, sanctions, and critical infrastructure monitoring."},
}


@router.get("/onboarding/template", dependencies=[Depends(require_read_api_key)])
async def onboarding_template() -> dict[str, object]:
    return {"templates": ONBOARDING_TEMPLATES}


async def build_value_report(org_id: str | None, days: int) -> dict[str, object]:
    items = [item for item in await list_items(settings.max_items) if _item_matches_org(item, org_id)]
    alerts_for_org = [alert for alert in await list_alerts() if _alert_matches_org(alert, org_id)]
    countries = Counter(country for item in items for country in item.affected_countries)
    sectors = Counter(sector for item in items for sector in item.affected_sectors)
    watchlists = Counter(alert.matched_watchlist_name for alert in alerts_for_org)
    failures = [asdict(source) for source in await list_source_health() if source.status == "failing"]
    unresolved = [a for a in alerts_for_org if a.status not in {"resolved", "false_positive"}]
    critical_alerts = [a for a in alerts_for_org if (a.severity_override or a.risk_level) == "Critical"]
    high_alerts = [a for a in alerts_for_org if (a.severity_override or a.risk_level) == "High"]
    avg = round(sum(item.risk_score for item in items) / len(items), 1) if items else 0
    actions = []
    if not await list_watchlists():
        actions.append("Add a customer watchlist to focus monitoring.")
    if unresolved:
        actions.append("Assign owners and due dates to unresolved alerts.")
    if failures:
        actions.append("Fix failing sources or add replacement feeds.")
    if not actions:
        actions.append("Review resolved alerts with the customer and refine scoring profile.")
    return {
        "org_id": org_id,
        "period_days": days,
        "total_items_monitored": len(items),
        "total_alerts": len(alerts_for_org),
        "critical_alerts": len(critical_alerts),
        "high_alerts": len(high_alerts),
        "unresolved_alerts": len(unresolved),
        "resolved_alerts": len([a for a in alerts_for_org if a.status in {"resolved", "false_positive"}]),
        "average_risk_score": avg,
        "top_countries": countries.most_common(5),
        "top_sectors": sectors.most_common(5),
        "top_watchlists": watchlists.most_common(5),
        "source_failures": failures,
        "recommended_next_actions": actions,
    }


@router.get("/reports/value", dependencies=[Depends(require_read_api_key)])
async def value_report(org_id: str | None = None, days: int = Query(default=7, ge=1, le=90)) -> dict[str, object]:
    return await build_value_report(org_id, days)


def _csv_response(filename: str, rows: list[dict[str, object]]) -> Response:
    buffer = io.StringIO()
    fieldnames = list(rows[0].keys()) if rows else ["empty"]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: (value if not isinstance(value, (list, dict)) else str(value)) for key, value in row.items()})
    return Response(content=buffer.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


@router.get("/reports/customer-proof", dependencies=[Depends(require_read_api_key)])
async def customer_proof_report(org_id: str = Query(..., min_length=1), days: int = Query(default=7, ge=1, le=90)) -> dict[str, object]:
    items = [item for item in await list_items(settings.max_items) if _item_matches_org(item, org_id)]
    alerts_for_org = [alert for alert in await list_alerts() if _alert_matches_org(alert, org_id)]
    watchlists = [watchlist for watchlist in await list_watchlists() if watchlist.org_id == org_id]
    sources = await list_source_health()
    top_risks = [item.title for item in sorted(items, key=lambda item: (item.risk_score, item.ingested_at), reverse=True)[:3]]
    actions = []
    for item in sorted(items, key=lambda item: (item.risk_score, item.ingested_at), reverse=True):
        if item.recommended_action and item.recommended_action not in actions:
            actions.append(item.recommended_action)
        if len(actions) == 3:
            break
    open_alerts = [alert for alert in alerts_for_org if alert.status not in {"resolved", "false_positive"}]
    resolved_alerts = [alert for alert in alerts_for_org if alert.status in {"resolved", "false_positive"}]
    health = Counter(source.status for source in sources)
    source_summary = {"total_sources": len(sources) or len(settings.feeds), "healthy": health.get("healthy", 0), "failing": health.get("failing", 0), "empty": health.get("empty", 0), "pending": health.get("pending", 0)}
    cves_tracked_values = sorted({cve for item in items for cve in item_cves(item)})
    enriched_cves_count = len(await list_cve_enrichments(limit=1000))
    clusters_for_items = [cluster for cluster in await list_intel_clusters(limit=1000) if any(item_id in {item.id for item in items} for item_id in cluster.item_ids)]
    review_items = await list_review_queue(limit=1000)
    false_positive_feedback_count = len(await list_item_feedback(limit=1000, org_id=org_id, relevance="false_positive"))
    maturity = await intelligence_maturity()
    clustered_item_count = len({item_id for cluster in clusters_for_items for item_id in cluster.item_ids})
    proof_summary = (
        f"POLARIS monitored {len(items)} risk signals, enriched {enriched_cves_count} CVEs, "
        f"grouped {clustered_item_count} items into {len(clusters_for_items)} incident clusters, "
        f"and generated {len(review_items)} review items for your organization."
    )
    return {
        "org_id": org_id,
        "period_days": days,
        "items_monitored": len(items),
        "watchlists_count": len(watchlists),
        "alerts_generated": len(alerts_for_org),
        "alerts_open": len(open_alerts),
        "alerts_resolved": len(resolved_alerts),
        "top_3_risks": top_risks,
        "top_3_recommended_actions": actions,
        "source_health_summary": source_summary,
        "cves_tracked": len(cves_tracked_values),
        "enriched_cves": enriched_cves_count,
        "clusters_detected": len(clusters_for_items),
        "multi_source_clusters": len([cluster for cluster in clusters_for_items if cluster.corroboration_level in {"multi_source", "strong"}]),
        "review_items_created": len(review_items),
        "false_positive_feedback_count": false_positive_feedback_count,
        "intelligence_maturity_score": maturity["score"],
        "proof_summary": proof_summary,
    }


@router.post("/feedback/item/{item_id}", dependencies=[Depends(require_api_key)], status_code=status.HTTP_201_CREATED)
async def create_item_feedback(item_id: str, payload: ItemFeedbackCreate) -> dict[str, object]:
    feedback = ItemFeedback(
        id=str(uuid.uuid4()),
        item_id=item_id,
        relevance=payload.relevance,
        severity_feedback=payload.severity_feedback,
        org_id=payload.org_id.strip(),
        comment=payload.comment.strip(),
        created_at=now_iso(),
    )
    if not await get_item(item_id):
        raise HTTPException(status_code=404, detail="Intelligence item not found")
    saved = await add_item_feedback(feedback)
    await _audit("feedback_creation", "item_feedback", saved.id, org_id=saved.org_id, message=f"Feedback created for item {item_id}.")
    return {"ok": True, "feedback_id": saved.id, "item_id": saved.item_id}


@router.get("/feedback", dependencies=[Depends(require_api_key)])
async def feedback(
    org_id: str | None = Query(default=None, min_length=1, max_length=80),
    item_id: str | None = Query(default=None, min_length=1, max_length=200),
    relevance: str | None = Query(default=None, pattern="^(useful|not_useful|false_positive)$"),
    limit: int = Query(default=200, ge=1, le=500),
) -> list[dict[str, object]]:
    return [asdict(item) for item in await list_item_feedback(limit, org_id=org_id, item_id=item_id, relevance=relevance)]


@router.get("/export/alerts.csv", dependencies=[Depends(require_read_api_key)])
async def export_alerts_csv(org_id: str | None = None) -> Response:
    rows = [alert_to_dict(alert) for alert in await list_alerts() if _alert_matches_org(alert, org_id)]
    return _csv_response("alerts.csv", rows)


@router.get("/export/value-report.csv", dependencies=[Depends(require_read_api_key)])
async def export_value_report_csv(org_id: str | None = None, days: int = Query(default=7, ge=1, le=90)) -> Response:
    report = await build_value_report(org_id, days)
    return _csv_response("value-report.csv", [report])


@router.post("/alerts/{alert_id}/telegram-send", dependencies=[Depends(require_api_key)])
async def telegram_send(alert_id: str) -> dict[str, object]:
    alert = await get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        await add_alert_event(AlertEvent(id=str(uuid.uuid4()), alert_id=alert_id, event_type="telegram_failed", message="Telegram credentials missing", created_at=now_iso()))
        await _audit("telegram_send_attempt", "alert", alert_id, org_id=alert.org_id, message="Telegram send attempted but credentials were missing.")
        raise HTTPException(status_code=400, detail="TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be configured to send Telegram alerts.")
    import httpx
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage",
                json={"chat_id": settings.telegram_chat_id, "text": format_alert_for_telegram(alert)},
                timeout=settings.http_timeout,
            )
            response.raise_for_status()
        logger.info("Telegram alert sent alert_id=%s", alert_id)
        await add_alert_event(AlertEvent(id=str(uuid.uuid4()), alert_id=alert_id, event_type="telegram_sent", message="Telegram alert sent", created_at=now_iso()))
        await _audit("telegram_send_attempt", "alert", alert_id, org_id=alert.org_id, message="Telegram alert sent.")
        return {"ok": True, "detail": "Telegram alert sent."}
    except Exception as exc:
        logger.warning("Telegram alert failed alert_id=%s error_type=%s message=%s", alert_id, type(exc).__name__, str(exc))
        await add_alert_event(AlertEvent(id=str(uuid.uuid4()), alert_id=alert_id, event_type="telegram_failed", message=f"Telegram send failed: {type(exc).__name__}", created_at=now_iso()))
        await _audit("telegram_send_attempt", "alert", alert_id, org_id=alert.org_id, message=f"Telegram send failed: {type(exc).__name__}.")
        raise HTTPException(status_code=502, detail="Telegram send failed.") from exc


@router.get("/source-configs", dependencies=[Depends(require_read_api_key)])
async def source_configs() -> list[dict[str, object]]:
    return [asdict(source) for source in await list_source_configs()]


@router.post("/source-configs", dependencies=[Depends(require_api_key)], status_code=201)
async def create_source_config(payload: SourceConfigCreate) -> dict[str, object]:
    source = SourceConfig(id=str(uuid.uuid4()), url=payload.url.strip(), label=payload.label.strip(), category=payload.category, enabled=payload.enabled, created_at=now_iso())
    saved = await add_source_config(source)
    await _audit("source_config_create", "source_config", saved.id, message=f"Created source config {saved.label}.")
    return asdict(saved)


@router.patch("/source-configs/{source_id}", dependencies=[Depends(require_api_key)])
async def patch_source_config(source_id: str, payload: SourceConfigUpdate) -> dict[str, object]:
    source = await update_source_config(source_id, url=payload.url.strip() if payload.url else None, label=payload.label.strip() if payload.label else None, category=payload.category, enabled=payload.enabled)
    if not source:
        raise HTTPException(status_code=404, detail="Source config not found")
    await _audit("source_config_update", "source_config", source.id, message=f"Updated source config {source.label}.")
    return asdict(source)


@router.delete("/source-configs/{source_id}", dependencies=[Depends(require_api_key)], status_code=204)
async def remove_source_config(source_id: str) -> Response:
    if not await delete_source_config(source_id):
        raise HTTPException(status_code=404, detail="Source config not found")
    await _audit("source_config_delete", "source_config", source_id, message="Deleted source config.")
    return Response(status_code=204)


@router.get("/org-profile", dependencies=[Depends(require_read_api_key)])
async def org_profile(org_id: str = Query(default=settings.default_org)) -> dict[str, object]:
    return asdict(await get_org_profile(org_id))


@router.put("/org-profile", dependencies=[Depends(require_api_key)])
async def save_org_profile(payload: OrgScoringProfileIn, org_id: str = Query(default=settings.default_org)) -> dict[str, object]:
    clean = lambda values: [value.strip() for value in values if value.strip()]
    profile = OrgScoringProfile(org_id=org_id, high_priority_countries=clean(payload.high_priority_countries), high_priority_sectors=clean(payload.high_priority_sectors), risk_boost_keywords=clean(payload.risk_boost_keywords), risk_reduce_keywords=clean(payload.risk_reduce_keywords))
    return asdict(await put_org_profile(profile))
