from __future__ import annotations

import asyncio
import csv
import io
import logging
import uuid
from collections import Counter
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from ..auth import require_api_key, require_read_api_key
from ..config import settings
from ..database import add_alert_event, add_pilot_lead, add_source_config, database_enabled, delete_source_config, get_alert, get_item, get_org_profile, get_public_metrics, increment_public_metric, list_alert_events, list_alerts, list_items, list_pilot_leads, list_source_configs, list_source_health, list_watchlists, put_org_profile, reset_memory_state, save_alerts_with_counts, update_alert, update_pilot_lead_status, update_source_config
from ..models import Alert, AlertEvent, IntelligenceItem, OrgScoringProfile, PilotLead, SourceConfig
from ..schemas import AlertUpdate, OrgScoringProfileIn, PilotLeadCreate, PilotLeadUpdate, SourceConfigCreate, SourceConfigUpdate
from ..services.analysis import now_iso
from ..services.briefing import alert_to_dict, alerts_from_items, format_alert_for_telegram, generate_alerts, generate_daily_brief
from ..services.ingestion import item_to_dict, refresh_status, refresh_store, seed_demo_items

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")


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




@router.post("/leads", status_code=status.HTTP_201_CREATED)
async def create_lead(payload: PilotLeadCreate) -> dict[str, object]:
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
    return asdict(saved)


@router.get("/leads", dependencies=[Depends(require_api_key)])
async def leads(limit: int = Query(default=50, ge=1, le=200)) -> list[dict[str, object]]:
    return [asdict(lead) for lead in await list_pilot_leads(limit)]


@router.patch("/leads/{lead_id}", dependencies=[Depends(require_api_key)])
async def patch_lead(lead_id: str, payload: PilotLeadUpdate) -> dict[str, object]:
    lead = await update_pilot_lead_status(lead_id, payload.status)
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")
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


@router.get("/latest", dependencies=[Depends(require_read_api_key)])
async def latest() -> list[dict[str, object]]:
    return [item_to_dict(item) for item in await list_items(settings.max_items)]


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
    return [item_to_dict(item) for item in results]


@router.get("/items/{item_id}", dependencies=[Depends(require_read_api_key)])
async def item_detail(item_id: str) -> dict[str, object]:
    item = await get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Intelligence item not found")
    return item_to_dict(item)


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
    for field, event_type in event_map.items():
        new_value = getattr(payload, field)
        if new_value is not None and before_values.get(field) != new_value:
            await add_alert_event(AlertEvent(id=str(uuid.uuid4()), alert_id=alert_id, event_type=event_type, message=f"{field} updated", created_at=now_iso()))
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
        return {"ok": True, "detail": "Telegram alert sent."}
    except Exception as exc:
        logger.warning("Telegram alert failed alert_id=%s error_type=%s message=%s", alert_id, type(exc).__name__, str(exc))
        await add_alert_event(AlertEvent(id=str(uuid.uuid4()), alert_id=alert_id, event_type="telegram_failed", message=f"Telegram send failed: {type(exc).__name__}", created_at=now_iso()))
        raise HTTPException(status_code=502, detail="Telegram send failed.") from exc


@router.get("/source-configs", dependencies=[Depends(require_read_api_key)])
async def source_configs() -> list[dict[str, object]]:
    return [asdict(source) for source in await list_source_configs()]


@router.post("/source-configs", dependencies=[Depends(require_api_key)], status_code=201)
async def create_source_config(payload: SourceConfigCreate) -> dict[str, object]:
    source = SourceConfig(id=str(uuid.uuid4()), url=payload.url.strip(), label=payload.label.strip(), category=payload.category, enabled=payload.enabled, created_at=now_iso())
    return asdict(await add_source_config(source))


@router.patch("/source-configs/{source_id}", dependencies=[Depends(require_api_key)])
async def patch_source_config(source_id: str, payload: SourceConfigUpdate) -> dict[str, object]:
    source = await update_source_config(source_id, url=payload.url.strip() if payload.url else None, label=payload.label.strip() if payload.label else None, category=payload.category, enabled=payload.enabled)
    if not source:
        raise HTTPException(status_code=404, detail="Source config not found")
    return asdict(source)


@router.delete("/source-configs/{source_id}", dependencies=[Depends(require_api_key)], status_code=204)
async def remove_source_config(source_id: str) -> Response:
    if not await delete_source_config(source_id):
        raise HTTPException(status_code=404, detail="Source config not found")
    return Response(status_code=204)


@router.get("/org-profile", dependencies=[Depends(require_read_api_key)])
async def org_profile(org_id: str = Query(default=settings.default_org)) -> dict[str, object]:
    return asdict(await get_org_profile(org_id))


@router.put("/org-profile", dependencies=[Depends(require_api_key)])
async def save_org_profile(payload: OrgScoringProfileIn, org_id: str = Query(default=settings.default_org)) -> dict[str, object]:
    clean = lambda values: [value.strip() for value in values if value.strip()]
    profile = OrgScoringProfile(org_id=org_id, high_priority_countries=clean(payload.high_priority_countries), high_priority_sectors=clean(payload.high_priority_sectors), risk_boost_keywords=clean(payload.risk_boost_keywords), risk_reduce_keywords=clean(payload.risk_reduce_keywords))
    return asdict(await put_org_profile(profile))
