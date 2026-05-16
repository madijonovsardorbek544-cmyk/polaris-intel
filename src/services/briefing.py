from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import asdict
from typing import Any

from ..models import Alert, IntelligenceItem, SourceHealth
from .analysis import now_iso
from .ingestion import item_to_dict


def generate_alerts(items: list[IntelligenceItem]) -> list[dict[str, object]]:
    alerts: list[dict[str, object]] = []
    for item in items:
        if item.risk_level not in {"Critical", "High"} or not item.watchlist_matches:
            continue
        by_watchlist = {}
        for match in item.watchlist_matches:
            by_watchlist.setdefault((match.watchlist_id, match.org_id), []).append(match)
        for (watchlist_id, _org_id), matches in by_watchlist.items():
            match = matches[0]
            reasons = "; ".join(dict.fromkeys(candidate.reason for candidate in matches))
            alert_id = uuid.uuid5(uuid.NAMESPACE_URL, f"{item.id}|{watchlist_id}").hex
            created_at = item.ingested_at or now_iso()
            alerts.append(
                {
                    "id": alert_id,
                    "item_id": item.id,
                    "title": item.title,
                    "risk_level": item.risk_level,
                    "matched_watchlist_id": match.watchlist_id,
                    "matched_watchlist_name": match.watchlist_name,
                    "matched_watchlist": match.watchlist_name,
                    "reason": reasons,
                    "recommended_action": item.recommended_action,
                    "status": "open",
                    "created_at": created_at,
                    "updated_at": created_at,
                    "notes": None,
                    "org_id": match.org_id,
                    "owner": None,
                    "due_at": None,
                    "severity_override": None,
                    "resolution_summary": None,
                }
            )
    return alerts


def alerts_from_items(items: list[IntelligenceItem]) -> list[Alert]:
    return [
        Alert(
            id=str(raw["id"]),
            item_id=str(raw["item_id"]),
            title=str(raw["title"]),
            risk_level=str(raw["risk_level"]),
            matched_watchlist_id=str(raw["matched_watchlist_id"]),
            matched_watchlist_name=str(raw["matched_watchlist_name"]),
            reason=str(raw["reason"]),
            recommended_action=str(raw["recommended_action"]),
            status=str(raw.get("status") or "open"),
            created_at=str(raw["created_at"]),
            updated_at=str(raw["updated_at"]),
            notes=raw.get("notes") if raw.get("notes") is None else str(raw.get("notes")),
            org_id=str(raw.get("org_id") or "demo"),
            owner=raw.get("owner") if raw.get("owner") is None else str(raw.get("owner")),
            due_at=raw.get("due_at") if raw.get("due_at") is None else str(raw.get("due_at")),
            severity_override=raw.get("severity_override") if raw.get("severity_override") is None else str(raw.get("severity_override")),
            resolution_summary=raw.get("resolution_summary") if raw.get("resolution_summary") is None else str(raw.get("resolution_summary")),
        )
        for raw in generate_alerts(items)
    ]


def alert_to_dict(alert: Alert) -> dict[str, Any]:
    payload = asdict(alert)
    payload["matched_watchlist"] = alert.matched_watchlist_name
    return payload


def format_alert_for_telegram(alert: Alert | dict[str, Any]) -> str:
    data = alert_to_dict(alert) if isinstance(alert, Alert) else alert
    return "\n".join(
        [
            f"POLARIS Alert [{data.get('risk_level', 'Unknown')}]",
            str(data.get("title") or "Untitled intelligence item"),
            f"Watchlist: {data.get('matched_watchlist_name') or data.get('matched_watchlist') or 'Unknown'}",
            f"Reason: {data.get('reason') or 'No reason provided'}",
            f"Action: {data.get('recommended_action') or 'Review and triage.'}",
            f"Source/Item: {data.get('item_id') or 'unknown'}",
        ]
    )


def generate_daily_brief(items: list[IntelligenceItem], sources: list[SourceHealth]) -> dict[str, object]:
    top_risks = sorted(items, key=lambda item: (item.risk_score, item.ingested_at), reverse=True)[:5]
    countries = Counter(country for item in items for country in item.affected_countries)
    sectors = Counter(sector for item in items for sector in item.affected_sectors)
    failures = [asdict(source) for source in sources if source.status == "failing"]
    empty_sources = [asdict(source) for source in sources if source.status == "empty"]
    critical_or_high = [item for item in items if item.risk_level in {"Critical", "High"}]
    actions = list(dict.fromkeys(item.recommended_action for item in critical_or_high[:5]))
    headline = (
        f"{len(critical_or_high)} Critical/High risks across {len(items)} tracked items; "
        f"top exposure: {countries.most_common(1)[0][0] if countries else 'no country concentration'} / "
        f"{sectors.most_common(1)[0][0] if sectors else 'no sector concentration'}."
    )
    return {
        "headline_summary": headline,
        "top_5_risks": [item_to_dict(item) for item in top_risks],
        "countries_affected": countries.most_common(10),
        "sectors_affected": sectors.most_common(10),
        "recommended_actions": actions or ["Seed or ingest intelligence, then review items matching your watchlists."],
        "source_failures": failures,
        "empty_sources": empty_sources,
    }
