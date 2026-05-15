from __future__ import annotations

from fastapi import APIRouter, Response

from ..config import settings
from ..database import database_enabled, list_alerts, list_items, list_source_health
from ..services.ingestion import refresh_status

router = APIRouter()


@router.head("/health", include_in_schema=False)
async def health_head() -> Response:
    return Response(status_code=200)


@router.get("/health")
async def health() -> dict[str, object]:
    items = await list_items(settings.max_items)
    alerts = await list_alerts()
    sources = await list_source_health()
    db_enabled = database_enabled()
    return {
        "ok": True,
        "app": settings.app_name,
        "version": settings.app_version,
        "mode": "database" if db_enabled else "demo-memory",
        "database": db_enabled,
        "api_key_configured": bool(settings.api_key),
        "read_protection_enabled": settings.protect_reads,
        "default_org": settings.default_org,
        "feeds": len(settings.feeds),
        "items": len(items),
        "alerts": len(alerts),
        "sources": len(sources),
        "last_status": refresh_status(),
    }
