from __future__ import annotations

from fastapi import APIRouter

from ..config import settings
from ..database import database_enabled, list_items
from ..services.ingestion import refresh_status

router = APIRouter()


@router.get("/health")
async def health() -> dict[str, object]:
    items = await list_items(settings.max_items)
    return {
        "ok": True,
        "app": settings.app_name,
        "version": settings.app_version,
        "items": len(items),
        "last_status": refresh_status(),
        "feeds": len(settings.feeds),
        "database": database_enabled(),
        "mode": "database" if database_enabled() else "demo-memory",
    }
