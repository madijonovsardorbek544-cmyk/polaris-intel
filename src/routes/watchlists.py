from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status

from ..auth import require_api_key, require_read_api_key
from ..config import settings
from ..database import add_admin_audit_event, add_watchlist, delete_watchlist, get_watchlist, list_watchlists, update_watchlist
from ..models import AdminAuditEvent, Watchlist
from ..schemas import WatchlistCreate, WatchlistOut
from ..services.analysis import now_iso

router = APIRouter(prefix="/api/watchlists")


async def _audit(action: str, watchlist: Watchlist | None = None, *, watchlist_id: str | None = None) -> None:
    resource_id = watchlist.id if watchlist else (watchlist_id or "unknown")
    org_id = watchlist.org_id if watchlist else None
    name = watchlist.name if watchlist else resource_id
    await add_admin_audit_event(AdminAuditEvent(id=str(uuid.uuid4()), action=action, resource_type="watchlist", resource_id=resource_id, org_id=org_id, message=f"Watchlist {name} {action.replace('watchlist_', '')}.", created_at=now_iso()))


def _clean(values: list[str]) -> list[str]:
    return [value.strip() for value in values if value.strip()]


def _from_payload(payload: WatchlistCreate, *, watchlist_id: str, created_at: str) -> Watchlist:
    return Watchlist(
        id=watchlist_id,
        name=payload.name.strip(),
        org_id=payload.org_id.strip() or settings.default_org,
        countries=_clean(payload.countries),
        sectors=_clean(payload.sectors),
        organizations=_clean(payload.organizations),
        keywords=_clean(payload.keywords),
        cves=[value.strip().upper() for value in payload.cves if value.strip()],
        threat_actors=_clean(payload.threat_actors),
        created_at=created_at,
    )


@router.post("", response_model=WatchlistOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_api_key)])
async def create_watchlist(payload: WatchlistCreate) -> Watchlist:
    watchlist = _from_payload(payload, watchlist_id=str(uuid.uuid4()), created_at=now_iso())
    saved = await add_watchlist(watchlist)
    await _audit("watchlist_create", saved)
    return saved


@router.get("", response_model=list[WatchlistOut], dependencies=[Depends(require_read_api_key)])
async def get_watchlists(org_id: str | None = None) -> list[Watchlist]:
    watchlists = await list_watchlists()
    if org_id:
        watchlists = [watchlist for watchlist in watchlists if watchlist.org_id == org_id]
    return watchlists


@router.get("/{watchlist_id}", response_model=WatchlistOut)
async def watchlist_detail(watchlist_id: str) -> Watchlist:
    watchlist = await get_watchlist(watchlist_id)
    if not watchlist:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    return watchlist


@router.put("/{watchlist_id}", response_model=WatchlistOut, dependencies=[Depends(require_api_key)])
async def replace_watchlist(watchlist_id: str, payload: WatchlistCreate) -> Watchlist:
    existing = await get_watchlist(watchlist_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    updated = _from_payload(payload, watchlist_id=watchlist_id, created_at=existing.created_at)
    saved = await update_watchlist(watchlist_id, updated)
    if not saved:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    await _audit("watchlist_update", saved)
    return saved


@router.delete("/{watchlist_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_api_key)])
async def remove_watchlist(watchlist_id: str) -> Response:
    existing = await get_watchlist(watchlist_id)
    if not await delete_watchlist(watchlist_id):
        raise HTTPException(status_code=404, detail="Watchlist not found")
    await _audit("watchlist_delete", existing, watchlist_id=watchlist_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
