from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status

from ..auth import require_api_key
from ..database import add_watchlist, delete_watchlist, get_watchlist, list_watchlists, update_watchlist
from ..models import Watchlist
from ..schemas import WatchlistCreate, WatchlistOut
from ..services.analysis import now_iso

router = APIRouter(prefix="/api/watchlists")


def _clean(values: list[str]) -> list[str]:
    return [value.strip() for value in values if value.strip()]


def _from_payload(payload: WatchlistCreate, *, watchlist_id: str, created_at: str) -> Watchlist:
    return Watchlist(
        id=watchlist_id,
        name=payload.name.strip(),
        org_id=payload.org_id.strip() or "demo",
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
    return await add_watchlist(watchlist)


@router.get("", response_model=list[WatchlistOut])
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
    return saved


@router.delete("/{watchlist_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_api_key)])
async def remove_watchlist(watchlist_id: str) -> Response:
    if not await delete_watchlist(watchlist_id):
        raise HTTPException(status_code=404, detail="Watchlist not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
