from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Response, status

from ..database import add_watchlist, delete_watchlist, get_watchlist, list_watchlists, update_watchlist
from ..models import Watchlist
from ..schemas import WatchlistCreate, WatchlistOut
from ..services.analysis import now_iso

router = APIRouter(prefix="/api/watchlists")


def _clean(values: list[str]) -> list[str]:
    return [value.strip() for value in values if value.strip()]


def _from_payload(payload: WatchlistCreate, watchlist_id: str | None = None, created_at: str | None = None) -> Watchlist:
    timestamp = now_iso()
    return Watchlist(
        id=watchlist_id or str(uuid.uuid4()),
        name=payload.name.strip(),
        countries=_clean(payload.countries),
        sectors=_clean(payload.sectors),
        organizations=_clean(payload.organizations),
        keywords=_clean(payload.keywords),
        cves=[value.strip().upper() for value in payload.cves if value.strip()],
        threat_actors=_clean(payload.threat_actors),
        created_at=created_at or timestamp,
        updated_at=timestamp,
    )


@router.post("", response_model=WatchlistOut, status_code=status.HTTP_201_CREATED)
async def create_watchlist(payload: WatchlistCreate) -> Watchlist:
    return await add_watchlist(_from_payload(payload))


@router.get("", response_model=list[WatchlistOut])
async def get_watchlists() -> list[Watchlist]:
    return await list_watchlists()


@router.get("/{watchlist_id}", response_model=WatchlistOut)
async def get_watchlist_detail(watchlist_id: str) -> Watchlist:
    watchlist = await get_watchlist(watchlist_id)
    if not watchlist:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    return watchlist


@router.put("/{watchlist_id}", response_model=WatchlistOut)
async def replace_watchlist(watchlist_id: str, payload: WatchlistCreate) -> Watchlist:
    existing = await get_watchlist(watchlist_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    updated = _from_payload(payload, watchlist_id=watchlist_id, created_at=existing.created_at)
    saved = await update_watchlist(watchlist_id, updated)
    if not saved:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    return saved


@router.delete("/{watchlist_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_watchlist(watchlist_id: str) -> Response:
    if not await delete_watchlist(watchlist_id):
        raise HTTPException(status_code=404, detail="Watchlist not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
