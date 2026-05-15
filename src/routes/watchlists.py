from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Response, status

from ..database import add_watchlist, delete_watchlist, list_watchlists
from ..models import Watchlist
from ..schemas import WatchlistCreate, WatchlistOut
from ..services.analysis import now_iso

router = APIRouter(prefix="/api/watchlists")


def _clean(values: list[str]) -> list[str]:
    return [value.strip() for value in values if value.strip()]


@router.post("", response_model=WatchlistOut, status_code=status.HTTP_201_CREATED)
async def create_watchlist(payload: WatchlistCreate) -> Watchlist:
    watchlist = Watchlist(
        id=str(uuid.uuid4()),
        name=payload.name.strip(),
        countries=_clean(payload.countries),
        sectors=_clean(payload.sectors),
        organizations=_clean(payload.organizations),
        keywords=_clean(payload.keywords),
        cves=[value.strip().upper() for value in payload.cves if value.strip()],
        threat_actors=_clean(payload.threat_actors),
        created_at=now_iso(),
    )
    return await add_watchlist(watchlist)


@router.get("", response_model=list[WatchlistOut])
async def get_watchlists() -> list[Watchlist]:
    return await list_watchlists()


@router.delete("/{watchlist_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_watchlist(watchlist_id: str) -> Response:
    if not await delete_watchlist(watchlist_id):
        raise HTTPException(status_code=404, detail="Watchlist not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
