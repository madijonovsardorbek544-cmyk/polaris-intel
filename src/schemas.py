from __future__ import annotations

from pydantic import BaseModel, Field


class WatchlistMatchOut(BaseModel):
    watchlist_id: str
    watchlist_name: str
    reason: str


class IntelligenceItemOut(BaseModel):
    id: str
    title: str
    summary: str
    category: str
    risk_score: int
    risk_level: str
    confidence_score: int
    source_url: str
    source_domain: str
    tags: list[str]
    entities: dict[str, list[str]]
    affected_countries: list[str]
    affected_sectors: list[str]
    why_it_matters: str
    recommended_action: str
    created_at: str
    ingested_at: str
    risk_factors: list[str]
    confidence_factors: list[str]
    watchlist_matches: list[WatchlistMatchOut]


class WatchlistCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    countries: list[str] = Field(default_factory=list)
    sectors: list[str] = Field(default_factory=list)
    organizations: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)


class WatchlistOut(WatchlistCreate):
    id: str
    created_at: str
    updated_at: str


class SourceHealthOut(BaseModel):
    source_url: str
    last_success_at: str | None = None
    last_failure_at: str | None = None
    failure_count: int
    last_error: str


class AlertOut(BaseModel):
    item_id: str
    title: str
    risk_level: str
    matched_watchlist: str
    reason: str
    recommended_action: str
    created_at: str
