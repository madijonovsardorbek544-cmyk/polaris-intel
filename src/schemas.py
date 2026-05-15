from __future__ import annotations

from pydantic import BaseModel, Field

from .config import settings


class WatchlistMatchOut(BaseModel):
    watchlist_id: str
    watchlist_name: str
    matched_on: str
    matched_value: str
    reason: str
    org_id: str = "demo"


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
    risk_factors: list[str] = Field(default_factory=list)
    confidence_factors: list[str] = Field(default_factory=list)
    watchlist_matches: list[WatchlistMatchOut] = Field(default_factory=list)


class WatchlistCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    org_id: str = Field(default_factory=lambda: settings.default_org, min_length=1, max_length=80)
    countries: list[str] = Field(default_factory=list)
    sectors: list[str] = Field(default_factory=list)
    organizations: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)


class WatchlistOut(WatchlistCreate):
    id: str
    created_at: str


class SourceHealthOut(BaseModel):
    source_url: str
    last_success_at: str | None = None
    last_failure_at: str | None = None
    last_empty_at: str | None = None
    total_failure_count: int = 0
    consecutive_failure_count: int = 0
    empty_count: int = 0
    last_error: str | None = None
    status: str = "pending"


class AlertOut(BaseModel):
    id: str
    item_id: str
    title: str
    risk_level: str
    matched_watchlist_id: str
    matched_watchlist_name: str
    reason: str
    recommended_action: str
    status: str = "open"
    created_at: str
    updated_at: str
    notes: str | None = None
    org_id: str = "demo"
    owner: str | None = None
    due_at: str | None = None
    severity_override: str | None = None
    resolution_summary: str | None = None


class AlertUpdate(BaseModel):
    status: str | None = Field(default=None, pattern="^(open|acknowledged|in_progress|resolved|false_positive)$")
    notes: str | None = Field(default=None, max_length=2000)
    owner: str | None = Field(default=None, max_length=200)
    due_at: str | None = Field(default=None, max_length=80)
    severity_override: str | None = Field(default=None, pattern="^(Critical|High|Medium|Low)$")
    resolution_summary: str | None = Field(default=None, max_length=4000)

class AlertEventOut(BaseModel):
    id: str
    alert_id: str
    event_type: str
    message: str
    created_at: str


class SourceConfigCreate(BaseModel):
    url: str = Field(..., min_length=1, max_length=1000)
    label: str = Field(..., min_length=1, max_length=200)
    category: str = Field(default="custom", pattern="^(cyber|geopolitical|local|custom)$")
    enabled: bool = True


class SourceConfigUpdate(BaseModel):
    url: str | None = Field(default=None, min_length=1, max_length=1000)
    label: str | None = Field(default=None, min_length=1, max_length=200)
    category: str | None = Field(default=None, pattern="^(cyber|geopolitical|local|custom)$")
    enabled: bool | None = None


class SourceConfigOut(SourceConfigCreate):
    id: str
    created_at: str


class OrgScoringProfileIn(BaseModel):
    high_priority_countries: list[str] = Field(default_factory=list)
    high_priority_sectors: list[str] = Field(default_factory=list)
    risk_boost_keywords: list[str] = Field(default_factory=list)
    risk_reduce_keywords: list[str] = Field(default_factory=list)


class OrgScoringProfileOut(OrgScoringProfileIn):
    org_id: str
