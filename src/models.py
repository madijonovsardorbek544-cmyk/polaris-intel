from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class WatchlistMatch:
    watchlist_id: str
    watchlist_name: str
    matched_on: str
    matched_value: str
    reason: str
    org_id: str = "demo"


@dataclass
class IntelligenceItem:
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
    risk_factors: list[str] = field(default_factory=list)
    confidence_factors: list[str] = field(default_factory=list)
    watchlist_matches: list[WatchlistMatch] = field(default_factory=list)


@dataclass
class Watchlist:
    id: str
    name: str
    org_id: str = "demo"
    countries: list[str] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    organizations: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    created_at: str = ""


@dataclass
class SourceHealth:
    source_url: str
    last_success_at: str | None = None
    last_failure_at: str | None = None
    last_empty_at: str | None = None
    total_failure_count: int = 0
    consecutive_failure_count: int = 0
    empty_count: int = 0
    last_error: str | None = None
    status: str = "pending"


@dataclass
class Alert:
    id: str
    item_id: str
    title: str
    risk_level: str
    matched_watchlist_id: str
    matched_watchlist_name: str
    reason: str
    recommended_action: str
    status: str = "open"
    created_at: str = ""
    updated_at: str = ""
    notes: str | None = None
    org_id: str = "demo"
    owner: str | None = None
    due_at: str | None = None
    severity_override: str | None = None
    resolution_summary: str | None = None


@dataclass
class AlertEvent:
    id: str
    alert_id: str
    event_type: str
    message: str
    created_at: str = ""


@dataclass
class SourceConfig:
    id: str
    url: str
    label: str
    category: str = "custom"
    enabled: bool = True
    created_at: str = ""


@dataclass
class OrgScoringProfile:
    org_id: str
    high_priority_countries: list[str] = field(default_factory=list)
    high_priority_sectors: list[str] = field(default_factory=list)
    risk_boost_keywords: list[str] = field(default_factory=list)
    risk_reduce_keywords: list[str] = field(default_factory=list)
