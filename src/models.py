from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class WatchlistMatch:
    watchlist_id: str
    watchlist_name: str
    matched_on: str
    matched_value: str
    reason: str


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
    failure_count: int = 0
    last_error: str | None = None
