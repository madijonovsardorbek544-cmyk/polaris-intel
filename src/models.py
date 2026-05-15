from __future__ import annotations

from dataclasses import dataclass, field


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
