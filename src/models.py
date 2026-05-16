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
    source_reliability: str = "Medium"
    source_type: str = "custom"
    evidence_links: list[str] = field(default_factory=list)
    evidence_summary: str = ""


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
    trust_tier: str = "Medium"
    source_type: str = "custom"
    country_focus: list[str] = field(default_factory=list)
    sector_focus: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class OrgScoringProfile:
    org_id: str
    high_priority_countries: list[str] = field(default_factory=list)
    high_priority_sectors: list[str] = field(default_factory=list)
    risk_boost_keywords: list[str] = field(default_factory=list)
    risk_reduce_keywords: list[str] = field(default_factory=list)


@dataclass
class PilotLead:
    id: str
    name: str
    organization: str = ""
    role: str = ""
    email: str = ""
    country: str = ""
    organization_type: str = ""
    problem_description: str = ""
    preferred_contact_method: str = ""
    created_at: str = ""
    status: str = "new"


@dataclass
class PublicMetrics:
    landing_page_views: int = 0
    demo_page_views: int = 0
    pilot_form_submissions: int = 0


@dataclass
class ItemFeedback:
    id: str
    item_id: str
    relevance: str
    severity_feedback: str
    org_id: str
    comment: str = ""
    created_at: str = ""


@dataclass
class AdminAuditEvent:
    id: str
    action: str
    resource_type: str
    resource_id: str
    org_id: str | None = None
    message: str = ""
    created_at: str = ""

@dataclass
class CveEnrichment:
    cve_id: str
    severity: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    cisa_kev: bool = False
    affected_products: list[str] = field(default_factory=list)
    vendor_advisory_links: list[str] = field(default_factory=list)
    exploit_status: str = "unknown"
    patch_status: str = "unknown"
    enriched_at: str = ""
    sources: list[str] = field(default_factory=list)
    last_refresh_attempt_at: str | None = None
    refresh_status: str = "pending"
    last_error: str | None = None
    nvd_last_modified: str | None = None
    cisa_kev_due_date: str | None = None
    epss_percentile: float | None = None
    description: str = ""


@dataclass
class IntelEntity:
    id: str
    type: str
    value: str
    display_name: str
    first_seen_at: str
    last_seen_at: str


@dataclass
class IntelEdge:
    id: str
    source_entity_id: str
    target_entity_id: str
    relationship: str
    evidence_item_id: str | None = None
    weight: float = 1.0
    created_at: str = ""


@dataclass
class IntelCluster:
    id: str
    title: str
    summary: str
    item_ids: list[str] = field(default_factory=list)
    source_domains: list[str] = field(default_factory=list)
    risk_level: str = "Low"
    confidence_score: int = 0
    first_seen_at: str = ""
    last_seen_at: str = ""
    key_entities: list[str] = field(default_factory=list)
    corroboration_level: str = "single_source"
    evidence_count: int = 0


@dataclass
class ReviewQueueItem:
    id: str
    item_id: str
    cluster_id: str | None = None
    org_id: str | None = None
    priority: str = "medium"
    reason: str = ""
    status: str = "pending"
    created_at: str = ""
    updated_at: str = ""


@dataclass
class BackgroundJob:
    id: str
    job_type: str
    status: str = "queued"
    created_at: str = ""
    started_at: str | None = None
    finished_at: str | None = None
    result_summary: str = ""
    error_message: str | None = None
