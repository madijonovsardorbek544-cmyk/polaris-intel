from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from .config import settings


class WatchlistMatchOut(BaseModel):
    watchlist_id: str
    watchlist_name: str
    matched_on: str
    matched_value: str
    reason: str
    org_id: str = "demo"


class CveEnrichmentOut(BaseModel):
    cve_id: str
    severity: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    cisa_kev: bool = False
    affected_products: list[str] = Field(default_factory=list)
    vendor_advisory_links: list[str] = Field(default_factory=list)
    exploit_status: str = "unknown"
    patch_status: str = "unknown"
    enriched_at: str = ""
    sources: list[str] = Field(default_factory=list)


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
    source_reliability: str = "Medium"
    source_type: str = "custom"
    evidence_links: list[str] = Field(default_factory=list)
    evidence_summary: str = ""
    cve_enrichments: list[CveEnrichmentOut] = Field(default_factory=list)
    cluster_id: str | None = None
    cluster_title: str | None = None


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


class PilotLeadCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    organization: str = Field(default="", max_length=200)
    role: str = Field(default="", max_length=200)
    email: str = Field(..., min_length=3, max_length=320)
    country: str = Field(default="", max_length=120)
    organization_type: str = Field(..., min_length=1, max_length=120)
    problem_description: str = Field(..., min_length=1, max_length=4000)
    preferred_contact_method: str = Field(default="", max_length=200)
    website: str = Field(default="", max_length=500)

    @field_validator("email")
    @classmethod
    def email_must_look_valid(cls, value: str) -> str:
        cleaned = value.strip()
        if "@" not in cleaned or "." not in cleaned.rsplit("@", 1)[-1]:
            raise ValueError("email must look like an email address")
        return cleaned

    @field_validator("name", "organization_type", "problem_description")
    @classmethod
    def required_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("field is required")
        return cleaned


class PilotLeadUpdate(BaseModel):
    status: str = Field(..., pattern="^(new|contacted|qualified|rejected)$")


class PilotLeadOut(PilotLeadCreate):
    id: str
    created_at: str
    status: str = "new"


class AdminAuditEventOut(BaseModel):
    id: str
    action: str
    resource_type: str
    resource_id: str
    org_id: str | None = None
    message: str = ""
    created_at: str = ""


class PublicMetricsOut(BaseModel):
    landing_page_views: int = 0
    demo_page_views: int = 0
    pilot_form_submissions: int = 0


class ItemFeedbackCreate(BaseModel):
    relevance: str = Field(..., pattern="^(useful|not_useful|false_positive)$")
    severity_feedback: str = Field(..., pattern="^(too_high|accurate|too_low)$")
    org_id: str = Field(..., min_length=1, max_length=80)
    comment: str = Field(default="", max_length=2000)


class ItemFeedbackOut(ItemFeedbackCreate):
    id: str
    item_id: str
    created_at: str
