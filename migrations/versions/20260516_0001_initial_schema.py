"""initial POLARIS production intelligence schema

Revision ID: 20260516_0001
Revises:
Create Date: 2026-05-16
"""
from __future__ import annotations

from alembic import op

revision = "20260516_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE IF NOT EXISTS cve_enrichments (
        cve_id TEXT PRIMARY KEY, severity TEXT, cvss_score DOUBLE PRECISION, epss_score DOUBLE PRECISION,
        cisa_kev BOOLEAN NOT NULL DEFAULT FALSE, affected_products JSONB NOT NULL DEFAULT '[]'::jsonb,
        vendor_advisory_links JSONB NOT NULL DEFAULT '[]'::jsonb, exploit_status TEXT NOT NULL DEFAULT 'unknown',
        patch_status TEXT NOT NULL DEFAULT 'unknown', enriched_at TIMESTAMPTZ, sources JSONB NOT NULL DEFAULT '[]'::jsonb,
        last_refresh_attempt_at TIMESTAMPTZ, refresh_status TEXT NOT NULL DEFAULT 'pending', last_error TEXT,
        nvd_last_modified TIMESTAMPTZ, cisa_kev_due_date TEXT, epss_percentile DOUBLE PRECISION, description TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS background_jobs (
        id TEXT PRIMARY KEY, job_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued', created_at TIMESTAMPTZ NOT NULL,
        started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ, result_summary TEXT NOT NULL DEFAULT '', error_message TEXT
    );
    ALTER TABLE source_configs ADD COLUMN IF NOT EXISTS trust_tier TEXT NOT NULL DEFAULT 'Medium';
    ALTER TABLE source_configs ADD COLUMN IF NOT EXISTS source_type TEXT NOT NULL DEFAULT 'custom';
    ALTER TABLE source_configs ADD COLUMN IF NOT EXISTS country_focus JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE source_configs ADD COLUMN IF NOT EXISTS sector_focus JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE source_configs ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT '';
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS background_jobs;")
