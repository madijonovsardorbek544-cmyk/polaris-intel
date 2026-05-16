# POLARIS Intel

Live demo: https://polaris-intel.onrender.com

POLARIS helps under-resourced organizations monitor cyber and geopolitical risk signals, understand what matters today, assign response work, and prove what action was taken. It is designed for schools, NGOs, logistics firms, banking and finance teams, energy organizations, telecom-adjacent companies, and small government-adjacent teams, especially in Central Asia and similar regions where dedicated security teams may be limited.

POLARIS is not a SIEM replacement, enterprise SOC automation platform, or guaranteed protection product. This version is built for public demos and controlled pilot deployments with honest limits.

## Public pages

- `/` — public product landing page for visitors and GitHub users.
- `/demo` — clean read-only live demo with Global Intelligence by default.
- `/dashboard` — operator dashboard with API-key-protected write actions.
- `/request-pilot` — public pilot request form.
- `/health` — public deployment health check.

## What POLARIS is

POLARIS Intel is a FastAPI + Jinja2 cyber-geopolitical risk intelligence app for pilot deployments. It ingests RSS feeds, extracts observable risk signals, tracks source health, applies deterministic risk and confidence scoring, matches intelligence against organization watchlists, persists alerts, and provides operator workflows for ownership, notes, status, Telegram delivery, source configuration, value reporting, and exportable evidence.

## Operator features

- Public landing page and read-only demo separated from the full operator dashboard.
- Dashboard **Global Intelligence** and **Org Watchlist** view modes so visitors can see live risk items immediately while operators can focus customer-specific matches.
- Watchlists for countries, sectors, organizations, keywords, CVEs, and threat actors.
- Tenant-ready `org_id` fields on watchlists, alerts, and watchlist matches.
- Single-org deployment defaults through `POLARIS_DEFAULT_ORG`.
- API-key protection for write operations using `POLARIS_API_KEY` and `X-Polaris-API-Key`.
- Optional API-key protection for read operations with `POLARIS_PROTECT_READS=true`.
- Persistent alert workflow with owner, due date, severity override, notes, resolution summary, and status tracking.
- Daily brief endpoint with top risks, affected countries/sectors, recommended actions, source failures, and empty sources.
- Source configuration, dashboard diagnostics, CSV exports, value reports, and org scoring profiles.
- Pilot lead capture with protected admin lead review.
- Privacy-safe public product counters for landing page views, demo page views, and pilot submissions. No cookies, no personal tracking, and no third-party analytics.

## Telegram delivery

Telegram preview works without credentials and does not send messages. Telegram sending requires both `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`, plus the write API key when `POLARIS_API_KEY` is configured. Tokens and chat IDs are never shown in the dashboard. Tests mock Telegram HTTP calls and do not send real messages.

## What remains future

Before a larger paid deployment, POLARIS still needs full multi-tenant SaaS isolation, real user login, role-based access control, billing/subscriptions, production monitoring and alerting, backups, rate limits, analyst queues, escalation policies, Alembic migrations, and a stronger operational security review.

## Project structure

```text
src/
  auth.py
  main.py
  config.py
  database.py
  models.py
  schemas.py
  feeds.py
  scoring.py
  entities.py
  services/
    analysis.py
    briefing.py
    ingestion.py
  routes/
    health.py
    intelligence.py
    watchlists.py
  templates/
    index.html
    demo.html
    dashboard.html
    request_pilot.html
tests/
pytest.ini
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn src.main:app --reload
```

Open the public product site at <http://127.0.0.1:8000/> or the operator dashboard at <http://127.0.0.1:8000/dashboard>.

## Configuration

Create a local `.env` file if you want to override defaults:

```env
POLARIS_API_KEY=
POLARIS_ADMIN_API_KEY=
POLARIS_OPERATOR_API_KEY=
POLARIS_READONLY_API_KEY=
POLARIS_ALLOWED_ORGS=
NVD_API_KEY=
POLARIS_PROTECT_READS=false
POLARIS_DEFAULT_ORG=demo
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
PORT=8000
DATABASE_URL=
MAX_ITEMS=60
AUTO_REFRESH_SECONDS=900
HTTP_TIMEOUT=15
FEEDS=
LOG_LEVEL=INFO
```

- `POLARIS_API_KEY`: optional legacy API key. If empty, demo writes are allowed. If set, it remains a backward-compatible admin fallback.
- `POLARIS_ADMIN_API_KEY`, `POLARIS_OPERATOR_API_KEY`, `POLARIS_READONLY_API_KEY`: optional role-specific API keys for production pilots.
- `POLARIS_ALLOWED_ORGS`: optional comma-separated allowed org IDs. When set, invalid `org_id` values are rejected with HTTP 400.
- `NVD_API_KEY`: optional NVD API key for CVE enrichment; unauthenticated NVD access is attempted when omitted.
- `POLARIS_PROTECT_READS`: default `false`. When `true` and `POLARIS_API_KEY` is set, read endpoints require `X-Polaris-API-Key` too.
- `POLARIS_DEFAULT_ORG`: default single-org context for the dashboard and omitted watchlist `org_id` values. Defaults to `demo`.
- `TELEGRAM_BOT_TOKEN`: enables Telegram sending when paired with `TELEGRAM_CHAT_ID`; preview formatting works without credentials.
- `TELEGRAM_CHAT_ID`: destination chat for Telegram sending when paired with `TELEGRAM_BOT_TOKEN`; tokens and chat IDs are never shown in the dashboard.
- `PORT`: default HTTP port for deployment commands.
- `DATABASE_URL`: when set, POLARIS uses PostgreSQL and creates/updates required tables at startup.
- `MAX_ITEMS`: maximum number of intelligence items returned/stored in memory.
- `AUTO_REFRESH_SECONDS`: background refresh interval.
- `HTTP_TIMEOUT`: RSS HTTP request timeout in seconds.
- `FEEDS`: optional comma-separated RSS feed override. If empty, built-in cyber and world-news feeds are used.
- `LOG_LEVEL`: standard Python logging level.

The environment block above intentionally matches `.env.example` exactly.

## Dashboard view modes and org context

The dashboard has a visible **Global Intelligence / Org Watchlist** toggle. Global Intelligence calls read endpoints without `org_id` filtering, while Org Watchlist adds the active `org_id` for customer-specific matching.

The dashboard sidebar has an **Active org_id** input. It defaults to `POLARIS_DEFAULT_ORG`, stores the current value in `sessionStorage`, displays the active org near the top of the dashboard, and reloads dashboard data when changed.

Org Watchlist dashboard read calls include the active org where supported:

- `/api/items?org_id=<activeOrg>`
- `/api/alerts?org_id=<activeOrg>`
- `/api/brief/daily?org_id=<activeOrg>`
- `/api/watchlists?org_id=<activeOrg>`

Watchlist creation also defaults to the active org. This avoids mixed-org dashboard data during a single-org pilot.

## Demo mode vs database mode

### Demo/in-memory mode

If `DATABASE_URL` is empty, POLARIS runs without PostgreSQL. Items, source health, watchlists, and alerts are stored in process memory and reset when the server restarts.

Demo mode also enables:

- `POST /api/demo/reset` — protected by `POLARIS_API_KEY` when configured. It clears in-memory items, watchlists, source health, alerts, pilot leads, and public counters for live demo resets without restarting the server.

If `DATABASE_URL` is set, `POST /api/demo/reset` returns HTTP 400 with `Demo reset is disabled in database mode.`

### PostgreSQL mode

If `DATABASE_URL` is set, POLARIS creates/updates these tables automatically:

- `intel_items`
- `watchlists`
- `source_health`
- `alerts`
- `pilot_leads`
- `public_metrics`

Example:

```bash
export DATABASE_URL='postgresql://postgres:postgres@localhost:5432/polaris'
export POLARIS_API_KEY='replace-me'
export POLARIS_PROTECT_READS=true
export POLARIS_DEFAULT_ORG='pilot-customer'
uvicorn src.main:app --reload
```

## API-key protection

Protected operator endpoints require `X-Polaris-API-Key` when `POLARIS_API_KEY` is configured:

- `POST /api/watchlists`
- `PUT /api/watchlists/{id}`
- `DELETE /api/watchlists/{id}`
- `POST /api/refresh`
- `POST /api/seed`
- `POST /api/alerts/generate`
- `PATCH /api/alerts/{id}`
- `POST /api/alerts/{id}/telegram-preview`
- `POST /api/alerts/{id}/telegram-send`
- `POST /api/source-configs`
- `PATCH /api/source-configs/{id}`
- `DELETE /api/source-configs/{id}`
- `PUT /api/org-profile`
- `GET /api/leads`
- `PATCH /api/leads/{id}`
- `GET /api/public-metrics`
- `POST /api/demo/reset`

Read endpoints are public by default. If `POLARIS_PROTECT_READS=true` and `POLARIS_API_KEY` is set, these read endpoints require the same header:

- `GET /api/items`
- `GET /api/alerts`
- `GET /api/brief/daily`
- `GET /api/sources`
- `GET /api/watchlists`

`GET /health` remains public and never exposes the actual API key.

## API endpoints

### System

- `GET /` — public landing page rendered from `src/templates/index.html`.
- `GET /demo` — clean read-only public demo rendered from `src/templates/demo.html`.
- `GET /dashboard` — full operator dashboard rendered from `src/templates/dashboard.html`.
- `GET /request-pilot` — pilot request form rendered from `src/templates/request_pilot.html`.
- `GET /health` — service health with storage mode, API-key configuration flag, read-protection flag, default org, feed count, item count, alert count, and source count.
- `POST /api/demo/reset` — demo-memory reset. Protected by API key. Disabled in database mode.
- `POST /api/leads` — create a pilot lead from the public form.
- `GET /api/leads` — protected operator lead list.
- `PATCH /api/leads/{id}` — protected lead status update.
- `GET /api/public-metrics` — protected privacy-safe public product counters.

### Intelligence

- `GET /api/latest` — latest intelligence items, kept for backward compatibility.
- `GET /api/items` — filterable intelligence items. Query params: `q`, `category`, `risk_level`, `country`, `sector`, `org_id`, `limit`.
- `GET /api/items/{id}` — one intelligence item by ID.
- `GET /api/stats` — compatibility stats endpoint. The dashboard derives visible stats from active-org items.
- `GET /api/summary` — short executive summary and top high-priority items.
- `POST /api/refresh` — force RSS refresh.
- `POST /api/seed` — load deterministic sample intelligence items.

### Source health

- `GET /api/sources` — source health records.

Source status rules:

- `failing` if `last_error` exists.
- `empty` if `last_empty_at` is newer than `last_success_at`.
- `healthy` if `last_success_at` exists and there is no current error.
- `pending` if the source has never been checked.

### Watchlists

- `POST /api/watchlists` — create a watchlist. Omitted `org_id` defaults to `POLARIS_DEFAULT_ORG`.
- `GET /api/watchlists` — list watchlists. Optional query param: `org_id`.
- `GET /api/watchlists/{id}` — retrieve watchlist detail.
- `PUT /api/watchlists/{id}` — replace/update a watchlist while keeping the same ID and creation timestamp.
- `DELETE /api/watchlists/{id}` — delete a watchlist.

Example watchlist payload:

```json
{
  "name": "Central Asia energy exposure",
  "org_id": "demo",
  "countries": ["Kazakhstan", "Uzbekistan"],
  "sectors": ["energy", "telecom"],
  "organizations": [],
  "keywords": ["pipeline", "sanction"],
  "cves": ["CVE-2026-12345"],
  "threat_actors": []
}
```

### Alerts

- `GET /api/alerts` — returns `persisted` alerts and `generated_preview` alerts separately. Optional query param: `org_id`.
- `GET /api/alerts/flat` — compatibility endpoint returning the old flat list behavior.
- `GET /api/alerts/{id}` — retrieve one persisted or generated alert.
- `POST /api/alerts/generate` — persist alert records for current Critical/High watchlist-matched items. Returns `ok`, `created`, `existing`, `created_alerts`, and `alerts`.
- `PATCH /api/alerts/{id}` — update alert `status` and/or `notes`.
- `POST /api/alerts/{id}/telegram-preview` — return the Telegram-formatted alert message without sending anything.

The operator dashboard can generate persistent alerts, filter persisted/preview alerts, search title/reason/watchlist text, edit alert ownership/status/notes, preview Telegram formatting, and send Telegram messages when credentials are configured.

### Daily brief

- `GET /api/brief/daily` — pilot-friendly summary for analyst review. Optional query param: `org_id`.

## Testing

```bash
pytest -q
```

The suite covers scoring, entity extraction, watchlist matching, `.env` loading, source failure logging, explainability factors, alert generation and persistence counts, daily brief generation, watchlist CRUD endpoints, API endpoint smoke tests, deduplication, optional read protection, default org behavior, demo reset behavior, dashboard control smoke tests, and Telegram alert formatting. Tests use isolated in-memory state and do not require real network calls.

## Smoke commands

Local run:

```bash
pip install -r requirements.txt
uvicorn src.main:app --reload
```

Production-like run:

```bash
PORT=8000 uvicorn src.main:app --host 0.0.0.0 --port 8000
```

Test:

```bash
pytest -q
```

## Deployment

POLARIS is a FastAPI backend application and must be deployed to a platform that runs a Python web server. Do **not** use GitHub Pages as the live app host; GitHub Pages can only host static files and will not run the FastAPI API, dashboard actions, or health checks.

**Public demo safety warning:** For public deployments, set `POLARIS_API_KEY` before sharing the link. Recommended public read-only demo settings are:

```env
POLARIS_API_KEY=<strong-random-key>
POLARIS_PROTECT_READS=false
```

With those settings, the dashboard and read endpoints remain publicly viewable, while write actions return HTTP 401 unless the operator sends `X-Polaris-API-Key`. If `POLARIS_API_KEY` is empty, write actions are intentionally open only for local development and private demos.

### A) Render deployment

Render is the recommended beginner-friendly path for the first public demo.

1. Push this repository to GitHub.
2. Open Render and choose **New +** → **Web Service**.
3. Connect the GitHub repository.
4. Use **Runtime: Python**.
5. Set **Build Command** to:

   ```bash
   pip install -r requirements.txt
   ```

6. Set **Start Command** to:

   ```bash
   uvicorn src.main:app --host 0.0.0.0 --port $PORT
   ```

7. Set **Health Check Path** to `/health` if Render asks for one.
8. Add environment variables:
   - `POLARIS_API_KEY=<strong-random-key>`
   - `POLARIS_PROTECT_READS=false`
   - `POLARIS_DEFAULT_ORG=demo`
   - `DATABASE_URL=` optional; leave empty for in-memory demo mode or set a PostgreSQL URL for persistence
   - `MAX_ITEMS=60`
   - `AUTO_REFRESH_SECONDS=900`
   - `HTTP_TIMEOUT=15`
   - `LOG_LEVEL=INFO`
   - Optional: `FEEDS=` comma-separated RSS feed override
   - Optional: `TELEGRAM_BOT_TOKEN=` and `TELEGRAM_CHAT_ID=` only if enabling Telegram sends
9. Deploy the service.
10. Open the Render URL and verify `/` and `/health`.
11. Copy the Render URL into the README **Live Demo** line and GitHub repository Website field.

This repository also includes `render.yaml` for Render Blueprint deployment. The manual settings above are still shown so beginners can deploy without learning Blueprints first.

### B) Railway deployment

1. Push this repository to GitHub.
2. Open Railway and choose **New Project** → **Deploy from GitHub repo**.
3. Select the POLARIS Intel repository.
4. Railway can use the included `railway.json`. If Railway asks for a start command, set:

   ```bash
   uvicorn src.main:app --host 0.0.0.0 --port $PORT
   ```

5. Add environment variables:
   - `POLARIS_API_KEY=<strong-random-key>`
   - `POLARIS_PROTECT_READS=false`
   - `POLARIS_DEFAULT_ORG=demo`
   - `DATABASE_URL=` optional; leave empty for in-memory demo mode or attach Railway PostgreSQL
   - `MAX_ITEMS=60`
   - `AUTO_REFRESH_SECONDS=900`
   - `HTTP_TIMEOUT=15`
   - `LOG_LEVEL=INFO`
   - Optional: `FEEDS=`
6. Deploy and open the generated Railway domain.
7. Verify `/` and `/health`, then add the live URL to README and GitHub About.

### C) Docker deployment

Build the image:

```bash
docker build -t polaris-intel .
```

Run an in-memory public-read demo locally:

```bash
docker run --rm -p 8000:8000 \
  -e PORT=8000 \
  -e POLARIS_API_KEY=<strong-random-key> \
  -e POLARIS_PROTECT_READS=false \
  -e POLARIS_DEFAULT_ORG=demo \
  polaris-intel
```

For PostgreSQL persistence, also pass `-e DATABASE_URL=<postgres-url>`.

## Add the live link to GitHub

After deployment:

1. Open the GitHub repository.
2. Click the gear/settings icon near the About section.
3. Paste the deployed app URL into the Website field.
4. Save.
5. Keep the same URL in README under Live Demo.

The live demo URL is published at the top of this README. Update that line if you redeploy under a different Render service name.

## Pilot customer workflow upgrade

POLARIS Intel is now positioned as a real pilot customer workflow product: it supports explainable monitoring, watchlist-driven alerting, analyst ownership, event history, guided onboarding, source configuration, value reporting, and exportable evidence. It is **not** enterprise-complete yet.

### API key protection

Set `POLARIS_API_KEY` to require `X-Polaris-API-Key` for write operations such as refresh, watchlist changes, alert generation, alert updates, source configuration, org scoring profiles, demo reset, and Telegram sending.

Optional read protection is enabled with:

```bash
POLARIS_API_KEY=change-me
POLARIS_PROTECT_READS=true
```

When enabled, sensitive read endpoints require the same `X-Polaris-API-Key`. `/health` remains public for uptime checks.

### Alert ownership workflow

Persistent alerts now include owner, due date, severity override, resolution summary, notes, and statuses: `open`, `acknowledged`, `in_progress`, `resolved`, and `false_positive`. Alert updates create audit events for status, owner, notes, resolution, and severity changes.

Useful endpoints:

- `PATCH /api/alerts/{id}`
- `GET /api/alerts/{id}/events`

### Onboarding templates

`GET /api/onboarding/template` returns starter watchlist templates for school, NGO, logistics, bank, energy, telecom, and government organizations. The dashboard can fill watchlist fields from a selected template before the operator saves it.

### Value reports

`GET /api/reports/value?org_id=<org_id>&days=7` returns a customer-facing value report with monitored items, alert counts, unresolved/resolved work, average risk, top countries, top sectors, top watchlists, source failures, and recommended next actions.

### CSV export

- `GET /api/export/alerts.csv?org_id=<org_id>`
- `GET /api/export/value-report.csv?org_id=<org_id>&days=7`

Exports are protected by optional read protection when `POLARIS_PROTECT_READS=true`.

### Telegram sending

Telegram preview works without credentials, so operators can inspect the exact message before enabling delivery. Telegram sending requires both:

```bash
TELEGRAM_BOT_TOKEN=<bot-token>
TELEGRAM_CHAT_ID=<chat-id>
```

Use `POST /api/alerts/{id}/telegram-send` with the write API key. If either variable is missing, POLARIS returns a clear `400` and records a `telegram_failed` event. Tokens are never shown in the dashboard. Tests must mock Telegram HTTP calls and must never send real Telegram messages.

### Source configuration

Operators can configure RSS sources without editing environment variables:

- `GET /api/source-configs`
- `POST /api/source-configs`
- `PATCH /api/source-configs/{id}`
- `DELETE /api/source-configs/{id}`

Refresh uses enabled source configs if any exist; otherwise it falls back to `FEEDS` / default feeds.

### Org scoring profiles

Use `GET /api/org-profile?org_id=<org_id>` and `PUT /api/org-profile?org_id=<org_id>` to calibrate rule-based scoring per organization with high-priority countries, sectors, boost keywords, and reduce keywords. Adjustments are explainable through `risk_factors`.

### What remains before enterprise / paid-scale deployment

- Real user login
- Full multi-tenant authorization and tenant isolation enforcement
- Billing
- Alembic migrations
- Hosted monitoring and alerting for the POLARIS service itself
- Analyst queues and assignment SLAs
- Customer admin portal
- Legal/compliance review

## Real pilot persistence and Render deployment

In-memory demo mode is only appropriate for the public demo and local product walkthroughs. Because Render web services can restart or scale, in-memory data can disappear. For real pilots, create a Render PostgreSQL instance and set `DATABASE_URL` on the web service so pilot leads, watchlists, alerts, feedback, public metrics, and customer proof inputs persist.

### Real pilot deployment checklist

1. Set `POLARIS_API_KEY` to a strong secret.
2. Set `POLARIS_PROTECT_READS=true` for real customer deployments.
3. Add Render PostgreSQL to the service.
4. Set `DATABASE_URL` from Render PostgreSQL.
5. Set `POLARIS_DEFAULT_ORG` to the pilot customer org slug.
6. Confirm `/health` shows `database=true`.
7. Submit a test lead from `/request-pilot`.
8. Create a watchlist from the dashboard First pilot setup wizard.
9. Generate alerts from the dashboard.
10. Check the customer proof report in the dashboard.
11. Export the proof report.
12. Test Telegram preview/send if `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` exist.

Demo-memory mode is only for the public demo and local walkthroughs. Real pilots must use PostgreSQL. Do not use public demo memory mode for customer data.

### New pilot acquisition endpoints

- `POST /api/leads` is public and returns only `{ "ok": true, "lead_id": "...", "message": "Pilot request received." }`.
- `GET /api/leads`, `PATCH /api/leads/{lead_id}`, and `GET /api/public-metrics` require `X-Polaris-API-Key`.
- `GET /api/reports/customer-proof?org_id=<org_id>&days=7` summarizes monitored items, alert outcomes, top risks/actions, source health, and customer-proof summary text.
- `POST /api/feedback/item/{item_id}` and `GET /api/feedback` collect operator feedback without changing scoring yet.

## Before offering POLARIS to real pilot users

POLARIS can run in demo-memory mode for local evaluation, but real pilot users require persistent storage and protected operator access. Before sharing a customer-facing deployment, verify this checklist:

- `DATABASE_URL` is set to a managed PostgreSQL database.
- `POLARIS_API_KEY` is set to a strong secret and shared only with operators.
- `POLARIS_PROTECT_READS=true` is enabled so sensitive read endpoints require the API key.
- `GET /api/pilot-readiness` returns `ready_for_real_pilot=true`.
- `POST /api/leads` has been tested from the public pilot request form.
- The full pilot workflow has been tested: watchlist -> rematch -> alerts -> proof report.
- A backup and restore plan exists for the PostgreSQL database before real customer data is entered.

Recommended local verification:

```bash
pytest -q
uvicorn src.main:app --reload
```

Then open `/dashboard`, add the API key in the Admin API key field, review the **Pilot readiness** panel, create or update a watchlist, click **Run rematch**, generate alerts, assign an owner, and confirm the customer proof report is populated.


## Toward Recorded Future-style intelligence

POLARIS now has a first serious intelligence layer beyond item listing. It is still intentionally deterministic and explainable for controlled pilot demos, but it can model relationships between risks, evidence, entities, sources, watchlists, clusters, and analyst review work.

Implemented layers today:

- **RSS source monitoring**: configured feeds are ingested, source health is tracked, and source reliability/type metadata is attached to items.
- **Explainable scoring**: each item keeps `risk_factors` and `confidence_factors` so operators can see why risk and confidence changed.
- **Source reliability and evidence fields**: source domains, evidence links, and evidence summaries are returned with intelligence items.
- **CVE enrichment v1**: `POST /api/cves/enrich` scans current items for CVEs and stores deterministic offline enrichment records with severity, exploitation status, CISA KEV placeholder logic, patch status, and sources. Read with `GET /api/cves` and `GET /api/cves/{cve_id}`.
- **Entity graph v1**: `POST /api/graph/rebuild` derives CVE, country, sector, source, watchlist, and alert entities plus relationship edges. Read with `GET /api/graph/entities`, `GET /api/graph/edges`, and `GET /api/graph/entity/{entity_id}`.
- **Incident clustering v1**: `POST /api/clusters/rebuild` groups items sharing CVEs, similar normalized titles, or deterministic country/sector/cyber-term patterns. Clusters expose corroboration levels: `single_source`, `multi_source`, and `strong`.
- **Confidence corroboration**: multi-source clusters add confidence factors without inflating risk score; strong clusters with 3+ sources add a stronger confidence factor.
- **Review queue v1**: `POST /api/review/generate` creates analyst review items for critical items, reported exploited CVEs, strongly corroborated clusters, false-positive feedback, and high-risk claims from low-reliability sources. Read with `GET /api/review`; update with `PATCH /api/review/{review_id}`.
- **Intelligence maturity endpoint**: `GET /api/intelligence-maturity` returns an honest 0-100 score, per-layer levels, blocking gaps, and next actions.
- **Customer proof reports**: `/api/reports/customer-proof` now includes CVEs tracked/enriched, clusters detected, multi-source clusters, review items, false-positive feedback, and intelligence maturity score.

Honest limitations remain:

- No dark web collection.
- No paid threat feeds.
- No full NVD/EPSS integration yet.
- No ML entity resolution yet.
- No real multi-tenant user authentication yet.
- No SIEM, SOAR, ticketing, SSO, or case-management integrations yet.
- No analyst team producing finished intelligence.

Recommended local intelligence-layer workflow:

```bash
pytest -q
uvicorn src.main:app --reload
```

Then, in a separate terminal or API client, run these after ingestion or seeding:

```bash
curl -X POST http://localhost:8000/api/cves/enrich -H "X-Polaris-API-Key: <key>"
curl -X POST http://localhost:8000/api/graph/rebuild -H "X-Polaris-API-Key: <key>"
curl -X POST http://localhost:8000/api/clusters/rebuild -H "X-Polaris-API-Key: <key>"
curl -X POST http://localhost:8000/api/review/generate -H "X-Polaris-API-Key: <key>"
curl http://localhost:8000/api/intelligence-maturity -H "X-Polaris-API-Key: <key>"
```

For Render redeploys, push the committed branch, confirm the Render service uses the same start command (`uvicorn src.main:app --host 0.0.0.0 --port $PORT` or the existing `Procfile`), and verify environment variables: `POLARIS_API_KEY`, `POLARIS_PROTECT_READS=true`, `DATABASE_URL`, and `POLARIS_DEFAULT_ORG`.

## Production Intelligence v2

POLARIS now includes a production-intelligence layer with deterministic offline CVE enrichment by default, in-process background jobs, stricter API-key roles, organization boundary validation, intelligence quality scoring, printable customer reports, and weekly briefs.

### CVE enrichment

- `POST /api/cves/enrich` performs deterministic offline enrichment from currently ingested items for demo/test safety and returns `items_scanned`, `cves_found`, and `cves_enriched`. Pass `{"cve_ids":["CVE-YYYY-NNNN"]}` only to filter that offline scan to specific CVEs already present in items.
- Optional external integration scaffolding lives in `src/services/enrichment.py` and is isolated from the default offline enrichment workflow. It uses timeouts/error isolation for:
  - NVD CVE API (`NVD_API_KEY` optional; unauthenticated public access is attempted when no key is set).
  - CISA Known Exploited Vulnerabilities catalog.
  - FIRST EPSS API.
- External enrichment failures are stored on the CVE record and do not fail the whole application.
- CVE freshness states are `pending`, `fresh`, `stale`, and `failed`; records older than 24 hours are considered stale.

### Background jobs

Use `POST /api/jobs/{job_type}` with an admin or operator key to enqueue non-blocking in-process jobs. Current job types are:

- `feed_refresh`
- `cve_enrichment`
- `graph_rebuild`
- `cluster_rebuild`
- `review_generate`
- `rematch`

Use `GET /api/jobs` and `GET /api/jobs/{job_id}` to inspect status. Jobs are intentionally simple and in-process; Celery/Redis is a future scale-out step.

### API key roles

Role-specific keys are supported without introducing full user auth:

```env
POLARIS_ADMIN_API_KEY=
POLARIS_OPERATOR_API_KEY=
POLARIS_READONLY_API_KEY=
POLARIS_API_KEY=
POLARIS_ALLOWED_ORGS=
NVD_API_KEY=
POLARIS_PROTECT_READS=false
```

`POLARIS_API_KEY` remains a backward-compatible admin fallback when role-specific keys are not configured. Admin can do everything. Operator can manage watchlists, alerts, feedback, jobs, rematch, source configs, and Telegram workflows, but cannot read leads or public metrics. Readonly is accepted only for protected read endpoints when `POLARIS_PROTECT_READS=true`.

### Organization boundaries

Set `POLARIS_ALLOWED_ORGS=demo,customer-a` to reject unsupported `org_id` values with HTTP 400 on write/filter endpoints. When unset, POLARIS keeps legacy flexible demo behavior.

### Database migrations

Startup `init_db()` still creates/updates tables for demo resilience, but real PostgreSQL deployments should run Alembic migrations before starting the app:

```bash
export DATABASE_URL='postgresql://postgres:postgres@localhost:5432/polaris'
alembic upgrade head
uvicorn src.main:app --reload
```

On Render, configure `DATABASE_URL`, API keys, and any feed/enrichment variables, then add `alembic upgrade head` as a pre-deploy or release command before the web service starts. Demo-memory mode does not require Alembic.

### Customer reporting

- `GET /api/reports/customer-proof.html?org_id=demo&days=7` returns clean printable HTML. Use the browser's **Print to PDF** action for PDF output.
- `GET /api/brief/weekly?org_id=demo&days=7` returns a customer-facing weekly brief with top risks, CVEs, exploited CVEs, clusters, alerts, actions, source-health notes, and proof summary.
- `GET /api/intelligence-quality` returns a 0-100 quality score plus gaps and next actions.

### CI

GitHub Actions CI is defined in `.github/workflows/ci.yml` and runs dependency installation, `pytest -q`, and `python -m compileall src` without requiring secrets.
