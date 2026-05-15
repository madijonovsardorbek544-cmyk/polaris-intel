# POLARIS Intel

POLARIS Intel is a **usable first pilot operator product** for an explainable cyber-geopolitical intelligence dashboard. It ingests RSS feeds, extracts observable risk signals, tracks source health, applies deterministic risk and confidence scoring, matches items against customer watchlists, persists an alert workflow, and presents pilot-ready intelligence in a FastAPI/Jinja2 dashboard.

POLARIS is **not enterprise-grade yet**. It does not claim to be an AI analyst, SOAR platform, SIEM replacement, or fully managed threat-intelligence product. This version is intended to support first pilot-operator workflows and controlled deployments with honest limitations.

## What is implemented

- FastAPI application with Jinja2 dashboard.
- `.env`-based local configuration via `python-dotenv` support.
- RSS ingestion with typed feed fetch results and explicit failed/empty feed tracking.
- Optional PostgreSQL persistence for intelligence items, watchlists, source health, and alerts.
- In-memory mode for fast local demos when `DATABASE_URL` is not set.
- Entity extraction for CVEs, selected countries/blocs, sectors, and cyber terms.
- Deterministic item classification: `Cyber`, `Geopolitics`, `Hybrid`, or `General`.
- Explainable scoring fields:
  - `risk_factors`, for example `CISA source reliability +22`, `CVE detected +15`, `Watchlist match +12`.
  - `confidence_factors`, for example source corroboration, structured entity detection, and summary clarity.
- Watchlists for countries, sectors, organizations, keywords, CVEs, and threat actors.
- Tenant-ready `org_id` fields on watchlists, alerts, and watchlist matches. The default org is `demo`.
- Minimal API-key protection for write operations using `POLARIS_API_KEY` and `X-Polaris-API-Key`.
- Watchlist match explanations showing which watchlist matched and why.
- Persistent alert workflow with `open`, `acknowledged`, and `resolved` statuses plus notes.
- Telegram-ready alert message formatting, without real bot delivery yet.
- Daily brief endpoint with top risks, affected countries/sectors, recommended actions, source failures, and empty sources.
- Responsive dashboard panels for source health, risk factors, watchlist badges, alerts, daily brief, watchlist management, and persistent alert workflow actions.
- Tests for API endpoints, `.env` loading, source failure logging, factors, alerts, daily brief, watchlist update, scoring, entities, deduplication, and Telegram alert formatting.

## What is still future work

- Full authentication, authorization, tenant isolation, and role-based access control.
- Billing, subscriptions, and customer self-service administration.
- Analyst assignments, queues, SLAs, escalation policies, and production case management.
- Production monitoring, metrics, tracing, alerting, backups, rate limits, and disaster recovery.
- Real notification delivery: Telegram bot, email, Slack, Teams, webhook, Jira, ServiceNow.
- Stronger source normalization, feed quality controls, and source-specific parsers.
- Customer-specific scoring calibration and explainability tuning.
- Enterprise deployment hardening: managed migrations, observability, secrets handling, and SSO.
- Human-reviewed intelligence production process and legal/compliance review.

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

Open the dashboard at <http://127.0.0.1:8000/>.

## Configuration

Create a local `.env` file if you want to override defaults:

```env
POLARIS_API_KEY=
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

- `POLARIS_API_KEY`: optional API key for write operations. If empty, demo-mode writes are allowed. If set, write requests must include `X-Polaris-API-Key: <key>`.
- `TELEGRAM_BOT_TOKEN`: reserved for future Telegram delivery; preview formatting does not send messages.
- `TELEGRAM_CHAT_ID`: reserved for future Telegram delivery; preview formatting does not send messages.
- `PORT`: default HTTP port for deployment commands; `.env.example` sets `PORT=8000`.
- `DATABASE_URL`: when set, POLARIS uses PostgreSQL and creates/updates required tables at startup.
- `MAX_ITEMS`: maximum number of intelligence items returned/stored in memory.
- `AUTO_REFRESH_SECONDS`: background refresh interval.
- `HTTP_TIMEOUT`: RSS HTTP request timeout in seconds.
- `FEEDS`: optional comma-separated RSS feed override. If empty, built-in cyber and world-news feeds are used.
- `LOG_LEVEL`: standard Python logging level.

The environment block above intentionally matches `.env.example` exactly.

## Demo mode vs database mode

### Demo/in-memory mode

If `DATABASE_URL` is empty, POLARIS runs without PostgreSQL. Items, source health, watchlists, and alerts are stored in process memory and reset when the server restarts. This is the easiest local pilot-demo mode.

If `POLARIS_API_KEY` is empty, write endpoints remain open for demo use. Set `POLARIS_API_KEY` before exposing a pilot instance.

### PostgreSQL mode

If `DATABASE_URL` is set, POLARIS creates/updates these tables automatically:

- `intel_items`
- `watchlists`
- `source_health`
- `alerts`

Example:

```bash
export DATABASE_URL='postgresql://postgres:postgres@localhost:5432/polaris'
export POLARIS_API_KEY='replace-me'
uvicorn src.main:app --reload
```

## API-key protected write operations

These endpoints require `X-Polaris-API-Key` when `POLARIS_API_KEY` is configured:

- `POST /api/watchlists`
- `PUT /api/watchlists/{id}`
- `DELETE /api/watchlists/{id}`
- `POST /api/refresh`
- `POST /api/seed`
- `POST /api/alerts/generate`
- `PATCH /api/alerts/{id}`
- `POST /api/alerts/{id}/telegram-preview`

Read-only endpoints are not blocked.

## API endpoints

### System

- `GET /` — dashboard UI rendered from `src/templates/index.html`.
- `GET /health` — service health, feed count, item count, storage mode.

### Intelligence

- `GET /api/latest` — latest intelligence items, kept for backward compatibility.
- `GET /api/items` — filterable intelligence items.
  - Query params: `q`, `category`, `risk_level`, `country`, `sector`, `org_id`, `limit`.
- `GET /api/items/{id}` — one intelligence item by ID.
- `GET /api/stats` — counts by category/risk plus top countries and sectors.
- `GET /api/summary` — short executive summary and top high-priority items.
- `POST /api/refresh` — force RSS refresh.
- `POST /api/seed` — load deterministic sample intelligence items.

### Source health

- `GET /api/sources` — source health records.

Example response item:

```json
{
  "source_url": "https://www.cisa.gov/news-events/alerts.xml",
  "last_success_at": "2026-05-15T12:00:00+00:00",
  "last_failure_at": null,
  "last_empty_at": null,
  "total_failure_count": 0,
  "consecutive_failure_count": 0,
  "empty_count": 0,
  "last_error": null,
  "status": "healthy"
}
```

Source status rules:

- `failing` if `last_error` exists.
- `empty` if `last_empty_at` is newer than `last_success_at`.
- `healthy` if `last_success_at` exists and there is no current error.
- `pending` if the source has never been checked.

### Watchlists

- `POST /api/watchlists` — create a watchlist.
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

- `GET /api/alerts` — returns both persisted alerts and generated Critical/High watchlist-matched previews in one object. Optional query param: `org_id`.
- `GET /api/alerts/flat` — compatibility endpoint returning the old flat list behavior: persisted alerts when present, otherwise generated previews. Optional query param: `org_id`.
- `GET /api/alerts/{id}` — retrieve one persisted or generated alert.
- `POST /api/alerts/generate` — persist alert records for current Critical/High watchlist-matched items and return `ok`, `created`, `existing`, and `alerts`.
- `PATCH /api/alerts/{id}` — update alert `status` and/or `notes`.
- `POST /api/alerts/{id}/telegram-preview` — return the Telegram-formatted alert message without sending anything.

Each alert includes:

- `id`
- `item_id`
- `title`
- `risk_level`
- `matched_watchlist_id`
- `matched_watchlist_name`
- `reason`
- `recommended_action`
- `status`
- `created_at`
- `updated_at`
- `notes`
- `org_id`

### Daily brief

- `GET /api/brief/daily` — pilot-friendly summary for analyst review. Optional query param: `org_id`.

The response includes:

- `headline_summary`
- `top_5_risks`
- `countries_affected`
- `sectors_affected`
- `recommended_actions`
- `source_failures`
- `empty_sources`

## Testing

```bash
pytest -q
```

The suite covers scoring, entity extraction, watchlist matching, `.env` loading, source failure logging, explainability factors, alert generation and persistence, daily brief generation, watchlist CRUD endpoints, API endpoint smoke tests, deduplication, and Telegram alert formatting. Tests use isolated in-memory state and do not require real network calls.

## Deployment notes

A simple pilot deployment should:

1. Install `requirements.txt`.
2. Set environment variables, especially `DATABASE_URL` for persistence and `POLARIS_API_KEY` for write protection.
3. Run with a production ASGI server command such as:

```bash
uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8000}
```

For platforms with a `Procfile`, ensure it points to `uvicorn src.main:app` and provides `PORT`.
