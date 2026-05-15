# POLARIS Intel

POLARIS Intel is a **paid pilot-ready foundation** for an explainable cyber-geopolitical intelligence dashboard. It ingests RSS feeds, extracts observable risk signals, tracks source health, applies deterministic risk and confidence scoring, matches items against customer watchlists, and presents alert-ready intelligence in a FastAPI/Jinja2 dashboard.

POLARIS is **not enterprise-grade yet**. It does not claim to be an AI analyst, SOAR platform, SIEM replacement, or fully managed threat-intelligence product. This version is intended to support first paid pilot conversations, workflow validation, and controlled deployments with clear limitations.

## What is implemented

- FastAPI application with Jinja2 dashboard.
- `.env`-based local configuration via `python-dotenv` support.
- RSS ingestion with explicit refresh logging and source failure tracking.
- Optional PostgreSQL persistence for intelligence items, watchlists, and source health.
- In-memory mode for fast local demos when `DATABASE_URL` is not set.
- Entity extraction for CVEs, selected countries/blocs, sectors, and cyber terms.
- Deterministic item classification: `Cyber`, `Geopolitics`, `Hybrid`, or `General`.
- Explainable scoring fields:
  - `risk_factors`, for example `CISA source reliability +22`, `CVE detected +15`, `Watchlist match +12`.
  - `confidence_factors`, for example source corroboration, structured entity detection, and summary clarity.
- Watchlists for countries, sectors, organizations, keywords, CVEs, and threat actors.
- Watchlist match explanations showing which watchlist matched and why.
- Alert-ready logic for Critical/High items that match a watchlist.
- Daily brief endpoint with top risks, affected countries/sectors, recommended actions, and source failures.
- Responsive dashboard panels for source health, risk factors, watchlist badges, alerts, and daily brief.
- Tests for `.env` loading, source failure logging, factors, alerts, daily brief, watchlist update, scoring, entities, and deduplication.

## What is still future work

- Authentication, authorization, tenants, and role-based access control.
- Production audit trails and immutable alert/event history.
- Real notification delivery: email, Slack, Teams, webhook, Jira, ServiceNow.
- Analyst workflow: assignments, status, notes, acknowledgements, and escalation state.
- Stronger source normalization, feed quality controls, and source-specific parsers.
- Customer-specific scoring calibration and explainability tuning.
- Enterprise deployment hardening: migrations, observability, backups, rate limits, and SSO.
- Human-reviewed intelligence production process and legal/compliance review.

## Project structure

```text
src/
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
PORT=8000
DATABASE_URL=
MAX_ITEMS=60
AUTO_REFRESH_SECONDS=900
HTTP_TIMEOUT=15
FEEDS=
LOG_LEVEL=INFO
```

- `DATABASE_URL`: when set, POLARIS uses PostgreSQL and creates/updates required tables at startup.
- `MAX_ITEMS`: maximum number of intelligence items returned/stored in memory.
- `AUTO_REFRESH_SECONDS`: background refresh interval.
- `HTTP_TIMEOUT`: RSS HTTP request timeout in seconds.
- `FEEDS`: optional comma-separated RSS feed override. If empty, built-in cyber and world-news feeds are used.
- `LOG_LEVEL`: standard Python logging level.

## Demo mode vs database mode

### Demo/in-memory mode

If `DATABASE_URL` is empty, POLARIS runs without PostgreSQL. Items, source health, and watchlists are stored in process memory and reset when the server restarts. This is the easiest local pilot-demo mode.

### PostgreSQL mode

If `DATABASE_URL` is set, POLARIS creates/updates these tables automatically:

- `intel_items`
- `watchlists`
- `source_health`

Example:

```bash
export DATABASE_URL='postgresql://postgres:postgres@localhost:5432/polaris'
uvicorn src.main:app --reload
```

## API endpoints

### System

- `GET /` — dashboard UI rendered from `src/templates/index.html`.
- `GET /health` — service health, feed count, item count, storage mode.

### Intelligence

- `GET /api/latest` — latest intelligence items, kept for backward compatibility.
- `GET /api/items` — filterable intelligence items.
  - Query params: `q`, `category`, `risk_level`, `country`, `sector`, `limit`.
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
  "failure_count": 0,
  "last_error": null
}
```

### Watchlists

- `POST /api/watchlists` — create a watchlist.
- `GET /api/watchlists` — list watchlists.
- `GET /api/watchlists/{id}` — retrieve watchlist detail.
- `PUT /api/watchlists/{id}` — replace/update a watchlist while keeping the same ID and creation timestamp.
- `DELETE /api/watchlists/{id}` — delete a watchlist.

Example watchlist payload:

```json
{
  "name": "Central Asia energy exposure",
  "countries": ["Kazakhstan", "Uzbekistan"],
  "sectors": ["energy", "telecom"],
  "organizations": [],
  "keywords": ["pipeline", "sanction"],
  "cves": ["CVE-2026-12345"],
  "threat_actors": []
}
```

### Alerts

- `GET /api/alerts` — generated from `Critical`/`High` intelligence items that match at least one watchlist.

Each alert includes:

- `item_id`
- `title`
- `risk_level`
- `matched_watchlist`
- `reason`
- `recommended_action`
- `created_at`

### Daily brief

- `GET /api/brief/daily` — pilot-friendly summary for analyst review.

The response includes:

- `headline_summary`
- `top_5_risks`
- `countries_affected`
- `sectors_affected`
- `recommended_actions`
- `source_failures`

## Testing

```bash
pytest -q
```

The suite covers scoring, entity extraction, watchlist matching, `.env` loading, source failure logging, explainability factors, alert generation, daily brief generation, and watchlist updates.

## Deployment notes

A simple pilot deployment should:

1. Install `requirements.txt`.
2. Set environment variables, especially `DATABASE_URL` for persistence.
3. Run with a production ASGI server command such as:

```bash
uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8000}
```

For platforms with a `Procfile`, ensure it points to `uvicorn src.main:app` and provides `PORT`.
