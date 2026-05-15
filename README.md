# POLARIS Intel

POLARIS Intel is a **paid pilot-ready foundation** for cyber-geopolitical risk intelligence. It ingests RSS sources, extracts observable risk signals, applies transparent rule-based scoring, tracks source health, matches items to customer watchlists, generates alert-ready records, and presents everything in a FastAPI/Jinja2 dashboard.

POLARIS is **not an enterprise platform yet** and does not claim fake AI analysis. The current product is a practical foundation for first pilot users who need explainable monitoring, triage, and daily brief workflows.

## Implemented now

- FastAPI API with Jinja2 dashboard.
- RSS ingestion with source health tracking and logging.
- In-memory demo mode plus optional PostgreSQL persistence.
- Rule-based classification: `Cyber`, `Geopolitics`, `Hybrid`, `General`.
- Entity extraction for:
  - CVEs by regex.
  - Countries/blocs: Uzbekistan, Kazakhstan, Russia, Ukraine, China, Taiwan, USA, Iran, Israel, NATO, EU.
  - Sectors: banking, education, government, energy, telecom, healthcare, logistics, defense.
  - Cyber terms: ransomware, phishing, malware, exploit, zero-day, DDoS, credential leak, breach.
- Explainable risk and confidence scoring with `risk_factors` and `confidence_factors`.
- Watchlists for countries, sectors, organizations, keywords, CVEs, and threat actors.
- Watchlist match explanations showing which watchlist matched and why.
- Alert-ready API records for Critical/High watchlist matches.
- Daily brief API with top risks, countries/sectors affected, recommended actions, and source failures.
- Dashboard search, filters, stats, source health, alerts, daily brief, risk factors, watchlist badges, and responsive cards.
- Pytest coverage for extraction, scoring, .env loading, logging behavior, alerts, daily brief, deduplication, and watchlist updates.

## Still future / not enterprise yet

- User accounts, RBAC, tenant isolation, audit logs.
- Human analyst workflow: assignment, notes, acknowledgement, SLA status.
- Email/Slack/webhook delivery for alerts and daily briefs.
- Admin UI for feed/source configuration and source reliability tuning.
- Production migrations, backups, and operational dashboards.
- Advanced NLP/ML enrichment or LLM summarization with citations.

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
    ingestion.py
    analysis.py
    briefing.py
  routes/
    health.py
    intelligence.py
    watchlists.py
  templates/
    index.html
tests/
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn src.main:app --reload
```

Open the dashboard at <http://127.0.0.1:8000/>.

## Configuration

Local development reads `.env` automatically using `python-dotenv` when available. Existing process environment variables are not overridden.

```env
PORT=8000
DATABASE_URL=
MAX_ITEMS=60
AUTO_REFRESH_SECONDS=900
HTTP_TIMEOUT=15
FEEDS=
LOG_LEVEL=INFO
```

- `DATABASE_URL`: if set, PostgreSQL is used and tables are created/updated automatically.
- `MAX_ITEMS`: max intelligence items to keep/return.
- `AUTO_REFRESH_SECONDS`: background refresh interval.
- `HTTP_TIMEOUT`: RSS HTTP timeout in seconds.
- `FEEDS`: optional comma-separated RSS feed override.
- `LOG_LEVEL`: Python logging level.

## Demo mode vs database mode

### Demo/in-memory mode

If `DATABASE_URL` is empty, POLARIS stores items, watchlists, and source health in process memory. This is best for demos and development; data resets on restart.

### PostgreSQL mode

If `DATABASE_URL` is set, POLARIS persists intelligence items and watchlists in PostgreSQL and creates required tables automatically.

```bash
export DATABASE_URL='postgresql://postgres:postgres@localhost:5432/polaris'
uvicorn src.main:app --reload
```

Source health is intentionally lightweight and process-local in this version.

## API endpoints

### System

- `GET /` — dashboard UI.
- `GET /health` — service health, feed count, failed feed count, item count, and storage mode.

### Intelligence

- `GET /api/latest` — latest intelligence items; kept for backward compatibility.
- `GET /api/items` — filterable intelligence items.
  - Query params: `q`, `category`, `risk_level`, `country`, `sector`, `limit`.
- `GET /api/items/{id}` — one intelligence item.
- `GET /api/stats` — counts by category/risk plus top countries and sectors.
- `GET /api/summary` — short executive summary and top high-priority items.
- `POST /api/refresh` — force RSS refresh.
- `POST /api/seed` — load deterministic sample intelligence items.

### Source health

- `GET /api/sources` — lightweight source status records:
  - `source_url`
  - `last_success_at`
  - `last_failure_at`
  - `failure_count`
  - `last_error`

### Watchlists

- `POST /api/watchlists` — create a watchlist.
- `GET /api/watchlists` — list watchlists.
- `GET /api/watchlists/{id}` — get one watchlist.
- `PUT /api/watchlists/{id}` — replace/update one watchlist.
- `DELETE /api/watchlists/{id}` — delete one watchlist.

Example payload:

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

- `GET /api/alerts` — alert-ready records generated from Critical/High items that match at least one watchlist.

Each alert includes:

- `item_id`
- `title`
- `risk_level`
- `matched_watchlist`
- `reason`
- `recommended_action`
- `created_at`

### Daily brief

- `GET /api/brief/daily` — pilot-friendly daily brief response containing:
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

Current tests cover:

- `.env` loading behavior.
- Source failure logging and source health updates.
- Risk-factor and confidence-factor generation.
- CVE, country, and sector extraction.
- Risk thresholds and watchlist risk boost.
- Alert generation.
- Daily brief generation.
- Deduplication.
- Watchlist update.

## Deployment notes

A simple pilot deployment should:

1. Install dependencies from `requirements.txt`.
2. Set environment variables, especially `DATABASE_URL` for persistence.
3. Run FastAPI behind a platform-managed HTTPS endpoint.
4. Run the ASGI command:

```bash
uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8000}
```

For paid pilots, add backups, authentication, analyst workflow, and alert delivery before expanding usage.
