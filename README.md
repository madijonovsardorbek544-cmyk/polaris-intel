# POLARIS Intel

## Live Demo

Live demo: https://polaris-intel.onrender.com

POLARIS Intel is a **single-org pilot deployment product** for explainable cyber-geopolitical intelligence. It ingests RSS feeds, extracts observable risk signals, tracks source health, applies deterministic risk and confidence scoring, matches intelligence against operator watchlists, persists alerts, and presents a FastAPI/Jinja2 dashboard for controlled pilot deployments.

POLARIS is **not enterprise-grade multi-tenant SaaS yet**. It does not claim to be an AI analyst, SOAR platform, SIEM replacement, or fully managed threat-intelligence product. This version is built for one pilot organization at a time, with honest limits and simple operator controls.

## What is implemented

- FastAPI application with Jinja2 dashboard.
- `.env`-based local configuration via `python-dotenv` support when installed.
- RSS ingestion with typed feed fetch results and explicit failed/empty feed tracking.
- Optional PostgreSQL persistence for intelligence items, watchlists, source health, and alerts.
- In-memory demo mode when `DATABASE_URL` is not set.
- Entity extraction for CVEs, selected countries/blocs, sectors, and cyber terms.
- Deterministic item classification, risk scoring, confidence scoring, and explainability factors.
- Watchlists for countries, sectors, organizations, keywords, CVEs, and threat actors.
- Tenant-ready `org_id` fields on watchlists, alerts, and watchlist matches.
- Single-org deployment defaults through `POLARIS_DEFAULT_ORG`.
- Dashboard Active `org_id` context so operator reads use one visible org filter.
- API-key protection for write operations using `POLARIS_API_KEY` and `X-Polaris-API-Key`.
- Optional API-key protection for read operations with `POLARIS_PROTECT_READS=true`.
- Persistent alert workflow with `open`, `acknowledged`, and `resolved` statuses plus notes.
- Alert preview generation, persistent alert generation, and Telegram message preview without sending.
- Daily brief endpoint with top risks, affected countries/sectors, recommended actions, source failures, and empty sources.
- Demo reset endpoint for in-memory pilot demos only.

## What is still future work

Before a real paid pilot, POLARIS still needs full multi-tenant SaaS isolation, real user login, role-based access control, billing/subscriptions, production monitoring and alerting, backups, rate limits, real Telegram sending, analyst queues, assignment workflows, escalation policies, and a stronger operational security review.

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

- `POLARIS_API_KEY`: optional API key. If empty, demo writes are allowed. If set, protected requests must include `X-Polaris-API-Key: <key>`.
- `POLARIS_PROTECT_READS`: default `false`. When `true` and `POLARIS_API_KEY` is set, read endpoints require `X-Polaris-API-Key` too.
- `POLARIS_DEFAULT_ORG`: default single-org context for the dashboard and omitted watchlist `org_id` values. Defaults to `demo`.
- `TELEGRAM_BOT_TOKEN`: reserved for future Telegram delivery; preview formatting does not send messages.
- `TELEGRAM_CHAT_ID`: reserved for future Telegram delivery; preview formatting does not send messages.
- `PORT`: default HTTP port for deployment commands.
- `DATABASE_URL`: when set, POLARIS uses PostgreSQL and creates/updates required tables at startup.
- `MAX_ITEMS`: maximum number of intelligence items returned/stored in memory.
- `AUTO_REFRESH_SECONDS`: background refresh interval.
- `HTTP_TIMEOUT`: RSS HTTP request timeout in seconds.
- `FEEDS`: optional comma-separated RSS feed override. If empty, built-in cyber and world-news feeds are used.
- `LOG_LEVEL`: standard Python logging level.

The environment block above intentionally matches `.env.example` exactly.

## Dashboard org context

The dashboard sidebar has an **Active org_id** input. It defaults to `POLARIS_DEFAULT_ORG`, stores the current value in `sessionStorage`, displays the active org near the top of the dashboard, and reloads dashboard data when changed.

Dashboard read calls include the active org where supported:

- `/api/items?org_id=<activeOrg>`
- `/api/alerts?org_id=<activeOrg>`
- `/api/brief/daily?org_id=<activeOrg>`
- `/api/watchlists?org_id=<activeOrg>`

Watchlist creation also defaults to the active org. This avoids mixed-org dashboard data during a single-org pilot.

## Demo mode vs database mode

### Demo/in-memory mode

If `DATABASE_URL` is empty, POLARIS runs without PostgreSQL. Items, source health, watchlists, and alerts are stored in process memory and reset when the server restarts.

Demo mode also enables:

- `POST /api/demo/reset` — protected by `POLARIS_API_KEY` when configured. It clears in-memory items, watchlists, source health, and alerts for live demo resets without restarting the server.

If `DATABASE_URL` is set, `POST /api/demo/reset` returns HTTP 400 with `Demo reset is disabled in database mode.`

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
export POLARIS_PROTECT_READS=true
export POLARIS_DEFAULT_ORG='pilot-customer'
uvicorn src.main:app --reload
```

## API-key protection

Write endpoints require `X-Polaris-API-Key` when `POLARIS_API_KEY` is configured:

- `POST /api/watchlists`
- `PUT /api/watchlists/{id}`
- `DELETE /api/watchlists/{id}`
- `POST /api/refresh`
- `POST /api/seed`
- `POST /api/alerts/generate`
- `PATCH /api/alerts/{id}`
- `POST /api/alerts/{id}/telegram-preview`
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

- `GET /` — dashboard UI rendered from `src/templates/index.html`.
- `GET /health` — service health with storage mode, API-key configuration flag, read-protection flag, default org, feed count, item count, alert count, and source count.
- `POST /api/demo/reset` — demo-memory reset. Protected by API key. Disabled in database mode.

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

The dashboard can generate persistent alerts, filter persisted/preview alerts, search title/reason/watchlist text, edit alert notes/status, and preview Telegram formatting. It does **not** send Telegram messages.

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

Replace the README placeholder line `Live demo: Coming soon. Deploy using the instructions below.` with your deployed Render URL, for example `Live demo: https://your-service-name.onrender.com`.

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

Telegram previews remain available. Real sending is enabled safely with:

```bash
TELEGRAM_BOT_TOKEN=<bot-token>
TELEGRAM_CHAT_ID=<chat-id>
```

Use `POST /api/alerts/{id}/telegram-send` with the write API key. If either variable is missing, POLARIS returns a clear `400` and records a `telegram_failed` event. Tokens and chat IDs are never shown in the dashboard.

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
