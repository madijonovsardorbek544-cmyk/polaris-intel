# POLARIS Intel

POLARIS Intel is a FastAPI cyber-geopolitical intelligence MVP. It ingests RSS feeds, extracts observable risk signals, assigns transparent rule-based risk and confidence scores, and presents the results in a mobile-friendly dashboard.

The project does **not** claim to be an AI analyst or an enterprise threat-intelligence platform. POLARIS v1 is an explainable, deterministic intelligence dashboard designed for local demos, product validation, and future integration work.

## What POLARIS does

- Ingests cyber and geopolitical RSS feeds.
- Deduplicates intelligence items by title and source URL.
- Classifies items as `Cyber`, `Geopolitics`, `Hybrid`, or `General`.
- Extracts:
  - CVEs by regex.
  - Countries and blocs: Uzbekistan, Kazakhstan, Russia, Ukraine, China, Taiwan, USA, Iran, Israel, NATO, EU.
  - Sectors: banking, education, government, energy, telecom, healthcare, logistics, defense.
  - Cyber terms: ransomware, phishing, malware, exploit, zero-day, DDoS, credential leak, breach.
- Scores risk using CVEs, active exploitation, ransomware, zero-day language, source reliability, country/sector exposure, geopolitical escalation words, and watchlist relevance.
- Scores confidence using source reliability, extracted entity count, title/summary clarity, and matching risk signals.
- Explains each item with `why_it_matters` and `recommended_action` fields.
- Supports simple watchlists for countries, sectors, organizations, keywords, CVEs, and threat actors.

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

`.env.example` documents supported environment variables:

```env
PORT=8000
DATABASE_URL=
MAX_ITEMS=60
AUTO_REFRESH_SECONDS=900
HTTP_TIMEOUT=15
FEEDS=
LOG_LEVEL=INFO
```

- `DATABASE_URL`: when set, POLARIS uses PostgreSQL and creates tables automatically at startup.
- `MAX_ITEMS`: maximum number of intelligence items returned/stored in memory.
- `AUTO_REFRESH_SECONDS`: background refresh interval.
- `HTTP_TIMEOUT`: RSS HTTP request timeout in seconds.
- `FEEDS`: optional comma-separated RSS feed override. If empty, built-in cyber and world-news feeds are used.

## Demo mode vs database mode

### Demo/in-memory mode

If `DATABASE_URL` is empty, POLARIS runs without PostgreSQL. Items and watchlists are stored in process memory and reset when the server restarts. This is the easiest local demo mode.

### PostgreSQL mode

If `DATABASE_URL` is set, POLARIS creates `intel_items` and `watchlists` tables automatically and persists ingested items/watchlists.

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

### Watchlists

- `POST /api/watchlists` — create a watchlist.
- `GET /api/watchlists` — list watchlists.
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

## Testing

```bash
pytest -q
```

Tests cover risk scoring, risk-level thresholds, CVE extraction, country extraction, sector extraction, deduplication, and watchlist relevance.

## Deployment notes

A simple production deployment should:

1. Install `requirements.txt`.
2. Set environment variables, especially `DATABASE_URL` for persistence.
3. Run with a production ASGI server command such as:

```bash
uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8000}
```

For platforms with a `Procfile`, ensure it points to `uvicorn src.main:app` and provides `PORT`.
