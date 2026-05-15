# POLARIS — Political & Cyber Risk Intelligence System

POLARIS is a unified cyber–geopolitical intelligence platform that ingests open-source RSS/Atom feeds, classifies each item, assigns a rule-based risk score, and presents the results through a FastAPI API and web dashboard.

## Core Capabilities
- Cyber threat intelligence aggregation
- Geopolitical and diplomatic risk monitoring
- Rule-based category classification and risk scoring
- CVE, source, and keyword tag extraction
- Optional PostgreSQL persistence through `DATABASE_URL`
- Browser dashboard plus JSON API endpoints

## Tech Stack
- Python 3.12
- FastAPI and Uvicorn
- Jinja2 templates
- HTTPX feed fetching
- psycopg/PostgreSQL persistence

## Project Layout
```text
src/
  main.py                 FastAPI routes and application wiring
  core/config.py          Environment-driven app settings and feed list
  core/database.py        PostgreSQL table initialization and item persistence
  models/intel.py         Intelligence item data model
  services/intel_service.py  Refresh, cache, seed, and feed orchestration
  services/risk_engine.py Risk category, score, level, and tag rules
  services/rss.py         RSS/Atom parser
  templates/index.html    Dashboard UI
  utils/text.py           Text cleanup and URL helpers
```

## API Endpoints
- `GET /` — dashboard
- `GET /health` — app, feed, database, and cache status
- `GET /api/latest` — latest intelligence items as JSON
- `POST /api/refresh` — force a feed refresh
- `POST /api/seed` — load demo records for local testing

## Configuration
Environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `APP_NAME` | `POLARIS Intel` | Display/API app name |
| `APP_VERSION` | `2.1.0` | FastAPI version metadata |
| `MAX_ITEMS` | `60` | Maximum cached/displayed intelligence records |
| `AUTO_REFRESH_SECONDS` | `900` | Background refresh interval |
| `HTTP_TIMEOUT` | `15` | Feed request timeout in seconds |
| `DATABASE_URL` | empty | Optional PostgreSQL connection string |
| `FEEDS` | built-in OSINT feed list | Comma-separated custom feed URLs |

## Local Run
```bash
python -m pip install -r requirements.txt
uvicorn src.main:app --reload
```

Then open `http://127.0.0.1:8000`.

## Project Status
MVP — active development.

## Author
Sardorbek Madijonov  
Founder & Developer
