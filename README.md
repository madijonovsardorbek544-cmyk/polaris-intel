# POLARIS

POLARIS is a FastAPI-based cyber and geopolitical risk intelligence app.

## What it does
- ingests RSS intelligence sources
- stores normalized intelligence items in SQLite or Postgres
- scores each item with a simple keyword-based risk model
- exposes JSON APIs for dashboard, items, sources, and refresh actions
- renders a dark dashboard UI for reviewing prioritized signals

## Current status
This is an MVP foundation, not a finished enterprise platform.

## Stack
- FastAPI
- SQLModel
- SQLite by default
- Jinja2 templates
- Feedparser

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open:
- http://127.0.0.1:8000
- http://127.0.0.1:8000/health
- http://127.0.0.1:8000/api/v1/dashboard

## Environment
Copy `.env.example` and set values as needed.

Important:
- `DATABASE_URL` is optional. If missing, SQLite is used.
- `POLARIS_ADMIN_TOKEN` protects write actions if you set it.

## Write-protected endpoints
If `POLARIS_ADMIN_TOKEN` is set, send it as:
```http
x-admin-token: your-token
```

Protected routes:
- `POST /api/v1/refresh`
- `POST /api/v1/sources`
- `PATCH /api/v1/sources/{source_id}`
- `POST /api/v1/sources/{source_id}/refresh`

## Example queries
```bash
curl http://127.0.0.1:8000/api/v1/items?min_risk=65
curl http://127.0.0.1:8000/api/v1/items?category=cyber
curl http://127.0.0.1:8000/api/v1/items?severity=critical
```

## Next serious upgrades
- authentication and RBAC
- background scheduler for automated refresh
- better deduplication
- source management UI
- analyst watchlists and saved filters
- tests
- deployment pipeline
