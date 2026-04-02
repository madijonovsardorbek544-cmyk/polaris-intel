from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session

from app.db import engine, get_session, init_db
from app.schemas import SourceCreate, SourceUpdate
from app.security import require_admin_token
from app.services import (
    create_source,
    ensure_default_sources,
    ingest_all_sources,
    ingest_source_by_id,
    list_items as list_filtered_items,
    list_sources as get_sources,
    make_dashboard_summary,
    update_source,
)


templates = Jinja2Templates(directory="templates")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with Session(engine) as session:
        ensure_default_sources(session)
    yield


app = FastAPI(
    title="POLARIS",
    version="1.1.0",
    summary="Political and cyber risk intelligence system",
    lifespan=lifespan,
)


@app.get("/health")
def healthcheck() -> dict:
    return {"ok": True, "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/v1/dashboard")
def dashboard(session: Session = Depends(get_session)) -> dict:
    summary = make_dashboard_summary(session)
    recent_items = list_filtered_items(session, limit=25)
    return {"summary": summary, "items": recent_items}


@app.get("/api/v1/items")
def list_items(
    limit: int = Query(default=50, ge=1, le=200),
    q: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    source_name: str | None = None,
    min_risk: int | None = Query(default=None, ge=0, le=100),
    session: Session = Depends(get_session),
):
    return list_filtered_items(
        session,
        limit=limit,
        q=q,
        category=category,
        severity=severity,
        source_name=source_name,
        min_risk=min_risk,
    )


@app.get("/api/v1/sources")
def list_sources(enabled_only: bool = False, session: Session = Depends(get_session)):
    return get_sources(session, enabled_only=enabled_only)


@app.post("/api/v1/sources")
def add_source(
    payload: SourceCreate,
    _: None = Depends(require_admin_token),
    session: Session = Depends(get_session),
):
    return create_source(session, payload)


@app.patch("/api/v1/sources/{source_id}")
def patch_source(
    source_id: int,
    payload: SourceUpdate,
    _: None = Depends(require_admin_token),
    session: Session = Depends(get_session),
):
    source = update_source(session, source_id, payload)
    if source is None:
        raise HTTPException(status_code=404, detail="source not found")
    return source


@app.post("/api/v1/refresh")
def refresh_all(
    _: None = Depends(require_admin_token),
    session: Session = Depends(get_session),
):
    stats = ingest_all_sources(session)
    return {"ok": True, **stats}


@app.post("/api/v1/sources/{source_id}/refresh")
def refresh_source(
    source_id: int,
    _: None = Depends(require_admin_token),
    session: Session = Depends(get_session),
):
    result = ingest_source_by_id(session, source_id)
    if result is None:
        raise HTTPException(status_code=404, detail="source not found")
    return {"ok": True, **result}


@app.get("/", response_class=HTMLResponse)
def home(request: Request, session: Session = Depends(get_session)):
    summary = make_dashboard_summary(session)
    items = list_filtered_items(session, limit=20)
    sources = get_sources(session)
    critical_items = [item for item in items if item.risk_score >= 80]
    high_items = [item for item in items if 65 <= item.risk_score < 80]
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "summary": summary,
            "items": items,
            "sources": sources,
            "critical_items": critical_items,
            "high_items": high_items,
        },
    )
