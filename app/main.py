from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from app.db import engine, get_session, init_db
from app.models import FeedSource, IntelItem
from app.services import ensure_default_sources, ingest_all_sources, ingest_source_by_id, make_dashboard_summary


templates = Jinja2Templates(directory="templates")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with Session(engine) as session:
        ensure_default_sources(session)
    yield


app = FastAPI(
    title="POLARIS",
    version="1.0.0",
    summary="Political and cyber risk intelligence system",
    lifespan=lifespan,
)


@app.get("/health")
def healthcheck() -> dict:
    return {"ok": True, "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/v1/dashboard")
def dashboard(session: Session = Depends(get_session)) -> dict:
    summary = make_dashboard_summary(session)
    recent_items = session.exec(select(IntelItem).order_by(IntelItem.published_at.desc()).limit(25)).all()
    return {"summary": summary, "items": recent_items}


@app.get("/api/v1/items")
def list_items(limit: int = 50, session: Session = Depends(get_session)):
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 200")
    return session.exec(select(IntelItem).order_by(IntelItem.published_at.desc()).limit(limit)).all()


@app.get("/api/v1/sources")
def list_sources(session: Session = Depends(get_session)):
    return session.exec(select(FeedSource).order_by(FeedSource.name)).all()


@app.post("/api/v1/refresh")
def refresh_all(session: Session = Depends(get_session)):
    stats = ingest_all_sources(session)
    return {"ok": True, **stats}


@app.post("/api/v1/sources/{source_id}/refresh")
def refresh_source(source_id: int, session: Session = Depends(get_session)):
    result = ingest_source_by_id(session, source_id)
    if result is None:
        raise HTTPException(status_code=404, detail="source not found")
    return {"ok": True, **result}


@app.get("/", response_class=HTMLResponse)
def home(request: Request, session: Session = Depends(get_session)):
    summary = make_dashboard_summary(session)
    items = session.exec(select(IntelItem).order_by(IntelItem.published_at.desc()).limit(20)).all()
    sources = session.exec(select(FeedSource).order_by(FeedSource.name)).all()
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "summary": summary,
            "items": items,
            "sources": sources,
        },
    )
