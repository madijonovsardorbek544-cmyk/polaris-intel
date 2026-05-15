from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from .config import settings
from .database import init_db, list_items
from .routes.health import router as health_router
from .routes.intelligence import router as intelligence_router
from .routes.watchlists import router as watchlists_router
from .services.ingestion import background_refresh_loop, refresh_store, refresh_status

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title=settings.app_name, version=settings.app_version)
app.include_router(health_router)
app.include_router(intelligence_router)
app.include_router(watchlists_router)

_bg_task_started = False


@app.on_event("startup")
async def startup_event() -> None:
    global _bg_task_started
    await init_db()
    try:
        await refresh_store(force=False)
    except Exception:
        pass
    if not _bg_task_started:
        _bg_task_started = True
        asyncio.create_task(background_refresh_loop())


@app.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    try:
        await refresh_store(force=False)
    except Exception:
        pass
    items = await list_items(settings.max_items)
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "app_name": settings.app_name,
            "version": settings.app_version,
            "items_count": len(items),
            "status": refresh_status(),
        },
    )


@app.get("/latest")
async def latest_hint() -> JSONResponse:
    return JSONResponse({"detail": "Use /api/latest for JSON or / for UI."}, status_code=404)
