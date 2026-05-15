from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from src.core.config import settings
from src.core.logger import configure_logging
from src.services.intel_service import intel_service

configure_logging()

templates = Jinja2Templates(directory="src/templates")
app = FastAPI(title=settings.app_name, version=settings.app_version)


@app.on_event("startup")
async def startup_event() -> None:
    await intel_service.startup()


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse(await intel_service.health())


@app.get("/api/latest")
async def api_latest() -> JSONResponse:
    return JSONResponse(await intel_service.latest())


@app.post("/api/refresh")
async def api_refresh() -> JSONResponse:
    return JSONResponse(await intel_service.refresh_store(force=True))


@app.post("/api/seed")
async def api_seed() -> JSONResponse:
    return JSONResponse(await intel_service.seed_demo())


@app.get("/latest")
async def latest_hint() -> JSONResponse:
    return JSONResponse({"detail": "Use /api/latest for JSON or / for UI."}, status_code=404)


@app.get("/")
async def home(request: Request):
    await intel_service.refresh_store(force=False)
    items, status = await intel_service.snapshot()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "app_name": settings.app_name,
            "status": status,
            "count": len(items),
        },
    )
