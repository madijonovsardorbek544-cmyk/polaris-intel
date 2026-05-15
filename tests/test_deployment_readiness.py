from __future__ import annotations

import importlib
from pathlib import Path

from fastapi.testclient import TestClient

from src.main import app

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT_CONFIGS = [
    ROOT / "Procfile",
    ROOT / "render.yaml",
    ROOT / "railway.json",
    ROOT / "Dockerfile",
    ROOT / ".dockerignore",
    ROOT / ".env.example",
]


def _client() -> TestClient:
    return TestClient(app)


def test_app_imports_successfully() -> None:
    module = importlib.import_module("src.main")
    assert module.app is app


def test_health_endpoint_returns_required_deployment_fields() -> None:
    response = _client().get("/health")
    assert response.status_code == 200
    payload = response.json()
    expected = {
        "ok",
        "app",
        "version",
        "mode",
        "database",
        "api_key_configured",
        "read_protection_enabled",
        "default_org",
        "feeds",
        "items",
        "alerts",
        "sources",
        "last_status",
    }
    assert expected.issubset(payload)
    assert payload["ok"] is True
    assert "api_key" not in payload


def test_homepage_returns_public_demo_warnings_without_network(monkeypatch) -> None:
    async def fake_refresh_store(force: bool = False) -> dict[str, object]:
        return {"ok": True, "status": "TEST", "items": 0, "force": force}

    monkeypatch.setattr("src.main.refresh_store", fake_refresh_store)
    response = _client().get("/")
    assert response.status_code == 200
    html = response.text
    assert "POLARIS" in html
    assert "Demo mode: data is stored in memory and may reset." in html
    assert "Warning: write actions are unprotected. Set POLARIS_API_KEY before public deployment." in html


def test_deployment_configs_exist_and_do_not_hardcode_secrets() -> None:
    for path in DEPLOYMENT_CONFIGS:
        assert path.exists(), f"Missing deployment config: {path.name}"
        text = path.read_text()
        assert "uvicorn src.main:app" in text or path.name in {".dockerignore", ".env.example"}
        assert "TELEGRAM_BOT_TOKEN=" not in text or path.name == ".env.example"
        assert "TELEGRAM_CHAT_ID=" not in text or path.name == ".env.example"
        for forbidden in ("sk-", "xoxb-", "bot-token", "postgres://user:password", "change-me-secret"):
            assert forbidden not in text


def test_head_routes_and_dashboard_health(monkeypatch) -> None:
    async def fake_refresh_store(force: bool = False) -> dict[str, object]:
        return {"ok": True, "status": "TEST", "items": 0, "force": force}

    monkeypatch.setattr("src.main.refresh_store", fake_refresh_store)
    c = _client()
    assert c.get("/").status_code == 200
    assert c.head("/").status_code == 200
    assert c.head("/health").status_code == 200
    response = c.get("/api/dashboard-health")
    assert response.status_code == 200
    payload = response.json()
    assert {"ok", "checks", "errors"}.issubset(payload)
    for check in ["items", "alerts", "sources", "brief", "watchlists", "onboarding", "value_report", "source_configs"]:
        assert check in payload["checks"]
        assert "ok" in payload["checks"][check]
    assert "api_key" not in response.text.lower()


def test_dashboard_public_demo_diagnostics_and_resilient_loading() -> None:
    html = (ROOT / "src" / "templates" / "index.html").read_text()
    assert "Public Demo" in html
    assert "Diagnostics" in html
    assert "safeJsonFetch(url, options, fallback, label)" in html
    assert "Promise.allSettled" in html
    assert "Promise.all([" not in html
    assert "Dashboard partially loaded" in html
    assert "Value report" in html and "Source config" in html and "Onboarding templates" in html
    assert "No watchlists yet. Add a watchlist to make alerts organization-specific." in html
    assert "No alerts yet. Add a watchlist, then generate persistent alerts." in html
    assert "No org-specific items yet. Global items exist, but none match this org’s watchlists." in html


def test_reuters_broken_feed_removed() -> None:
    config = (ROOT / "src" / "config.py").read_text()
    assert "reutersagency.com/feed/?best-topics=world&post_type=best" not in config
    assert "feeds.bbci.co.uk/news/world/rss.xml" in config


def test_application_files_do_not_hardcode_common_secret_tokens() -> None:
    for path in (ROOT / "src").rglob("*"):
        if not path.is_file() or path.suffix not in {".py", ".html"}:
            continue
        text = path.read_text()
        for forbidden in ("sk-", "xoxb-", "bot-token", "postgres://user:password", "change-me-secret"):
            assert forbidden not in text, f"Potential hardcoded secret in {path.relative_to(ROOT)}"
