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
