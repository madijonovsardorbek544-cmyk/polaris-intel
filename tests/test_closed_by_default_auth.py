from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from src.database import reset_memory_state
from src.main import app

KEY_VARS = ["POLARIS_ADMIN_API_KEY", "POLARIS_OPERATOR_API_KEY", "POLARIS_READONLY_API_KEY", "POLARIS_API_KEY", "POLARIS_PROTECT_READS", "POLARIS_ALLOW_OPEN_ACCESS", "DATABASE_URL"]


@pytest.fixture()
def c(monkeypatch) -> TestClient:
    asyncio.run(reset_memory_state())
    for key in KEY_VARS:
        monkeypatch.delenv(key, raising=False)
    return TestClient(app)


def test_writes_fail_closed_when_no_key_configured(c) -> None:
    for path in ["/api/demo/reset", "/api/watchlists", "/api/seed"]:
        res = c.post(path, json={"name": "x", "keywords": ["x"]})
        assert res.status_code == 401, path
        assert "No POLARIS API key is configured" in res.json()["detail"]


def test_public_reads_and_lead_form_stay_open_in_demo_memory(c) -> None:
    assert c.get("/api/items").status_code == 200
    assert c.get("/health").json()["api_key_configured"] is False
    lead = {"name": "A", "organization": "B", "role": "C", "email": "a@example.org", "country": "UZ", "organization_type": "NGO", "problem_description": "Need alerts"}
    assert c.post("/api/leads", json=lead).status_code == 201


def test_open_access_opt_in_restores_keyless_dev_mode(c, monkeypatch) -> None:
    monkeypatch.setenv("POLARIS_ALLOW_OPEN_ACCESS", "true")
    assert c.post("/api/seed").status_code == 200


def test_role_key_alone_counts_as_configured(c, monkeypatch) -> None:
    monkeypatch.setenv("POLARIS_OPERATOR_API_KEY", "op")
    assert c.get("/health").json()["api_key_configured"] is True
    assert c.post("/api/seed").status_code == 401
    assert c.post("/api/seed", headers={"X-Polaris-API-Key": "op"}).status_code == 200


def test_reads_protected_by_default_in_database_mode(monkeypatch) -> None:
    from src import auth

    monkeypatch.delenv("POLARIS_PROTECT_READS", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://example/db")
    assert auth.protect_reads() is True
    monkeypatch.setenv("POLARIS_PROTECT_READS", "false")
    assert auth.protect_reads() is False
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.delenv("POLARIS_PROTECT_READS")
    assert auth.protect_reads() is False
