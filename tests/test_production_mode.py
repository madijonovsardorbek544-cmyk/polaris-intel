from __future__ import annotations

import asyncio

import pytest

from src import auth, main

ENV = ["POLARIS_ENV", "DATABASE_URL", "POLARIS_ADMIN_API_KEY", "POLARIS_API_KEY", "POLARIS_OPERATOR_API_KEY", "POLARIS_READONLY_API_KEY", "POLARIS_ALLOW_OPEN_ACCESS", "POLARIS_PROTECT_READS"]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in ENV:
        monkeypatch.delenv(key, raising=False)


def test_non_production_has_no_requirements() -> None:
    assert auth.production_config_errors() == []


def test_production_refuses_demo_memory_and_missing_key(monkeypatch) -> None:
    monkeypatch.setenv("POLARIS_ENV", "production")
    errors = " ".join(auth.production_config_errors())
    assert "DATABASE_URL" in errors and "POLARIS_ADMIN_API_KEY" in errors
    with pytest.raises(RuntimeError, match="refused to start"):
        asyncio.run(main.startup_event())


def test_production_refuses_explicit_open_settings(monkeypatch) -> None:
    monkeypatch.setenv("POLARIS_ENV", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql://example/db")
    monkeypatch.setenv("POLARIS_ADMIN_API_KEY", "k")
    assert auth.production_config_errors() == []
    monkeypatch.setenv("POLARIS_PROTECT_READS", "false")
    monkeypatch.setenv("POLARIS_ALLOW_OPEN_ACCESS", "true")
    assert len(auth.production_config_errors()) == 2
