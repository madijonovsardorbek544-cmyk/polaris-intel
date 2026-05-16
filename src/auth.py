from __future__ import annotations

import os

from fastapi import Header, HTTPException, status

from .config import settings


def _configured_keys() -> dict[str, str]:
    legacy = os.getenv("POLARIS_API_KEY", settings.api_key).strip()
    admin = os.getenv("POLARIS_ADMIN_API_KEY", "").strip() or legacy
    operator = os.getenv("POLARIS_OPERATOR_API_KEY", "").strip()
    readonly = os.getenv("POLARIS_READONLY_API_KEY", "").strip()
    return {"admin": admin, "operator": operator, "readonly": readonly}


def _role_for_key(value: str | None) -> str | None:
    if not value:
        return None
    keys = _configured_keys()
    for role in ("admin", "operator", "readonly"):
        if keys[role] and value == keys[role]:
            return role
    return None


def _any_key_configured() -> bool:
    keys = _configured_keys()
    return any(keys.values())


def _protect_reads() -> bool:
    return os.getenv("POLARIS_PROTECT_READS", str(settings.protect_reads)).strip().lower() in {"1", "true", "yes", "on"}


def _reject(required: str, provided: str | None) -> None:
    role = _role_for_key(provided)
    if role:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"{required} POLARIS API key required")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing POLARIS API key")


async def require_admin_key(x_polaris_api_key: str | None = Header(default=None)) -> None:
    if not _any_key_configured():
        return
    if _role_for_key(x_polaris_api_key) != "admin":
        _reject("Admin", x_polaris_api_key)


async def require_operator_key(x_polaris_api_key: str | None = Header(default=None)) -> None:
    if not _any_key_configured():
        return
    if _role_for_key(x_polaris_api_key) not in {"admin", "operator"}:
        _reject("Admin or operator", x_polaris_api_key)


async def require_read_key(x_polaris_api_key: str | None = Header(default=None)) -> None:
    if not _protect_reads() or not _any_key_configured():
        return
    if _role_for_key(x_polaris_api_key) not in {"admin", "operator", "readonly"}:
        _reject("Read", x_polaris_api_key)


# Backward-compatible dependency names used by existing routes.
require_api_key = require_operator_key
require_read_api_key = require_read_key
