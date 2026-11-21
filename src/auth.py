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


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def any_key_configured() -> bool:
    keys = _configured_keys()
    return any(keys.values())


def database_mode() -> bool:
    return bool(os.getenv("DATABASE_URL", settings.database_url).strip())


def open_access_allowed() -> bool:
    """Keyless access: explicit POLARIS_ALLOW_OPEN_ACCESS wins; unset means open only in demo-memory mode."""
    explicit = os.getenv("POLARIS_ALLOW_OPEN_ACCESS", "").strip()
    if explicit:
        return _truthy(explicit)
    # Demo-memory holds only public feed data and resets on restart; Postgres holds customer data, so fail closed.
    return not database_mode()


def protect_reads() -> bool:
    explicit = os.getenv("POLARIS_PROTECT_READS", "").strip()
    if explicit:
        return _truthy(explicit)
    # Real customer data (Postgres) is private unless the operator opts out; demo-memory stays public.
    return settings.protect_reads or database_mode()


def production_config_errors() -> list[str]:
    """Settings that must hold when POLARIS_ENV=production; startup refuses to run otherwise."""
    if os.getenv("POLARIS_ENV", "").strip().lower() != "production":
        return []
    errors = []
    if not database_mode():
        errors.append("DATABASE_URL is required; demo-memory mode loses customer data on restart.")
    if not any_key_configured():
        errors.append("POLARIS_ADMIN_API_KEY (or a role key) is required.")
    if open_access_allowed():
        errors.append("POLARIS_ALLOW_OPEN_ACCESS must not be true.")
    if not protect_reads():
        errors.append("POLARIS_PROTECT_READS must not be false.")
    return errors


def _require_configured_keys() -> bool:
    """Return True when the request may skip key checks; raise when no key is configured."""
    if any_key_configured():
        return False
    if open_access_allowed():
        return True
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No POLARIS API key is configured on this server; set POLARIS_ADMIN_API_KEY",
    )


def _reject(required: str, provided: str | None) -> None:
    role = _role_for_key(provided)
    if role:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"{required} POLARIS API key required")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing POLARIS API key")


async def require_admin_key(x_polaris_api_key: str | None = Header(default=None)) -> None:
    if _require_configured_keys():
        return
    if _role_for_key(x_polaris_api_key) != "admin":
        _reject("Admin", x_polaris_api_key)


async def require_operator_key(x_polaris_api_key: str | None = Header(default=None)) -> None:
    if _require_configured_keys():
        return
    if _role_for_key(x_polaris_api_key) not in {"admin", "operator"}:
        _reject("Admin or operator", x_polaris_api_key)


async def require_read_key(x_polaris_api_key: str | None = Header(default=None)) -> None:
    if not protect_reads() or _require_configured_keys():
        return
    if _role_for_key(x_polaris_api_key) not in {"admin", "operator", "readonly"}:
        _reject("Read", x_polaris_api_key)


# Backward-compatible dependency names used by existing routes.
require_api_key = require_operator_key
require_read_api_key = require_read_key
