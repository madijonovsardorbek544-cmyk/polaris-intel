from __future__ import annotations

from fastapi import Header, HTTPException, status

from .config import settings


async def require_api_key(x_polaris_api_key: str | None = Header(default=None)) -> None:
    """Require X-Polaris-API-Key for write operations when configured.

    Empty POLARIS_API_KEY keeps local/demo writes frictionless.
    """
    expected = settings.api_key.strip()
    if not expected:
        return
    if x_polaris_api_key != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing POLARIS API key")
