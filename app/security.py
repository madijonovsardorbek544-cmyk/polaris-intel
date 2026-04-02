import os

from fastapi import Header, HTTPException, status


def require_admin_token(x_admin_token: str | None = Header(default=None)) -> None:
    expected = os.getenv("POLARIS_ADMIN_TOKEN")
    if not expected:
        return
    if x_admin_token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid admin token",
        )
