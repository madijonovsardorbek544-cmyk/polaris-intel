from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_env_file(path: str = ".env") -> None:
    dotenv_spec = importlib.util.find_spec("dotenv")
    if dotenv_spec is not None:
        dotenv = __import__("dotenv")
        dotenv.load_dotenv(path)
        return

    env_path = Path(path)
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_env_file()


DEFAULT_FEEDS = [
    "https://www.cisa.gov/news-events/cybersecurity-advisories.xml",
    "https://www.cisa.gov/news-events/alerts.xml",
    "https://www.cisa.gov/news-events/ics-advisories.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.darkreading.com/rss.xml",
    "https://www.aljazeera.com/xml/rss/all.xml",
    "https://feeds.bbci.co.uk/news/world/rss.xml",
]


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str = "POLARIS Intel"
    app_version: str = "1.0.0"
    port: int = int(os.getenv("PORT", "8000"))
    database_url: str = os.getenv("DATABASE_URL", "").strip()
    api_key: str = os.getenv("POLARIS_API_KEY", "").strip()
    admin_api_key: str = os.getenv("POLARIS_ADMIN_API_KEY", "").strip()
    operator_api_key: str = os.getenv("POLARIS_OPERATOR_API_KEY", "").strip()
    readonly_api_key: str = os.getenv("POLARIS_READONLY_API_KEY", "").strip()
    nvd_api_key: str = os.getenv("NVD_API_KEY", "").strip()
    allowed_orgs: list[str] = field(default_factory=lambda: _csv(os.getenv("POLARIS_ALLOWED_ORGS", "")))
    protect_reads: bool = _bool(os.getenv("POLARIS_PROTECT_READS", "false"))
    default_org: str = os.getenv("POLARIS_DEFAULT_ORG", "demo").strip() or "demo"
    telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    telegram_chat_id: str = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    max_items: int = int(os.getenv("MAX_ITEMS", "60"))
    auto_refresh_seconds: int = int(os.getenv("AUTO_REFRESH_SECONDS", "900"))
    http_timeout: float = float(os.getenv("HTTP_TIMEOUT", "15"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    feeds: list[str] = field(default_factory=lambda: _csv(os.getenv("FEEDS", "")) or DEFAULT_FEEDS)


settings = Settings()
