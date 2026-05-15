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
    "https://www.reutersagency.com/feed/?best-topics=world&post_type=best",
]


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    app_name: str = "POLARIS Intel"
    app_version: str = "1.0.0"
    port: int = int(os.getenv("PORT", "8000"))
    database_url: str = os.getenv("DATABASE_URL", "").strip()
    api_key: str = os.getenv("POLARIS_API_KEY", "").strip()
    telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    telegram_chat_id: str = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    max_items: int = int(os.getenv("MAX_ITEMS", "60"))
    auto_refresh_seconds: int = int(os.getenv("AUTO_REFRESH_SECONDS", "900"))
    http_timeout: float = float(os.getenv("HTTP_TIMEOUT", "15"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    feeds: list[str] = field(default_factory=lambda: _csv(os.getenv("FEEDS", "")) or DEFAULT_FEEDS)


settings = Settings()
