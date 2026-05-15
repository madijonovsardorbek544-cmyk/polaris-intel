from __future__ import annotations

import os
from dataclasses import dataclass, field


DEFAULT_FEEDS = (
    "https://www.cisa.gov/news-events/cybersecurity-advisories.xml",
    "https://www.cisa.gov/news-events/alerts.xml",
    "https://www.cisa.gov/news-events/ics-advisories.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.darkreading.com/rss.xml",
    "https://www.aljazeera.com/xml/rss/all.xml",
    "https://feeds.bbci.co.uk/news/world/rss.xml",
    "https://www.reutersagency.com/feed/?best-topics=world&post_type=best",
)


def _csv_env(name: str, default: tuple[str, ...]) -> list[str]:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return list(default)
    return [value.strip() for value in raw_value.split(",") if value.strip()]


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "POLARIS Intel")
    app_version: str = os.getenv("APP_VERSION", "2.1.0")
    max_items: int = int(os.getenv("MAX_ITEMS", "60"))
    auto_refresh_seconds: int = int(os.getenv("AUTO_REFRESH_SECONDS", "900"))
    http_timeout: float = float(os.getenv("HTTP_TIMEOUT", "15"))
    database_url: str = os.getenv("DATABASE_URL", "").strip()
    feeds: list[str] = field(default_factory=lambda: _csv_env("FEEDS", DEFAULT_FEEDS))


settings = Settings()
