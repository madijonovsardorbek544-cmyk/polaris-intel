from __future__ import annotations

import os
from dataclasses import dataclass, field


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
    max_items: int = int(os.getenv("MAX_ITEMS", "60"))
    auto_refresh_seconds: int = int(os.getenv("AUTO_REFRESH_SECONDS", "900"))
    http_timeout: float = float(os.getenv("HTTP_TIMEOUT", "15"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    feeds: list[str] = field(default_factory=lambda: _csv(os.getenv("FEEDS", "")) or DEFAULT_FEEDS)


settings = Settings()
