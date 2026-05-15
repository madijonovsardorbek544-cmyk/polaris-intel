from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass, field
from pathlib import Path


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


def load_env(env_path: str | os.PathLike[str] | None = None) -> None:
    """Load local .env values without overriding real environment variables."""
    path = Path(env_path) if env_path else Path.cwd() / ".env"
    spec = importlib.util.find_spec("dotenv")
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.load_dotenv(dotenv_path=path, override=False)
        return

    if not path.exists():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_env()


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    app_name: str = "POLARIS Intel"
    app_version: str = "1.1.0"
    port: int = int(os.getenv("PORT", "8000"))
    database_url: str = os.getenv("DATABASE_URL", "").strip()
    max_items: int = int(os.getenv("MAX_ITEMS", "60"))
    auto_refresh_seconds: int = int(os.getenv("AUTO_REFRESH_SECONDS", "900"))
    http_timeout: float = float(os.getenv("HTTP_TIMEOUT", "15"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    feeds: list[str] = field(default_factory=lambda: _csv(os.getenv("FEEDS", "")) or DEFAULT_FEEDS)


settings = Settings()
