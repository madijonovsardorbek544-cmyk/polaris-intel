"""Compatibility re-export for older imports.

New code should import from src.config directly.
"""

from src.config import DEFAULT_FEEDS, Settings, load_env, settings

__all__ = ["DEFAULT_FEEDS", "Settings", "load_env", "settings"]
