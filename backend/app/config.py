"""Application configuration.

Beginner-friendly settings loaded from environment variables with safe
defaults. Only uses the standard library + pydantic (already required),
so it works even without ``pydantic-settings`` or ``sqlalchemy`` installed.
"""

import os
from functools import lru_cache

from pydantic import BaseModel


class Settings(BaseModel):
    """Runtime settings for API Sentinel."""

    app_name: str = "api-sentinel"
    version: str = "0.1.0"
    database_url: str = "sqlite:///./api_sentinel.db"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = False
    enable_capture: bool = True
    # Local OpenAPI JSON file used by GET /api/shadow-apis. None means
    # "no specification configured" (endpoint still works; see contract).
    openapi_spec_path: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from environment variables (with safe defaults)."""
        return cls(
            database_url=os.getenv("DATABASE_URL", "sqlite:///./api_sentinel.db"),
            api_host=os.getenv("API_HOST", "0.0.0.0"),
            api_port=int(os.getenv("API_PORT", "8000")),
            debug=os.getenv("DEBUG", "False").lower() in {"1", "true", "yes"},
            enable_capture=os.getenv("ENABLE_CAPTURE", "True").lower()
            in {"1", "true", "yes"},
            openapi_spec_path=os.getenv("OPENAPI_SPEC_PATH") or None,
        )


@lru_cache
def get_settings() -> Settings:
    """Return cached settings (reads environment on first call)."""
    return Settings.from_env()


def get_db_path(database_url: str | None = None) -> str:
    """Resolve a SQLite file path from a ``sqlite:///`` URL.

    Only SQLite is supported in this foundation step. ``:memory:`` is
    passed through for tests.
    """
    url = database_url or get_settings().database_url
    prefix = "sqlite:///"
    if url.startswith(prefix):
        return url[len(prefix):] or "./api_sentinel.db"
    raise ValueError(f"Only SQLite database URLs are supported, got: {url!r}")
