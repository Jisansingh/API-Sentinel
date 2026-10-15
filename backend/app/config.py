"""Application configuration.

Beginner-friendly settings loaded from environment variables with safe
defaults. Only uses the standard library + pydantic (already required),
so it works even without ``pydantic-settings`` or ``sqlalchemy`` installed.
"""

import os
from functools import lru_cache

from pydantic import BaseModel, SecretStr

# Secrets shorter than this are rejected (fingerprint key / admin API key).
MIN_FP_SECRET_LENGTH = 32


class Settings(BaseModel):
    """Runtime settings for API Sentinel."""

    app_name: str = "api-sentinel"
    version: str = "0.1.0"
    database_url: str = "sqlite:///./api_sentinel.db"
    # Loopback by default: exposing Sentinel is an explicit decision (see docs/DEPLOYMENT.md).
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    debug: bool = False
    enable_capture: bool = True
    # Local OpenAPI JSON file used by GET /api/shadow-apis. None means
    # "no specification configured" (endpoint still works; see contract).
    openapi_spec_path: str | None = None
    # Key for credential fingerprints (SENTINEL_FP_SECRET). SecretStr keeps it
    # out of reprs/logs. None disables fingerprinting (actor = client IP).
    fp_secret: SecretStr | None = None
    # Admin key for Sentinel's own API (SENTINEL_API_KEY); see app/auth.py.
    api_key: SecretStr | None = None
    # Mounts the deliberately vulnerable demo shop (never in production).
    enable_demo_target: bool = False
    # "development" (local demo: open reads, loud warnings) or "production"
    # (fail closed: key + fingerprint secret required, demo target refused).
    env: str = "development"
    # Extra directory that ``GET /api/shadow-apis?spec_path=`` may read from
    # (SENTINEL_SPEC_DIR). The directory of OPENAPI_SPEC_PATH is always allowed.
    spec_dir: str | None = None
    # Optional JSON ownership context for confirmed-BOLA detection.
    ownership_path: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from environment variables (with safe defaults)."""
        return cls(
            database_url=os.getenv("DATABASE_URL", "sqlite:///./api_sentinel.db"),
            api_host=os.getenv("API_HOST", "127.0.0.1"),
            api_port=int(os.getenv("API_PORT", "8000")),
            debug=os.getenv("DEBUG", "False").lower() in {"1", "true", "yes"},
            enable_capture=os.getenv("ENABLE_CAPTURE", "True").lower()
            in {"1", "true", "yes"},
            openapi_spec_path=os.getenv("OPENAPI_SPEC_PATH") or None,
            fp_secret=os.getenv("SENTINEL_FP_SECRET") or None,
            api_key=os.getenv("SENTINEL_API_KEY") or None,
            enable_demo_target=os.getenv("ENABLE_DEMO_TARGET", "False").lower()
            in {"1", "true", "yes"},
            env=os.getenv("SENTINEL_ENV", "development").strip().lower(),
            spec_dir=os.getenv("SENTINEL_SPEC_DIR") or None,
            ownership_path=os.getenv("SENTINEL_OWNERSHIP_PATH") or None,
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


def resolve_fp_secret(secret: str | None) -> bytes | None:
    """Return the HMAC key as bytes, or None if missing or too short."""
    if not secret or len(secret) < MIN_FP_SECRET_LENGTH:
        return None
    return secret.encode()


def validate_environment(
    env: str, *, has_api_key: bool, has_fp_secret: bool, demo_enabled: bool
) -> None:
    """Refuse to start an insecure production configuration.

    ``development`` (default) only warns elsewhere. In ``production`` every
    protection is mandatory: this raises instead of silently running open.
    """
    if env not in ("development", "production"):
        raise ValueError("SENTINEL_ENV must be 'development' or 'production'")
    if env != "production":
        return
    problems = []
    if not has_api_key:
        problems.append(f"SENTINEL_API_KEY (>= {MIN_FP_SECRET_LENGTH} chars) is required")
    if not has_fp_secret:
        problems.append(f"SENTINEL_FP_SECRET (>= {MIN_FP_SECRET_LENGTH} chars) is required")
    if demo_enabled:
        problems.append("ENABLE_DEMO_TARGET must be off (the demo shop is deliberately vulnerable)")
    if problems:
        raise ValueError("insecure production configuration: " + "; ".join(problems))
