"""Shared fixtures: a dedicated monitored target API for live-capture tests.

Sentinel's own routes (including /api/health) are never captured, so tests
that need real traffic hit these target routes instead.
"""

import pytest
from fastapi import HTTPException

from app.main import create_app


@pytest.fixture
def target_app():
    """Factory: ``target_app(**create_app_kwargs)`` -> app with /target/* routes."""

    def build(**kwargs):
        app = create_app(**kwargs)

        @app.get("/target/ping")
        def ping() -> dict:
            return {"ok": True}

        @app.get("/target/items/{item_id}")
        def item(item_id: int) -> dict:
            if item_id > 100:
                raise HTTPException(status_code=404)
            return {"id": item_id}

        return app

    return build
