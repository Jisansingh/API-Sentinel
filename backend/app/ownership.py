"""Load and validate operator-supplied ownership context (confirmed BOLA).

Format (JSON)::

    {"resources": {"/shop/orders/{id}": {"1": "alice", "2": "bob"}},
     "actors": {"<credential fingerprint or client IP>": "alice"}}

Actor keys are the same identifiers Sentinel stores (``actor_fp`` or IP).
Raw tokens never belong in this file.
"""

import json
from pathlib import Path

MAX_BYTES = 5 * 1024 * 1024


def validate_ownership(data: object) -> dict:
    """Return ``data`` if it has the expected shape, else raise ValueError."""
    if not isinstance(data, dict):
        raise ValueError("ownership context must be a JSON object")
    resources, actors = data.get("resources", {}), data.get("actors", {})
    if not isinstance(resources, dict) or not isinstance(actors, dict):
        raise ValueError("ownership 'resources' and 'actors' must be objects")
    for template, owners in resources.items():
        if not isinstance(template, str) or not isinstance(owners, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in owners.items()
        ):
            raise ValueError("ownership 'resources' must map template -> {id: owner}")
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in actors.items()):
        raise ValueError("ownership 'actors' must map actor -> user")
    return {"resources": resources, "actors": actors}


def load_ownership(path: str | Path) -> dict:
    """Read and validate an ownership file (fails loudly at startup)."""
    p = Path(path)
    if not p.is_file() or p.stat().st_size > MAX_BYTES:
        raise ValueError("SENTINEL_OWNERSHIP_PATH must be a JSON file under 5 MiB")
    try:
        return validate_ownership(json.loads(p.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("SENTINEL_OWNERSHIP_PATH is not valid JSON") from None
