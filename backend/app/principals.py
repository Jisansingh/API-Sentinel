"""Operator-provisioned principals (who a credential belongs to, and its role).

Sentinel has no identity provider of its own. A principal is recognised only
when the request's credential (``Authorization`` or ``X-API-Key``) has a keyed
fingerprint (``capture.credential_fingerprint``, HMAC with SENTINEL_FP_SECRET)
that the operator listed in SENTINEL_PRINCIPALS_PATH. The file holds
fingerprints, never credentials, and there is no built-in or default account:
without the file nobody is a principal and nobody gets the VP quota.

File format::

    {"principals": [
        {"id": "jane", "fingerprint": "<32 hex>", "role": "vp"},
        {"id": "scanner-1", "fingerprint": "<32 hex>", "role": "user", "purpose": "security_scan"}
    ]}

``role``: ``user`` or ``vp``. ``purpose`` (optional, default ``normal``):
``normal``, ``security_scan`` or ``authorized_test`` - labels traffic in the
gateway event log; it grants nothing.

Make a fingerprint without putting the credential in shell history or argv::

    SENTINEL_FP_SECRET=... python3 -m app.principals fingerprint   # reads the credential from stdin
"""

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROLES = ("user", "vp")
PURPOSES = ("normal", "security_scan", "authorized_test")
_FINGERPRINT = re.compile(r"^[0-9a-f]{32}$")
_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_PRINCIPALS = 10_000


@dataclass(frozen=True)
class Principal:
    id: str
    role: str
    purpose: str = "normal"


def validate_principals(data: object) -> dict[str, Principal]:
    """Return {fingerprint: Principal}; raise ValueError on anything malformed."""
    if not isinstance(data, dict) or not isinstance(data.get("principals"), list):
        raise ValueError("principals file must be an object with a 'principals' list")
    entries = data["principals"]
    if len(entries) > MAX_PRINCIPALS:
        raise ValueError(f"at most {MAX_PRINCIPALS} principals are supported")
    by_fp: dict[str, Principal] = {}
    ids: set[str] = set()
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) - {"id", "fingerprint", "role", "purpose"}:
            raise ValueError(f"principal #{i}: expected keys id, fingerprint, role[, purpose]")
        pid, fp = entry.get("id"), entry.get("fingerprint")
        role, purpose = entry.get("role"), entry.get("purpose", "normal")
        if not isinstance(pid, str) or not _ID.match(pid):
            raise ValueError(f"principal #{i}: id must match {_ID.pattern}")
        if not isinstance(fp, str) or not _FINGERPRINT.match(fp):
            raise ValueError(f"principal {pid!r}: fingerprint must be 32 lowercase hex characters")
        if role not in ROLES:
            raise ValueError(f"principal {pid!r}: role must be one of {ROLES}")
        if purpose not in PURPOSES:
            raise ValueError(f"principal {pid!r}: purpose must be one of {PURPOSES}")
        if pid in ids or fp in by_fp:
            raise ValueError(f"principal {pid!r}: duplicate id or fingerprint")
        ids.add(pid)
        by_fp[fp] = Principal(pid, role, purpose)
    return by_fp


def load_principals(path: str | Path) -> dict[str, Principal]:
    """Read and validate a principals file (errors never echo file content)."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError) as err:
        raise ValueError(f"cannot read principals file: {type(err).__name__}") from None
    return validate_principals(data)


if __name__ == "__main__":
    import os

    from app.capture import credential_fingerprint
    from app.config import resolve_fp_secret

    if sys.argv[1:] != ["fingerprint"]:
        sys.exit("usage: SENTINEL_FP_SECRET=... python3 -m app.principals fingerprint  (credential on stdin)")
    key = resolve_fp_secret(os.getenv("SENTINEL_FP_SECRET"))
    if key is None:
        sys.exit("SENTINEL_FP_SECRET (>= 32 chars) is required")
    credential = sys.stdin.readline().strip()
    if not credential:
        sys.exit("no credential on stdin")
    # Same header the gateway fingerprints first; e.g. "Bearer abc" for Authorization.
    print(credential_fingerprint({"authorization": credential}, key))
