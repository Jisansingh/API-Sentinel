"""Pydantic response/request schemas.

These define the shapes of our API payloads. Keeping them here (instead
of inline in routes) makes validation explicit and easy for beginners.
"""

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Payload returned by ``GET /api/health``."""

    status: str = Field(examples=["ok"])
    service: str = Field(examples=["api-sentinel"])
    version: str = Field(examples=["0.1.0"])


class CapturedRequest(BaseModel):
    """A safely-stored summary of one HTTP request.

    NOTE: this intentionally has NO headers, body, token, or password
    fields. We never store raw secrets or request bodies.
    """

    method: str = Field(examples=["GET"])
    path: str = Field(examples=["/api/health"])
    status_code: int = Field(examples=[200])
    duration_ms: float = Field(examples=[1.23])
    client_ip: str = Field(examples=["testclient"])


class InventoryItem(BaseModel):
    """One aggregated API endpoint observed in captured traffic."""

    method: str = Field(examples=["GET"])
    path: str = Field(examples=["/api/users/{id}"])
    request_count: int = Field(examples=[2])
    status_codes: list[int] = Field(examples=[[200]])
    last_status: int = Field(examples=[200])
    last_seen: str = Field(examples=["2026-10-14 00:00:00"])
    # Safe query-parameter NAMES only — never values.
    query_params: list[str] = Field(examples=[["next", "token"]])


class InventoryResponse(BaseModel):
    """Payload returned by ``GET /api/inventory``."""

    items: list[InventoryItem]
    total_requests: int = Field(examples=[5])
    total_endpoints: int = Field(examples=[3])


class DocumentedRoute(BaseModel):
    """An observed route that is also documented in the OpenAPI spec."""

    method: str = Field(examples=["GET"])
    path: str = Field(examples=["/api/health"])


class ShadowApiFinding(BaseModel):
    """An observed route with no matching OpenAPI operation (shadow API)."""

    method: str = Field(examples=["GET"])
    path: str = Field(examples=["/api/admin/export"])
    request_count: int = Field(examples=[4])
    last_seen: str = Field(examples=["2026-10-14 00:00:00"])
    reason: str = Field(
        examples=["observed in captured traffic but not documented in the OpenAPI specification"]
    )


class ShadowApiResponse(BaseModel):
    """Payload returned by ``GET /api/shadow-apis``."""

    documented: list[DocumentedRoute]
    shadow_apis: list[ShadowApiFinding]
    spec_loaded: bool = Field(examples=[True])
    spec_error: str | None = Field(
        default=None, examples=["OpenAPI specification not found: ./openapi.json"]
    )


class DetectionResultIn(BaseModel):
    """PROPOSED submission shape for detector modules (Claude: abuse/risk).

    Not consumed by any endpoint yet — draft interface for the integration
    contract in ``docs/backend-contract.md``. Detector modules own the
    detection logic; this only standardizes how findings are reported.
    """

    detector: str = Field(examples=["abuse-detection"])
    method: str = Field(examples=["POST"])
    path: str = Field(examples=["/api/login"])
    finding_type: str = Field(examples=["rate-anomaly"])
    severity: str = Field(examples=["medium"])
    reason: str = Field(examples=["120 requests/min from one client"])
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class Finding(BaseModel):
    """A structured abuse-detection finding (integration pipeline output).

    Numeric ``risk_score`` (0-100, higher = more dangerous) is authoritative;
    no severity vocabulary is used here to avoid conflicting with the draft
    ``DetectionResultIn.severity`` field. ``metadata`` holds only safe,
    supporting data (counts, thresholds, IPs, token fingerprints) — never
    raw tokens, passwords, cookies, or bodies.
    """

    detection_type: str = Field(examples=["scraping"])
    endpoint: str = Field(examples=["/api/users/{id}"])
    risk_score: int = Field(ge=0, le=100, examples=[30])
    reason: str = Field(examples=["User testclient made 15 requests in 60s (threshold: 10)"])
    timestamp: str = Field(examples=["2026-10-14 00:00:00"])
    metadata: dict = Field(default_factory=dict)


class FindingsResponse(BaseModel):
    """Payload returned by ``GET /api/findings``."""

    items: list[Finding]
    total_findings: int = Field(examples=[1])
