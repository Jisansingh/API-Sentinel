"""Pydantic response/request schemas.

These define the shapes of our API payloads. Keeping them here (instead
of inline in routes) makes validation explicit and easy for beginners.
"""

from typing import Literal

from pydantic import BaseModel, Field

AlertStatus = Literal["open", "acknowledged", "resolved", "ignored"]


class HealthResponse(BaseModel):
    """Payload returned by ``GET /api/health``."""

    status: str = Field(examples=["ok"])
    service: str = Field(examples=["api-sentinel"])
    version: str = Field(examples=["0.1.0"])
    database: str = Field(default="ok", examples=["ok"])
    api_revision: int = Field(examples=[2])


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
    authentication_types: list[str] = Field(default_factory=lambda: ["unknown"])
    data_sensitivity: Literal["low", "medium", "high"] = "low"
    sensitivity_basis: str = ""
    # False when every observed response was 404/405 (nothing was served: not a confirmed live API).
    confirmed_live: bool = True


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
    # Documented operations marked ``deprecated: true`` in the spec and still receiving traffic.
    deprecated_apis: list[ShadowApiFinding] = Field(default_factory=list)
    # Needs an ownership/management registry; empty with ``unmanaged_note`` explaining why.
    unmanaged_apis: list[ShadowApiFinding] = Field(default_factory=list)
    unmanaged_note: str | None = None
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


class Alert(BaseModel):
    """A persistent, deduplicated alert (one per type + actor + endpoint)."""

    id: int
    detection_type: str = Field(examples=["scraping"])
    actor: str = Field(examples=["1.2.3.4"])
    endpoint: str = Field(examples=["/api/users/{id}"])
    risk_score: int = Field(ge=0, le=100)
    reason: str
    metadata: dict = Field(default_factory=dict)
    status: AlertStatus
    note: str | None = None
    first_seen: str
    last_seen: str
    occurrences: int = Field(ge=1)
    incident_id: int | None = None


class AlertsResponse(BaseModel):
    """Payload returned by ``GET /api/alerts``."""

    items: list[Alert]
    total: int


class AlertUpdate(BaseModel):
    """Body for ``PATCH /api/alerts/{id}``."""

    status: AlertStatus
    note: str | None = Field(default=None, max_length=500)


class ScanResponse(BaseModel):
    """Payload returned by ``POST /api/scan``."""

    findings: int
    created: int
    updated: int
    unchanged: int


class RateLimitItem(BaseModel):
    """Quota of one endpoint per window; ``vp_limit`` is always 21 x ``normal_limit``."""

    endpoint: str = Field(examples=["GET /api/inventory"])
    normal_limit: int = Field(examples=[60])
    vp_limit: int = Field(examples=[1260])
    source: Literal["configured", "built-in default", "default_limit"]


class RateLimitsResponse(BaseModel):
    """Payload returned by ``GET /api/rate-limits``."""

    window_seconds: int
    vp_multiplier: int
    gateway_enabled: bool
    principals_configured: int
    vp_principals: int
    items: list[RateLimitItem]


class GatewayEvent(BaseModel):
    """One aggregated access-control event (no credentials, raw paths or bodies)."""

    id: int
    window_start: str
    endpoint: str
    decision: Literal["allowed", "rate_limited", "blocked", "ignored"]
    reason: str
    status_code: int
    identity_kind: Literal["principal", "admin", "ip"]
    principal_id: str
    role: str
    purpose: str
    client_ip: str
    count: int
    first_seen: str
    last_seen: str


class GatewayEventsResponse(BaseModel):
    """Payload returned by ``GET /api/gateway-events``."""

    items: list[GatewayEvent]
    total: int


class EvaluationMetrics(BaseModel):
    """A confusion-matrix summary. Precision/recall/F1/FPR are ``None`` ("Not measured")
    when there were no eligible positive (precision/recall) or negative (FPR) test cases."""

    tp: int
    fp: int
    tn: int
    fn: int
    precision: float | None = Field(default=None, examples=[0.88])
    recall: float | None = Field(default=None, examples=[0.78])
    f1: float | None = None
    false_positive_rate: float | None = Field(default=None, examples=[0.02])


class EvaluationScenario(BaseModel):
    """One labelled benchmark scenario: ground truth vs. what the real detectors found."""

    name: str = Field(examples=["scraping_burst"])
    description: str
    holdout: bool = Field(examples=[False], description="True = never tuned on; a stronger signal.")
    expected: list[str] = Field(examples=[["scraping"]])
    instances: int = Field(ge=0)
    hits: int = Field(ge=0, description="Expected detections that fired.")
    misses: int = Field(ge=0, description="Expected detections that did not fire.")
    false_alerts: int = Field(ge=0, description="Detections that fired but were not expected.")
    detection_rate: float | None = None
    false_alert_rate: float | None = None


class EvaluationShadowResult(BaseModel):
    """Shadow-API detection scored against the benchmark's hand-labelled truth set."""

    spec_loaded: bool
    truth_undocumented: list[list[str]]
    predicted_shadow: list[list[str]]
    false_positives: list[list[str]]
    missed: list[list[str]]
    precision: float | None = None
    recall: float | None = None


class EvaluationResponse(BaseModel):
    """Payload returned by ``GET``/``POST /api/evaluation``.

    Computed by actually running ``backend/benchmark/run.py`` (an isolated subprocess,
    its own temporary database, never the live one) against ground-truth-labelled
    synthetic scenarios through the real, unmodified capture -> analyze -> score ->
    alert pipeline. ``available=False`` means no saved result exists yet (POST triggers a
    fresh run; a successful run is saved and survives restarts, see ``persisted``).
    Every metric here is synthetic-benchmark accuracy, not live production accuracy.
    """

    available: bool
    note: str = Field(examples=["No evaluation has been run yet in this process. POST to run one."])
    persisted: bool = Field(default=False, description="True when this result is saved and survives a restart.")
    ran_at: str | None = None
    duration_ms: float | None = None
    seed: int | None = None
    synthetic: bool = Field(default=True, description="Always true: ground truth exists only for synthetic traffic.")
    total_records: int | None = None
    total_instances: int | None = None
    overall: EvaluationMetrics | None = None
    tuning_set: EvaluationMetrics | None = None
    holdout_set: EvaluationMetrics | None = Field(
        default=None, description="Scenarios never tuned on; the more honest accuracy estimate of the two.")
    per_detection_type: dict[str, EvaluationMetrics] = Field(default_factory=dict)
    scenarios: list[EvaluationScenario] = Field(default_factory=list)
    shadow_api: EvaluationShadowResult | None = None
    unattributed_alerts: int = Field(
        default=0, description="Alerts matching no labelled test actor; counted as false positives.")
    test_execution_coverage: str = Field(
        default="not available via this API: pytest results run outside this process and are not persisted "
                "or exposed over HTTP",
        description="Honest limitation, not a fabricated figure. See the Evaluation tab for detail.")
