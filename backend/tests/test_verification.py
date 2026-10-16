"""Review checks: secret handling, fingerprint lifecycle, score invariants."""

import logging

from fastapi.testclient import TestClient

from app.config import Settings
from app.risk_scoring import RiskScorer
from app.storage import fetch_captured_requests
from simulator.run import run_scenarios

FP = "f" * 40
KEY = "k" * 40


def test_secrets_are_redacted_in_settings_repr(monkeypatch):
    monkeypatch.setenv("SENTINEL_FP_SECRET", FP)
    monkeypatch.setenv("SENTINEL_API_KEY", KEY)
    settings = Settings.from_env()
    assert settings.fp_secret.get_secret_value() == FP
    assert FP not in repr(settings) and KEY not in repr(settings)
    assert FP not in str(settings.model_dump()) and KEY not in str(settings.model_dump())


def test_short_fp_secret_warning_does_not_log_the_value(tmp_path, caplog, target_app):
    weak = "weak-secret-value"
    with caplog.at_level(logging.WARNING):
        target_app(db_path=str(tmp_path / "w.db"), fp_secret=weak)
    assert "SENTINEL_FP_SECRET is shorter" in caplog.text
    assert weak not in caplog.text


def test_fingerprints_survive_restart_and_change_on_rotation(tmp_path, target_app):
    db_file = str(tmp_path / "rot.db")
    header = {"Authorization": "Bearer same-token"}
    for secret in (FP, FP, "g" * 40):  # restart with same key, then rotate
        TestClient(target_app(db_path=db_file, fp_secret=secret)).get("/target/ping", headers=header)
    a, b, c = (r["actor_fp"] for r in fetch_captured_requests(db_file))
    assert a == b  # same key across restarts -> same actor
    assert a != c  # rotated key -> unlinkable to old fingerprints


def test_every_scanned_alert_breakdown_sums_to_its_score(tmp_path):
    from app.main import create_app

    app = create_app(db_path=str(tmp_path / "v.db"), fp_secret=FP, api_key=KEY, enable_demo=True)
    run_scenarios(lambda m, p, h, ip: TestClient(app, client=(ip, 1)).request(m, p, headers=h).status_code)
    client = TestClient(app, headers={"X-Sentinel-Key": KEY})
    client.post("/api/scan")
    alerts = client.get("/api/alerts").json()["items"]
    assert len(alerts) >= 4
    w = RiskScorer.SIGNAL_WEIGHTS
    base = {"scraping": ("scraping", RiskScorer.SCRAPING_WEIGHT),
            "bola_enumeration": ("bola", RiskScorer.BOLA_WEIGHT),
            "bola": ("bola", RiskScorer.BOLA_WEIGHT),  # demo ownership context (Phase 5)
            "token_replay": ("token_replay", RiskScorer.TOKEN_REPLAY_WEIGHT),
            "bola_blocked": ("bola_attempt", w["bola_attempt"]),
            "bola_inconclusive": ("bola_attempt", w["bola_attempt"]),
            "access_denied": ("access_denied", w["access_denied"]),
            "rate_anomaly": ("anomaly", w["anomaly"]), "error_spike": ("anomaly", w["anomaly"]),
            "payload_anomaly": ("anomaly", w["anomaly"])}
    for alert in alerts:
        bd = alert["metadata"]["breakdown"]
        key, weight = base[alert["detection_type"]]
        assert 0 < alert["risk_score"] <= 100
        assert sum(bd.values()) == alert["risk_score"], alert
        assert bd[key] == weight  # detector key is always the base weight
        assert alert["metadata"]["rule_id"]
        if key in ("bola", "scraping", "token_replay"):
            assert set(bd) == {"bola", "scraping", "token_replay", "magnitude", "context"}
        else:
            assert set(bd) == {key, "magnitude", "context"}
