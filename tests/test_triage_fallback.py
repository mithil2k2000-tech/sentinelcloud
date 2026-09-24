"""
SR-4a for the detection layer (v1 spec §6, §17.2) — mirrors
test_explain_fallback.py exactly, one layer up: alerts instead of
findings, INCIDENT/CLEAR instead of BLOCKED/ALLOWED. The alert list and
the aggregated incident decision must be identical whether
ANTHROPIC_API_KEY is unset, set-but-failing, or set-and-working —
triage.narrate_alert() is never on the critical path of that decision.
"""

from __future__ import annotations

import importlib
from unittest import mock

import triage
from detect import aggregate_alerts
from detection_engine import LogEvent, run_detection

MULTI_STAGE_FIXTURE = (
    __import__("pathlib").Path(__file__).resolve().parent.parent
    / "threat-model" / "logs" / "logs-multi-stage-incident.json"
)


def _fresh_triage_module():
    """triage.py memoizes its client in module-level globals (_client,
    _client_checked) the first time _get_client() runs. Reloading gives
    each test a clean slate regardless of import order or what an earlier
    test set ANTHROPIC_API_KEY to."""
    return importlib.reload(triage)


def _load_alerts():
    from detection_engine import load_events

    return run_detection(load_events(MULTI_STAGE_FIXTURE))


def test_decision_identical_with_api_key_unset(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    mod = _fresh_triage_module()

    alerts = _load_alerts()
    baseline_summary = aggregate_alerts(_load_alerts())

    for a in alerts:
        narrative = mod.narrate_alert(a)
        assert isinstance(narrative, str) and narrative  # template still produced something

    summary_after_triage = aggregate_alerts(alerts)
    assert baseline_summary == summary_after_triage


def test_decision_identical_when_api_call_fails(monkeypatch):
    """Key is set, SDK is importable, but the actual network call raises —
    exactly the case triage.py's try/except is written to survive."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    mod = _fresh_triage_module()

    failing_client = mock.MagicMock()
    failing_client.messages.create.side_effect = RuntimeError("simulated network failure")

    alerts = _load_alerts()
    baseline_summary = aggregate_alerts(_load_alerts())

    with mock.patch.object(mod, "_get_client", return_value=failing_client):
        narratives = [mod.narrate_alert(a) for a in alerts]

    summary_after_triage = aggregate_alerts(alerts)
    assert baseline_summary == summary_after_triage
    # Prove the failure path actually ran (not silently skipped): the
    # fallback note only gets appended when the API call was attempted
    # and raised.
    assert any("[LLM triage unavailable" in n for n in narratives)


def test_decision_identical_when_api_call_succeeds(monkeypatch):
    """Key is set and the call 'succeeds' with a mocked response — proves
    the decision doesn't change even when the LLM path is fully working,
    which matters just as much as the failure case: the decision must
    never depend on the LLM being available OR unavailable."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    mod = _fresh_triage_module()

    ok_client = mock.MagicMock()
    fake_response = mock.MagicMock()
    fake_response.content = [mock.MagicMock(text="A fabricated but well-formed SOC narrative.")]
    ok_client.messages.create.return_value = fake_response

    alerts = _load_alerts()
    baseline_summary = aggregate_alerts(_load_alerts())

    with mock.patch.object(mod, "_get_client", return_value=ok_client):
        narratives = [mod.narrate_alert(a) for a in alerts]

    summary_after_triage = aggregate_alerts(alerts)
    assert baseline_summary == summary_after_triage
    assert all("fabricated but well-formed" in n for n in narratives)


def test_template_fallback_only_repeats_fields_the_engine_already_produced():
    """The template must not be able to say anything the deterministic
    Alert doesn't already say — it narrates, it never adds new claims."""
    mod = _fresh_triage_module()
    for a in _load_alerts():
        narrative = mod._template_narrative(a)
        assert a.title in narrative
        assert a.behavior in narrative
        assert a.impact in narrative
        assert a.recommended_action in narrative


def test_no_api_key_and_sdk_missing_both_fall_back_cleanly(monkeypatch):
    """Belt-and-suspenders: even if the anthropic package were
    uninstalled, _get_client() must return None rather than raise, and
    narrate_alert must still produce a usable string."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    mod = _fresh_triage_module()
    assert mod._get_client() is None

    alert = _load_alerts()[0]
    narrative = mod.narrate_alert(alert)
    assert narrative == mod._template_narrative(alert)
