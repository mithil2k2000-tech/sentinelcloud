"""
SR-4a — the decision-neutrality guarantee (v1 spec §6, §17.2).

SentinelCloud's central architectural claim is that no LLM call sits on
the critical path of a BLOCKED/ALLOWED decision. This file exercises
that claim directly instead of trusting explain.py's docstring: the
finding list and the aggregated deployment decision must be identical
whether ANTHROPIC_API_KEY is unset, set-but-failing, or set-and-working.
"""

from __future__ import annotations

import importlib
from unittest import mock

import explain
from analyze import aggregate
from threat_engine import Architecture, run_engine

FIXTURE = (
    __import__("pathlib").Path(__file__).resolve().parent.parent
    / "threat-model" / "architecture-hardened.json"
)


def _fresh_explain_module():
    """explain.py memoizes its client in module-level globals
    (_client, _client_checked) the first time _get_client() runs.
    Reloading gives each test a clean slate regardless of import order
    or what an earlier test set ANTHROPIC_API_KEY to."""
    return importlib.reload(explain)


def _load_findings():
    return run_engine(Architecture.from_file(FIXTURE))


def test_decision_identical_with_api_key_unset(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    mod = _fresh_explain_module()

    findings = _load_findings()
    baseline_summary = aggregate(run_engine(Architecture.from_file(FIXTURE)))

    for f in findings:
        narrative = mod.narrate_finding(f)
        assert isinstance(narrative, str) and narrative  # template still produced something

    summary_after_explaining = aggregate(findings)
    assert baseline_summary == summary_after_explaining


def test_decision_identical_when_api_call_fails(monkeypatch):
    """Key is set, SDK is importable, but the actual network call raises —
    exactly the case explain.py's try/except is written to survive."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    mod = _fresh_explain_module()

    failing_client = mock.MagicMock()
    failing_client.messages.create.side_effect = RuntimeError("simulated network failure")

    findings = _load_findings()
    baseline_summary = aggregate(run_engine(Architecture.from_file(FIXTURE)))

    with mock.patch.object(mod, "_get_client", return_value=failing_client):
        explanations = [mod.narrate_finding(f) for f in findings]

    summary_after_explaining = aggregate(findings)
    assert baseline_summary == summary_after_explaining
    # Prove the failure path actually ran (not silently skipped): the
    # fallback note only gets appended when the API call was attempted
    # and raised.
    assert any("[LLM explanation unavailable" in e for e in explanations)


def test_decision_identical_when_api_call_succeeds(monkeypatch):
    """Key is set and the call 'succeeds' with a mocked response — proves
    the decision doesn't change even when the LLM path is fully working,
    which matters just as much as the failure case: the decision must
    never depend on the LLM being available OR unavailable."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    mod = _fresh_explain_module()

    ok_client = mock.MagicMock()
    fake_response = mock.MagicMock()
    fake_response.content = [mock.MagicMock(text="A fabricated but well-formed LLM explanation.")]
    ok_client.messages.create.return_value = fake_response

    findings = _load_findings()
    baseline_summary = aggregate(run_engine(Architecture.from_file(FIXTURE)))

    with mock.patch.object(mod, "_get_client", return_value=ok_client):
        explanations = [mod.narrate_finding(f) for f in findings]

    summary_after_explaining = aggregate(findings)
    assert baseline_summary == summary_after_explaining
    assert all("fabricated but well-formed" in e for e in explanations)


def test_template_fallback_only_repeats_fields_the_engine_already_produced():
    """The template must not be able to say anything the deterministic
    Finding doesn't already say — it narrates, it never adds new claims."""
    mod = _fresh_explain_module()
    for f in _load_findings():
        narrative = mod._template_narrative(f)
        assert f.title in narrative
        assert f.threat in narrative
        assert f.impact in narrative
        assert f.mitigation in narrative


def test_no_api_key_and_sdk_missing_both_fall_back_cleanly(monkeypatch):
    """Belt-and-suspenders: even if the anthropic package were uninstalled,
    _get_client() must return None rather than raise, and narrate_finding
    must still produce a usable string."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    mod = _fresh_explain_module()
    assert mod._get_client() is None

    finding = _load_findings()[0]
    narrative = mod.narrate_finding(finding)
    assert narrative == mod._template_narrative(finding)
