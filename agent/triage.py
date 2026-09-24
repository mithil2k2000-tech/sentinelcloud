"""
LLM triage layer — the "reasoning and explanation" half of the split, for
alerts instead of design findings (v1 spec §6, SR-4/SR-4a).

Same guarantee as explain.py, restated for this layer: this module NEVER
decides whether something is an alert, how severe it is, or what to do
about it — detection_engine.py already settled all of that
deterministically. All this does is turn an Alert into a short analyst-
readable narrative, using an LLM when one is configured, or a plain
deterministic template when it isn't. The narrative is never load-bearing
for whether an incident gets raised — narrate_alert() always returns
something usable even with zero LLM involvement, and its content can
never change which Alerts exist or their severity (proven by
tests/test_triage_fallback.py, mirroring test_explain_fallback.py exactly).
"""

from __future__ import annotations

import os

from detection_engine import Alert

_client = None
_client_checked = False


def _get_client():
    """Lazily construct an Anthropic client if the SDK and API key are both
    available. Returns None otherwise — callers must handle that."""
    global _client, _client_checked
    if _client_checked:
        return _client
    _client_checked = True

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None

    _client = anthropic.Anthropic(api_key=api_key)
    return _client


def _template_narrative(alert: Alert) -> str:
    """Deterministic fallback — no API key required, always available."""
    return (
        f"{alert.title}. "
        f"What happened: {alert.behavior} "
        f"Why it matters: {alert.impact} "
        f"Recommended action: {alert.recommended_action}"
    )


def narrate_alert(alert: Alert) -> str:
    """Return a short human-readable narrative for one alert, for a SOC
    analyst triaging a queue. Uses the Anthropic API when
    ANTHROPIC_API_KEY is set and the SDK is installed; otherwise falls
    back to a deterministic template built from the same fields the
    detection engine already produced."""
    client = _get_client()
    if client is None:
        return _template_narrative(alert)

    prompt = (
        "You are a SOC analyst triaging one security alert for a colleague, "
        "in 2-3 sentences, plainly and without hedging. Use the facts given "
        "— do not invent new details, and do not change the severity or "
        "recommended action.\n\n"
        f"Alert: {alert.title}\n"
        f"Category: {alert.stride.value}\n"
        f"Severity: {alert.severity}\n"
        f"Behavior observed: {alert.behavior}\n"
        f"Impact if real: {alert.impact}\n"
        f"Recommended action: {alert.recommended_action}\n"
    )
    try:
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=220,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text.strip()
    except Exception as exc:  # network, auth, rate limit, etc.
        # Never let a triage-layer failure block the pipeline — the
        # deterministic template is always a safe fallback.
        return _template_narrative(alert) + f" [LLM triage unavailable: {exc}]"
