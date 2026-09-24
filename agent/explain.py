"""
LLM explanation layer — the "reasoning and explanation" half of the split.

This module NEVER decides whether something is a finding, how severe it is,
or what the policy says — threat_engine.py already settled all of that
deterministically. All this does is turn a Finding into a short paragraph a
human can read in a standup, using an LLM when one is configured, or a
plain deterministic template when it isn't.

That fallback matters: the agent's actual enforcement value (the risk score,
the BLOCKED/ALLOWED decision) works identically with or without an API key.
The LLM only makes the *explanation* nicer — it's never load-bearing for
whether a bad architecture gets blocked.
"""

from __future__ import annotations

import os

from threat_engine import Finding

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


def _template_narrative(finding: Finding) -> str:
    """Deterministic fallback — no API key required, always available."""
    return (
        f"{finding.title}. "
        f"Why it matters: {finding.threat} "
        f"If left as-is: {finding.impact} "
        f"Fix: {finding.mitigation}"
    )


def narrate_finding(finding: Finding) -> str:
    """Return a short human-readable narrative for one finding. Uses the
    Anthropic API when ANTHROPIC_API_KEY is set and the SDK is installed;
    otherwise falls back to a deterministic template built from the same
    fields the engine already produced."""
    client = _get_client()
    if client is None:
        return _template_narrative(finding)

    prompt = (
        "You are a security architecture reviewer explaining one finding to "
        "an engineer, in 2-3 sentences, plainly and without hedging. Use the "
        "facts given — do not invent new details or change the severity.\n\n"
        f"Finding: {finding.title}\n"
        f"STRIDE category: {finding.stride.value}\n"
        f"Severity: {finding.severity}\n"
        f"Threat: {finding.threat}\n"
        f"Impact: {finding.impact}\n"
        f"Mitigation: {finding.mitigation}\n"
    )
    try:
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=220,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text.strip()
    except Exception as exc:  # network, auth, rate limit, etc.
        # Never let an explanation-layer failure block the pipeline — the
        # deterministic template is always a safe fallback.
        return _template_narrative(finding) + f" [LLM explanation unavailable: {exc}]"
