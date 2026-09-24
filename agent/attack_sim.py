#!/usr/bin/env python3
"""
attack_sim.py — Attack path simulation (portfolio checklist item, not part
of the SentinelCloud v1 spec's own §16 table).

This does NOT probe, exploit, or connect to anything. It is a purely
static, deterministic graph-reachability analysis over architecture.json's
own `flows` list — the same input threat_engine.py already reads — asking
one narrow question: starting from every asset that is a true entry point
(never the destination of any flow, e.g. mobile-app), is there a path
through the flow graph to an asset holding sensitive data (a `database`,
`storage`, or `secret-store` type asset, mirroring threat_engine.py's own
SENSITIVE_TYPES), and does every hop on that path require authentication?

REFERENCE_ONLY / NOT A PROOF OF EXPLOITABILITY. A "HIGH feasibility" chain
below means the flow graph contains at least one unauthenticated hop on a
path that reaches sensitive data — it is a reachability claim grounded in
the same `authenticated` field threat_engine.py's own rules read, nothing
more. It is not a penetration test, it does not confirm the hop is
actually reachable at runtime, and it does not imply any vulnerability
beyond what threat_engine.py's own rules already independently flag. This
module never fabricates a network call, a credential, or an exploit
payload — per this project's standing constraint against any offensive
tooling, everything here is a read-only walk over a JSON graph.

REPORT, NOT A GATE. Like drift_scan.py and report_compliance.py before it,
this CLI always exits 0. Attack-chain feasibility is derived entirely from
data threat_engine.py's own deterministic rules already read (the
`authenticated` field on each flow) — gating on a second, redundant
judgment over the same underlying facts would create two sources of truth
for one question, the same reasoning report_compliance.py's own docstring
already gives for staying non-gating.

This module produces `AttackChain`, its own dataclass — not a `Finding`.
A chain is a claim about reachability across multiple assets, not about
one asset's own misconfiguration, so it doesn't fit threat_engine.py's
per-asset Finding shape (the same reasoning that kept detection_engine.py's
Alert and this project's other non-Finding shapes separate rather than
forced into a shape that doesn't match what they're actually claiming).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from threat_engine import Architecture, SENSITIVE_TYPES, HIGH_SENSITIVITY

REFERENCE_ONLY_LABEL = "(reachability analysis only — not a penetration test or proof of exploitability)"

MAX_PATH_DEPTH = 10  # generous bound for these small architecture graphs; prevents runaway search on a cyclic or malformed flows list


@dataclass
class AttackChain:
    chain_id: str
    entry: str
    target: str
    target_type: str
    target_sensitivity: str
    hops: list[dict] = field(default_factory=list)  # [{"from":..., "to":..., "authenticated": bool}]
    broken_hop_count: int = 0
    feasibility: str = "LOW"  # "HIGH" if any hop is unauthenticated, else "LOW"

    def path_str(self) -> str:
        return " -> ".join([self.entry] + [h["to"] for h in self.hops])

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "entry": self.entry,
            "target": self.target,
            "target_type": self.target_type,
            "target_sensitivity": self.target_sensitivity,
            "path": self.path_str(),
            "hops": self.hops,
            "broken_hop_count": self.broken_hop_count,
            "feasibility": self.feasibility,
        }


def _entry_points(arch: Architecture) -> list[str]:
    """An entry point is any asset that is the source of at least one flow
    but never the destination of one — a true starting point for an
    attacker, not an intermediate hop. Order is stable (insertion order of
    arch.assets) so results are deterministic across runs."""
    destinations = {f["to"] for f in arch.flows}
    sources = {f["from"] for f in arch.flows}
    return [a for a in arch.assets if a in sources and a not in destinations]


def _sensitive_targets(arch: Architecture) -> list[str]:
    return [aid for aid, a in arch.assets.items() if a.get("type") in SENSITIVE_TYPES]


def _find_paths(arch: Architecture, start: str, target: str, max_depth: int) -> list[list[str]]:
    """All simple (no repeated asset) paths from start to target, depth-bounded.
    Depth-first with an explicit visited set rather than relying on recursion
    limits, since architecture.json is untrusted input in principle even
    though every fixture in this repo is small and hand-authored."""
    paths: list[list[str]] = []
    stack: list[tuple[str, list[str]]] = [(start, [start])]
    while stack:
        node, path = stack.pop()
        if node == target and len(path) > 1:
            paths.append(path)
            continue
        if len(path) - 1 >= max_depth:
            continue
        for flow in arch.flows_from(node):
            nxt = flow["to"]
            if nxt in path:  # no cycles
                continue
            stack.append((nxt, path + [nxt]))
    return paths


def find_attack_chains(arch: Architecture, max_depth: int = MAX_PATH_DEPTH) -> list[AttackChain]:
    """The one deterministic entry point this module exposes. Same input,
    same output, always — no model call anywhere in this function."""
    chains: list[AttackChain] = []
    entries = _entry_points(arch)
    targets = _sensitive_targets(arch)
    chain_no = 0
    for entry in entries:
        for target in targets:
            for path in _find_paths(arch, entry, target, max_depth):
                chain_no += 1
                hops = []
                for u, v in zip(path, path[1:]):
                    flow = next(
                        (f for f in arch.flows_from(u) if f["to"] == v), None
                    )
                    authed = bool(flow.get("authenticated")) if flow else False
                    hops.append({"from": u, "to": v, "authenticated": authed})
                broken = sum(1 for h in hops if not h["authenticated"])
                target_asset = arch.assets.get(target, {})
                chains.append(
                    AttackChain(
                        chain_id=f"CHAIN-{chain_no:02d}",
                        entry=entry,
                        target=target,
                        target_type=target_asset.get("type", "unknown"),
                        target_sensitivity=target_asset.get("sensitivity", "unknown"),
                        hops=hops,
                        broken_hop_count=broken,
                        feasibility="HIGH" if broken > 0 else "LOW",
                    )
                )
    return chains


# --------------------------------------------------------------------------
# LLM narration — reads chains, never decides feasibility. Own function
# rather than reusing explain.py's narrate_finding, because AttackChain is
# not a Finding (see module docstring) and a template built for one
# dataclass's fields shouldn't silently be pointed at another's.
# --------------------------------------------------------------------------

_client = None
_client_checked = False


def _get_client():
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


def _template_narrative(chain: AttackChain) -> str:
    if chain.feasibility == "HIGH":
        broken = [h for h in chain.hops if not h["authenticated"]]
        broken_str = ", ".join(f"{h['from']} -> {h['to']}" for h in broken)
        return (
            f"{chain.path_str()} reaches {chain.target} "
            f"({chain.target_sensitivity}-sensitivity {chain.target_type}) "
            f"through {len(broken)} unauthenticated hop(s): {broken_str}. "
            f"{REFERENCE_ONLY_LABEL}"
        )
    return (
        f"{chain.path_str()} reaches {chain.target} "
        f"({chain.target_sensitivity}-sensitivity {chain.target_type}), but every "
        f"hop on this path requires authentication — defense-in-depth only. "
        f"{REFERENCE_ONLY_LABEL}"
    )


def narrate_chain(chain: AttackChain) -> str:
    client = _get_client()
    if client is None:
        return _template_narrative(chain)
    prompt = (
        "You are a security architecture reviewer describing one attack "
        "path to an engineer, in 2-3 sentences, plainly. This is a "
        "reachability analysis, not a confirmed exploit — do not claim the "
        "path has been tested or that a breach occurred. Use only the "
        "facts given.\n\n"
        f"Path: {chain.path_str()}\n"
        f"Target: {chain.target} ({chain.target_sensitivity}-sensitivity {chain.target_type})\n"
        f"Feasibility: {chain.feasibility}\n"
        f"Hops: {chain.hops}\n"
    )
    try:
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=220,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text.strip()
    except Exception as exc:
        return _template_narrative(chain) + f" [LLM explanation unavailable: {exc}]"


# --------------------------------------------------------------------------
# Report rendering + CLI
# --------------------------------------------------------------------------

def render_report(chains: list[AttackChain], arch_name: str, narrate: bool = True) -> str:
    lines = [f"# Attack Path Simulation — {arch_name}", ""]
    lines.append(REFERENCE_ONLY_LABEL)
    lines.append("")
    if not chains:
        lines.append("No path from an entry point to any sensitive-data asset was found.")
        return "\n".join(lines)

    high = [c for c in chains if c.feasibility == "HIGH"]
    low = [c for c in chains if c.feasibility == "LOW"]
    lines.append(f"{len(chains)} path(s) found: {len(high)} HIGH feasibility, {len(low)} LOW (defense-in-depth only).")
    lines.append("")
    for chain in chains:
        lines.append(f"## {chain.chain_id} — {chain.feasibility}")
        lines.append(f"Path: `{chain.path_str()}`")
        lines.append(f"Target: `{chain.target}` ({chain.target_sensitivity}-sensitivity {chain.target_type})")
        if narrate:
            lines.append(narrate_chain(chain))
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("architecture", help="Path to an architecture.json file")
    parser.add_argument("--json", metavar="OUT", help="Also write JSON output to this path")
    parser.add_argument("--no-explain", action="store_true", help="Skip LLM/template narration (faster, still shows every chain)")
    args = parser.parse_args(argv)

    arch = Architecture.from_file(args.architecture)
    chains = find_attack_chains(arch)

    report = render_report(chains, arch.name, narrate=not args.no_explain)
    print(report)

    if args.json:
        payload = {
            "architecture": arch.name,
            "label": REFERENCE_ONLY_LABEL,
            "chain_count": len(chains),
            "high_feasibility_count": sum(1 for c in chains if c.feasibility == "HIGH"),
            "chains": [c.to_dict() for c in chains],
        }
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n")

    return 0  # report, not a gate — see module docstring


if __name__ == "__main__":
    sys.exit(main())
