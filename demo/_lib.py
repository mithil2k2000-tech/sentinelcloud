"""
Shared helpers for demo/scenario*.py — spec §19 (Demonstration Scenarios),
§16 table item 11 ("Demonstration + portfolio packaging").

Every scenario script prints a narrated walkthrough AND asserts, in code,
that reality matches what it's narrating — the same "prove it, don't
assume it" discipline this whole project follows elsewhere (fixture
counts confirmed by real runs before tests were written, snapshot tests
against committed real output, etc.). A demo script that just prints
canned text could silently drift out of sync with the actual code; one
that asserts its own narration cannot.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = REPO_ROOT / "agent"
THREAT_MODEL_DIR = REPO_ROOT / "threat-model"


def header(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def step(text: str) -> None:
    print(f"\n>>> {text}")


def run(cmd: list[str], cwd: Path = AGENT_DIR) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr.strip():
        print(result.stderr, file=sys.stderr)
    return result


def check(condition: bool, ok_message: str, fail_message: str) -> None:
    """Print and enforce one assertion about real output. Raises
    AssertionError on failure so a scenario script exits non-zero the
    moment reality stops matching what it's narrating, rather than
    printing a false PASS."""
    if condition:
        print(f"    [OK] {ok_message}")
    else:
        print(f"    [FAIL] {fail_message}")
        raise AssertionError(fail_message)


def finish(scenario_name: str) -> int:
    print()
    print("=" * 78)
    print(f"{scenario_name}: PASS — demo played out exactly as documented.")
    print("=" * 78)
    return 0
