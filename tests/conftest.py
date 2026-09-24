"""
Shared pytest setup for the SentinelCloud test suite (v1 spec §17).

The agent modules (threat_engine.py, explain.py, analyze.py) live in
agent/ as flat scripts, not an installed package, matching how they're
actually run today (`python3 analyze.py ...`). Rather than restructure
them mid-Phase-2, we add agent/ to sys.path once here so every test file
can just `import threat_engine` / `import explain` / `import analyze`.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = REPO_ROOT / "agent"
FIXTURES_DIR = REPO_ROOT / "threat-model"

sys.path.insert(0, str(AGENT_DIR))
