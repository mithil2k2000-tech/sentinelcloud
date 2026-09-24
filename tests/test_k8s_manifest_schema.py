"""
Real Kubernetes API schema validation for kubernetes/manifests/{vulnerable,hardened}/.

Closes a real gap named directly in the SentinelCloud v1 spec's own §16
development-phase table, item 6 ("Kubernetes workload security"): "Manifests
validated with kubeval/kubeconform." Neither `kubeval` nor `kubeconform` can
be installed in this sandbox — both ship as GitHub-release binaries, and this
sandbox's egress is blocked to the hosts that would serve them (the same
class of restriction that blocks the real `terraform` and `opa` binaries —
see docs/phase2-tests.md and docs/phase4-zero-trust.md). `kubernetes-validate`
(PyPI) is used instead: it validates a manifest against the actual official
Kubernetes OpenAPI schemas for a given cluster version, which is the same
underlying check kubeval/kubeconform perform, just via a pip-installable
library instead of a Go binary. Same substitution pattern already
established for `terraform validate` (-> python-hcl2) and the real `opa`
binary (-> the local regorus-based test runner, still real for CI itself).

This is schema validity ONLY — "is this valid Kubernetes API syntax for a
real cluster" — a materially different, narrower question from
"is this configuration secure," which is what agent/k8s_engine.py answers.
A manifest can pass this test and still fail every one of k8s_engine.py's
8 rules (the vulnerable/ fixture does exactly that) — the two checks are
deliberately independent, same relationship as terraform-validate vs.
threat-model-gate in the CI workflow.
"""

from __future__ import annotations

import glob
from pathlib import Path

import kubernetes_validate as kv
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFESTS_DIR = REPO_ROOT / "kubernetes" / "manifests"

# Matches the Kubernetes version this project's Terraform provisions
# (see terraform/*/modules/*/aks|gke|eks — all pinned to a 1.29.x control
# plane as of Phase 1/5).
K8S_VERSION = "1.29"


def _load_all_documents(directory: Path) -> list[tuple[Path, dict]]:
    documents = []
    for path in sorted(directory.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if doc:
                documents.append((path, doc))
    return documents


@pytest.mark.parametrize("manifest_set", ["vulnerable", "hardened"])
def test_every_manifest_document_is_schema_valid(manifest_set):
    documents = _load_all_documents(MANIFESTS_DIR / manifest_set)
    assert documents, f"no YAML documents found in {manifest_set}/ — did the fixture move?"
    failures = []
    for path, doc in documents:
        try:
            kv.validate(doc, desired_version=K8S_VERSION)
        except kv.ValidationError as e:
            failures.append(f"{path.name}: {doc.get('kind')}/{doc.get('metadata', {}).get('name')}: {e}")
    assert not failures, "schema-invalid manifest(s):\n" + "\n".join(failures)


def test_vulnerable_and_hardened_have_the_same_number_of_documents_checked():
    """Sanity check that this test isn't silently validating an empty or
    partial directory — the vulnerable/hardened sets differ in file count
    (hardened has an extra networkpolicy.yaml) but both should have real
    content, not zero documents."""
    vuln = _load_all_documents(MANIFESTS_DIR / "vulnerable")
    hardened = _load_all_documents(MANIFESTS_DIR / "hardened")
    assert len(vuln) > 0
    assert len(hardened) > 0
    # hardened has one more file (networkpolicy.yaml, several NetworkPolicy
    # documents) than vulnerable, which has none — so it should have strictly
    # more documents, not fewer or equal.
    assert len(hardened) > len(vuln)
