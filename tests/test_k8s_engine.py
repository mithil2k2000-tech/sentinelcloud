"""
Unit tests for the deterministic Kubernetes manifest engine (Phase 5,
v1 spec §16) — same approach as test_threat_engine.py: each rule gets a
positive case (a minimal manifest set crafted to trigger it) and a
negative case (a minimal manifest set that should NOT trigger it), built
directly as Python dicts rather than loaded from disk, so each test's
intent is visible in the test itself. A separate integration test at the
bottom checks the real fixtures in kubernetes/manifests/.
"""

from __future__ import annotations

from pathlib import Path

from k8s_engine import (
    K8sManifest,
    Severity,
    Stride,
    rule_broad_rbac,
    rule_capabilities_not_dropped,
    rule_container_runs_as_root,
    rule_host_namespace_sharing,
    rule_missing_network_policy,
    rule_missing_resource_limits,
    rule_mutable_image_tag,
    rule_privileged_container,
    run_engine,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def deployment(name="svc", namespace="app", containers=None, pod_overrides=None):
    """A minimal Deployment dict. `containers` is a list of container
    dicts (default: one minimal, safe container); `pod_overrides` merges
    into spec.template.spec (for hostNetwork/hostPID/etc.)."""
    if containers is None:
        containers = [safe_container()]
    pod_spec = {"containers": containers}
    if pod_overrides:
        pod_spec.update(pod_overrides)
    return {
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"template": {"spec": pod_spec}},
    }


def safe_container(name="svc", **overrides):
    """A container dict with every rule's condition already satisfied —
    negative-case tests start from this and override only the one field
    under test."""
    c = {
        "name": name,
        "image": "example/svc:1.0.0",
        "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}},
        "securityContext": {
            "privileged": False,
            "runAsNonRoot": True,
            "capabilities": {"drop": ["ALL"]},
        },
    }
    c.update(overrides)
    return c


def manifest(*docs) -> K8sManifest:
    return K8sManifest(list(docs))


# ---------------------------------------------------------------------------
# rule_privileged_container — K8S-PRIV-01
# ---------------------------------------------------------------------------

def test_privileged_container_fires_critical():
    c = safe_container()
    c["securityContext"]["privileged"] = True
    m = manifest(deployment(containers=[c]))
    findings = list(rule_privileged_container(m))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-PRIV-01"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].stride == Stride.ELEVATION_OF_PRIVILEGE


def test_non_privileged_container_does_not_fire():
    m = manifest(deployment())
    assert list(rule_privileged_container(m)) == []


# ---------------------------------------------------------------------------
# rule_host_namespace_sharing — K8S-HOSTNS-01
# ---------------------------------------------------------------------------

def test_host_network_fires_critical():
    m = manifest(deployment(pod_overrides={"hostNetwork": True}))
    findings = list(rule_host_namespace_sharing(m))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-HOSTNS-01"
    assert findings[0].severity == Severity.CRITICAL
    assert "hostNetwork" in findings[0].title


def test_host_pid_and_ipc_both_named_in_one_finding():
    m = manifest(deployment(pod_overrides={"hostPID": True, "hostIPC": True}))
    findings = list(rule_host_namespace_sharing(m))
    assert len(findings) == 1
    assert "hostPID" in findings[0].title and "hostIPC" in findings[0].title


def test_no_host_namespace_sharing_does_not_fire():
    m = manifest(deployment())
    assert list(rule_host_namespace_sharing(m)) == []


# ---------------------------------------------------------------------------
# rule_container_runs_as_root — K8S-ROOT-01
# ---------------------------------------------------------------------------

def test_missing_run_as_non_root_fires_high():
    c = safe_container()
    del c["securityContext"]["runAsNonRoot"]
    m = manifest(deployment(containers=[c]))
    findings = list(rule_container_runs_as_root(m))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-ROOT-01"
    assert findings[0].severity == Severity.HIGH


def test_run_as_non_root_false_fires():
    c = safe_container()
    c["securityContext"]["runAsNonRoot"] = False
    m = manifest(deployment(containers=[c]))
    findings = list(rule_container_runs_as_root(m))
    assert len(findings) == 1


def test_run_as_non_root_true_does_not_fire():
    m = manifest(deployment())
    assert list(rule_container_runs_as_root(m)) == []


# ---------------------------------------------------------------------------
# rule_capabilities_not_dropped — K8S-CAP-01
# ---------------------------------------------------------------------------

def test_capabilities_not_dropped_fires_high():
    c = safe_container()
    c["securityContext"]["capabilities"] = {}
    m = manifest(deployment(containers=[c]))
    findings = list(rule_capabilities_not_dropped(m))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "does not drop all" in findings[0].title


def test_dangerous_capability_added_after_dropping_all_fires():
    c = safe_container()
    c["securityContext"]["capabilities"] = {"drop": ["ALL"], "add": ["NET_ADMIN"]}
    m = manifest(deployment(containers=[c]))
    findings = list(rule_capabilities_not_dropped(m))
    assert len(findings) == 1
    assert "NET_ADMIN" in findings[0].title


def test_harmless_capability_added_after_dropping_all_does_not_fire():
    c = safe_container()
    c["securityContext"]["capabilities"] = {"drop": ["ALL"], "add": ["CHOWN"]}
    m = manifest(deployment(containers=[c]))
    assert list(rule_capabilities_not_dropped(m)) == []


def test_all_dropped_and_nothing_added_does_not_fire():
    m = manifest(deployment())
    assert list(rule_capabilities_not_dropped(m)) == []


# ---------------------------------------------------------------------------
# rule_broad_rbac — K8S-RBAC-01
# ---------------------------------------------------------------------------

def test_wildcard_cluster_role_fires_critical():
    cr = {
        "kind": "ClusterRole",
        "metadata": {"name": "broad-role"},
        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
    }
    m = manifest(cr)
    findings = list(rule_broad_rbac(m))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-RBAC-01"
    assert findings[0].severity == Severity.CRITICAL


def test_scoped_role_does_not_fire():
    role = {
        "kind": "Role",
        "metadata": {"name": "scoped-role", "namespace": "app"},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "list"]}],
    }
    m = manifest(role)
    assert list(rule_broad_rbac(m)) == []


def test_wildcard_verbs_alone_without_wildcard_resources_does_not_fire():
    """Only the combination of wildcard verbs AND wildcard resources is
    flagged — a role with '*' verbs on one named resource type, while
    still broader than ideal, isn't the "any verb on anything" case this
    rule targets. Documents the rule's actual boundary rather than
    leaving it implicit."""
    role = {
        "kind": "Role",
        "metadata": {"name": "verb-only", "namespace": "app"},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["*"]}],
    }
    m = manifest(role)
    assert list(rule_broad_rbac(m)) == []


# ---------------------------------------------------------------------------
# rule_missing_network_policy — K8S-NETPOL-01
# ---------------------------------------------------------------------------

def test_namespace_with_workload_and_no_network_policy_fires_medium():
    m = manifest(deployment(namespace="app"))
    findings = list(rule_missing_network_policy(m))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-NETPOL-01"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].asset_ids == ["Namespace/app"]


def test_namespace_with_network_policy_does_not_fire():
    np = {
        "kind": "NetworkPolicy",
        "metadata": {"name": "default-deny", "namespace": "app"},
        "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
    }
    m = manifest(deployment(namespace="app"), np)
    assert list(rule_missing_network_policy(m)) == []


def test_network_policy_in_different_namespace_does_not_cover_this_one():
    np = {
        "kind": "NetworkPolicy",
        "metadata": {"name": "default-deny", "namespace": "other-namespace"},
        "spec": {},
    }
    m = manifest(deployment(namespace="app"), np)
    findings = list(rule_missing_network_policy(m))
    assert len(findings) == 1
    assert findings[0].asset_ids == ["Namespace/app"]


# ---------------------------------------------------------------------------
# rule_missing_resource_limits — K8S-RESOURCE-01
# ---------------------------------------------------------------------------

def test_missing_both_limits_fires_medium():
    c = safe_container()
    del c["resources"]
    m = manifest(deployment(containers=[c]))
    findings = list(rule_missing_resource_limits(m))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "cpu/memory" in findings[0].title


def test_missing_only_memory_limit_fires_and_names_only_memory():
    c = safe_container()
    c["resources"] = {"limits": {"cpu": "500m"}}
    m = manifest(deployment(containers=[c]))
    findings = list(rule_missing_resource_limits(m))
    assert len(findings) == 1
    assert "memory" in findings[0].title
    assert "cpu" not in findings[0].title.split("has no")[-1]


def test_both_limits_present_does_not_fire():
    m = manifest(deployment())
    assert list(rule_missing_resource_limits(m)) == []


# ---------------------------------------------------------------------------
# rule_mutable_image_tag — K8S-IMAGE-01
# ---------------------------------------------------------------------------

def test_latest_tag_fires_medium():
    c = safe_container()
    c["image"] = "example/svc:latest"
    m = manifest(deployment(containers=[c]))
    findings = list(rule_mutable_image_tag(m))
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-IMAGE-01"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].stride == Stride.TAMPERING


def test_no_tag_at_all_fires():
    c = safe_container()
    c["image"] = "example/svc"
    m = manifest(deployment(containers=[c]))
    findings = list(rule_mutable_image_tag(m))
    assert len(findings) == 1


def test_pinned_version_tag_does_not_fire():
    m = manifest(deployment())  # safe_container() uses "1.0.0"
    assert list(rule_mutable_image_tag(m)) == []


# ---------------------------------------------------------------------------
# Integration — real fixtures, real documented numbers (run for real, not
# hand-derived: see docs/phase5-kubernetes.md).
# ---------------------------------------------------------------------------

def test_vulnerable_fixture_produces_documented_findings():
    m = K8sManifest.from_dir(REPO_ROOT / "kubernetes" / "manifests" / "vulnerable")
    findings = run_engine(m)
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    assert len(findings) == 14
    assert counts == {Severity.LOW: 0, Severity.MEDIUM: 5, Severity.HIGH: 6, Severity.CRITICAL: 3}


def test_hardened_fixture_produces_zero_findings():
    m = K8sManifest.from_dir(REPO_ROOT / "kubernetes" / "manifests" / "hardened")
    findings = run_engine(m)
    assert findings == []


def test_hardened_fixture_has_a_real_network_policy_not_just_an_absence_of_deployments():
    """Guards against the trivial way test_hardened_fixture_produces_zero_findings
    could pass for the wrong reason: confirms the hardened fixture actually
    defines the same three workloads as the vulnerable one, so the zero
    finding count reflects real hardening, not an empty fixture."""
    vulnerable = K8sManifest.from_dir(REPO_ROOT / "kubernetes" / "manifests" / "vulnerable")
    hardened = K8sManifest.from_dir(REPO_ROOT / "kubernetes" / "manifests" / "hardened")
    vulnerable_names = {d["metadata"]["name"] for d in vulnerable.of_kind("Deployment")}
    hardened_names = {d["metadata"]["name"] for d in hardened.of_kind("Deployment")}
    assert vulnerable_names == hardened_names == {"payment-service", "account-service", "notification-service"}
    assert len(hardened.of_kind("NetworkPolicy")) > 0
