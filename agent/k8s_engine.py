"""
Deterministic Kubernetes manifest engine — Phase 5 (SentinelCloud v1 spec §16).

Same split as threat_engine.py and detection_engine.py before it: every
finding here comes from an explicit, inspectable rule over the manifests
themselves (no model call, no ambiguity), so it's safe to gate a deploy on.
The LLM only narrates these findings afterward (explain.py's
narrate_finding, reused as-is — see below), never decides them.

This module deliberately reuses threat_engine.py's Finding/Severity/Stride
rather than inventing a third shape: a Kubernetes misconfiguration is still
a design-time, STRIDE-classifiable finding, the same category as an
architecture.json finding, just over a different input document (a set of
Kubernetes manifests instead of an architecture graph). That's why
explain.py's narrate_finding works on these findings completely unchanged
— confirmed by tests/test_k8s_engine.py, not assumed.

(Contrast with detection_engine.py's Alert, which is a genuinely different
kind of thing — a retrospective claim about events that already happened,
not a design-time property — so it correctly has its own dataclass rather
than reusing Finding. See docs/phase9-siem-detection.md's "why two
engines" section for that reasoning; the same reasoning is why this module
reuses Finding rather than duplicating it.)
"""

from __future__ import annotations

from pathlib import Path

import yaml

from threat_engine import Finding, Severity, Stride

# Capabilities that grant meaningfully dangerous privileges beyond a
# container's normal default set — not an exhaustive list, but the ones
# most directly tied to container-escape or host-compromise paths.
DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "NET_RAW",
    "SYS_PTRACE",
    "SYS_MODULE",
    "DAC_READ_SEARCH",
    "DAC_OVERRIDE",
}


class K8sManifest:
    """Wraps a set of parsed Kubernetes manifest documents with convenience
    lookups, mirroring the role Architecture plays for threat_engine.py."""

    def __init__(self, documents: list[dict]):
        # Multi-document YAML files can contain blank documents (a
        # trailing "---" with nothing after it parses to None) — drop
        # those rather than making every rule defend against them.
        self.documents: list[dict] = [d for d in documents if d]

    @classmethod
    def from_dir(cls, path: str | Path) -> "K8sManifest":
        """Load every *.yaml/*.yml file in a directory (non-recursive —
        each manifest set, vulnerable/ or hardened/, is a flat directory
        by convention) as one or more YAML documents."""
        docs: list[dict] = []
        for p in sorted(Path(path).glob("*.yaml")) + sorted(Path(path).glob("*.yml")):
            with open(p) as fh:
                docs.extend(yaml.safe_load_all(fh))
        return cls(docs)

    def of_kind(self, kind: str) -> list[dict]:
        return [d for d in self.documents if d.get("kind") == kind]

    def pod_specs(self) -> list[tuple[str, str, dict]]:
        """Every workload's pod template, as (kind, name, pod_spec) — the
        rules that inspect containers/hostNetwork/etc. all work off this,
        so a future Kubernetes workload kind (StatefulSet, DaemonSet, Job)
        only needs adding here once, not in every rule."""
        out = []
        for kind in ("Deployment", "StatefulSet", "DaemonSet"):
            for d in self.of_kind(kind):
                name = d.get("metadata", {}).get("name", "unnamed")
                spec = d.get("spec", {}).get("template", {}).get("spec", {})
                out.append((kind, name, spec))
        return out

    def containers(self) -> list[tuple[str, str, str, dict]]:
        """Every container across every workload, as
        (kind, workload_name, container_name, container_spec)."""
        out = []
        for kind, name, pod_spec in self.pod_specs():
            for c in pod_spec.get("containers", []):
                out.append((kind, name, c.get("name", "unnamed"), c))
        return out

    def namespaces_with_workloads(self) -> set[str]:
        return {
            d.get("metadata", {}).get("namespace", "default")
            for d in self.documents
            if d.get("kind") in ("Deployment", "StatefulSet", "DaemonSet")
        }


# --------------------------------------------------------------------------
# Rules — each takes a K8sManifest and yields zero or more Findings.
# --------------------------------------------------------------------------


def rule_privileged_container(manifest: K8sManifest):
    for kind, name, cname, c in manifest.containers():
        if c.get("securityContext", {}).get("privileged") is True:
            yield Finding(
                rule_id="K8S-PRIV-01",
                stride=Stride.ELEVATION_OF_PRIVILEGE,
                severity=Severity.CRITICAL,
                asset_ids=[f"{kind}/{name}/{cname}"],
                title=f"{kind}/{name} container '{cname}' runs privileged",
                threat=(
                    "A privileged container has essentially unrestricted access to "
                    "the host — every device, every kernel capability, no seccomp/"
                    "AppArmor confinement. A compromised process inside it can "
                    "escape to the node directly."
                ),
                impact="Container compromise becomes node compromise, and from there every workload scheduled on that node.",
                control_id="K8S-001",
                policy=f"{kind}/{name}'s '{cname}' container must not set securityContext.privileged: true.",
                mitigation="Remove privileged: true; request only the specific capabilities actually needed instead (see K8S-CAP-01).",
            )


def rule_host_namespace_sharing(manifest: K8sManifest):
    for kind, name, spec in manifest.pod_specs():
        shared = [ns for ns in ("hostNetwork", "hostPID", "hostIPC") if spec.get(ns) is True]
        if shared:
            yield Finding(
                rule_id="K8S-HOSTNS-01",
                stride=Stride.ELEVATION_OF_PRIVILEGE,
                severity=Severity.CRITICAL,
                asset_ids=[f"{kind}/{name}"],
                title=f"{kind}/{name} shares the host's {', '.join(shared)}",
                threat=(
                    "hostNetwork exposes the node's real network interfaces (no "
                    "namespace isolation — the pod sees and can inject on the "
                    "same interfaces the node itself uses); hostPID/hostIPC let "
                    "the pod see and signal every process on the node, not just "
                    "its own."
                ),
                impact="A compromised pod can sniff/spoof node-level network traffic and inspect or kill other pods' processes on the same node.",
                control_id="K8S-002",
                policy=f"{kind}/{name} must not set {'/'.join(shared)}: true unless the workload has a specific, documented need for host-level access.",
                mitigation="Remove the hostNetwork/hostPID/hostIPC fields; use a Kubernetes Service for network access and standard pod-to-pod isolation instead.",
            )


def rule_container_runs_as_root(manifest: K8sManifest):
    for kind, name, cname, c in manifest.containers():
        container_non_root = c.get("securityContext", {}).get("runAsNonRoot")
        if container_non_root is True:
            continue
        yield Finding(
            rule_id="K8S-ROOT-01",
            stride=Stride.ELEVATION_OF_PRIVILEGE,
            severity=Severity.HIGH,
            asset_ids=[f"{kind}/{name}/{cname}"],
            title=f"{kind}/{name} container '{cname}' does not enforce runAsNonRoot",
            threat=(
                "Without runAsNonRoot: true, the container can run as UID 0 "
                "(root) — whatever the image's Dockerfile happens to specify, "
                "not a property this manifest actually controls."
            ),
            impact="A container-breakout bug is far more dangerous as root: it starts with root's filesystem/capability defaults instead of an unprivileged user's.",
            control_id="K8S-003",
            policy=f"{kind}/{name}'s '{cname}' container must set securityContext.runAsNonRoot: true.",
            mitigation="Add runAsNonRoot: true (and runAsUser: <non-zero UID>) to the container's securityContext.",
        )


def rule_capabilities_not_dropped(manifest: K8sManifest):
    for kind, name, cname, c in manifest.containers():
        sc = c.get("securityContext", {}) or {}
        caps = sc.get("capabilities", {}) or {}
        dropped = caps.get("drop") or []
        added = caps.get("add") or []
        dangerous_added = [a for a in added if a in DANGEROUS_CAPABILITIES]
        if "ALL" not in dropped:
            yield Finding(
                rule_id="K8S-CAP-01",
                stride=Stride.ELEVATION_OF_PRIVILEGE,
                severity=Severity.HIGH,
                asset_ids=[f"{kind}/{name}/{cname}"],
                title=f"{kind}/{name} container '{cname}' does not drop all Linux capabilities",
                threat=(
                    "Containers get a broad default capability set unless the "
                    "manifest explicitly drops it. Most workloads need none of "
                    "the default set at all."
                ),
                impact="An unnecessary default capability (e.g. CAP_NET_RAW, CAP_CHOWN) becomes one more tool available to an attacker who compromises the process.",
                control_id="K8S-004",
                policy=f"{kind}/{name}'s '{cname}' container must set securityContext.capabilities.drop: [\"ALL\"], then add back only what it specifically needs.",
                mitigation="Add capabilities.drop: [\"ALL\"] and only capabilities.add the specific ones the workload actually requires, if any.",
            )
        elif dangerous_added:
            yield Finding(
                rule_id="K8S-CAP-01",
                stride=Stride.ELEVATION_OF_PRIVILEGE,
                severity=Severity.HIGH,
                asset_ids=[f"{kind}/{name}/{cname}"],
                title=f"{kind}/{name} container '{cname}' adds dangerous capabilities: {', '.join(dangerous_added)}",
                threat=(
                    "These capabilities are directly implicated in known "
                    "container-escape and privilege-escalation techniques "
                    "(e.g. NET_ADMIN/NET_RAW for network-level attacks, "
                    "SYS_ADMIN/SYS_PTRACE for near-root host access)."
                ),
                impact="Even with the default set correctly dropped, re-adding one of these largely defeats the point of dropping the rest.",
                control_id="K8S-004",
                policy=f"{kind}/{name}'s '{cname}' container should not add {', '.join(dangerous_added)} without a specific, documented, narrowly-scoped need.",
                mitigation="Remove the dangerous capability from capabilities.add; find a less privileged way to accomplish what it was added for.",
            )


def rule_broad_rbac(manifest: K8sManifest):
    for kind in ("Role", "ClusterRole"):
        for d in manifest.of_kind(kind):
            name = d.get("metadata", {}).get("name", "unnamed")
            for rule in d.get("rules", []) or []:
                verbs = rule.get("verbs", []) or []
                resources = rule.get("resources", []) or []
                if "*" in verbs and "*" in resources:
                    yield Finding(
                        rule_id="K8S-RBAC-01",
                        stride=Stride.ELEVATION_OF_PRIVILEGE,
                        severity=Severity.CRITICAL,
                        asset_ids=[f"{kind}/{name}"],
                        title=f"{kind}/{name} grants wildcard verbs and resources ('*'/'*')",
                        threat=(
                            "Any ServiceAccount bound to this role can read, "
                            "create, modify, or delete any resource of any kind "
                            f"{'cluster-wide' if kind == 'ClusterRole' else 'in its namespace'} "
                            "— Secrets, other workloads' pods, RBAC objects "
                            "themselves."
                        ),
                        impact="A compromised pod using this identity can pivot to read every Secret and take over every other workload it can reach, not just act within its own intended scope.",
                        control_id="K8S-005",
                        policy=f"{kind}/{name} must list specific apiGroups/resources/verbs (and, for a Role, resourceNames where practical) instead of '*'.",
                        mitigation="Replace the wildcard rule with the specific verbs and resources the bound ServiceAccount actually needs — same least-privilege principle as the cloud IAM roles in terraform/*/modules/iam.",
                    )


def rule_missing_network_policy(manifest: K8sManifest):
    policy_namespaces = {
        d.get("metadata", {}).get("namespace", "default")
        for d in manifest.of_kind("NetworkPolicy")
    }
    for ns in manifest.namespaces_with_workloads():
        if ns not in policy_namespaces:
            yield Finding(
                rule_id="K8S-NETPOL-01",
                stride=Stride.ELEVATION_OF_PRIVILEGE,
                severity=Severity.MEDIUM,
                asset_ids=[f"Namespace/{ns}"],
                title=f"Namespace '{ns}' has workloads but no NetworkPolicy",
                threat=(
                    "With no NetworkPolicy, Kubernetes' default is allow-all: "
                    "every pod in the cluster can reach every pod in this "
                    "namespace on any port, regardless of whether the service "
                    "mesh's mTLS (modules/mesh) is proving who's calling."
                ),
                impact="A compromised pod anywhere in the cluster — not just this namespace — can reach every workload here directly, enabling lateral movement the mesh's identity layer alone doesn't prevent.",
                control_id="K8S-006",
                policy=f"Namespace '{ns}' must have a default-deny NetworkPolicy plus explicit allow rules for the traffic each workload actually needs.",
                mitigation="Add a default-deny-all NetworkPolicy for the namespace, then explicit allow rules scoped to each workload's real traffic pattern (see kubernetes/manifests/hardened/networkpolicy.yaml).",
            )


def rule_missing_resource_limits(manifest: K8sManifest):
    for kind, name, cname, c in manifest.containers():
        limits = c.get("resources", {}).get("limits", {}) or {}
        missing = [r for r in ("cpu", "memory") if r not in limits]
        if missing:
            yield Finding(
                rule_id="K8S-RESOURCE-01",
                stride=Stride.DENIAL_OF_SERVICE,
                severity=Severity.MEDIUM,
                asset_ids=[f"{kind}/{name}/{cname}"],
                title=f"{kind}/{name} container '{cname}' has no {'/'.join(missing)} limit",
                threat=(
                    "Without resource limits, one runaway or compromised "
                    "container can consume all available CPU/memory on its "
                    "node, starving every other pod scheduled there."
                ),
                impact="A single misbehaving or intentionally resource-exhausting container becomes a node-wide (and potentially cluster-wide, via rescheduling pressure) denial of service.",
                control_id="K8S-007",
                policy=f"{kind}/{name}'s '{cname}' container must set resources.limits for {' and '.join(missing)}.",
                mitigation="Add resources.requests and resources.limits (both cpu and memory) sized to the workload's actual usage.",
            )


def rule_mutable_image_tag(manifest: K8sManifest):
    for kind, name, cname, c in manifest.containers():
        image = c.get("image", "")
        tag = image.rsplit(":", 1)[-1] if ":" in image else None
        if tag is None or tag == "latest":
            yield Finding(
                rule_id="K8S-IMAGE-01",
                stride=Stride.TAMPERING,
                severity=Severity.MEDIUM,
                asset_ids=[f"{kind}/{name}/{cname}"],
                title=f"{kind}/{name} container '{cname}' uses a mutable image reference ({image or 'no tag'})",
                threat=(
                    "':latest' (or no tag at all) can point to different actual "
                    "image content on different days, or even different "
                    "content on the same tag if it gets re-pushed — there's no "
                    "way to know exactly what code is running, or to roll back "
                    "to a known-good build reliably."
                ),
                impact="An attacker (or a mistake) that re-pushes the same tag changes what every future pod runs without any manifest change to review or audit.",
                control_id="K8S-008",
                policy=f"{kind}/{name}'s '{cname}' container must reference an immutable image (a specific version tag, ideally pinned by digest), not ':latest' or an untagged reference.",
                mitigation="Pin the image to a specific version (and ideally a content digest, e.g. image@sha256:...) produced by CI, not a floating tag.",
            )


ALL_RULES = [
    rule_privileged_container,
    rule_host_namespace_sharing,
    rule_container_runs_as_root,
    rule_capabilities_not_dropped,
    rule_broad_rbac,
    rule_missing_network_policy,
    rule_missing_resource_limits,
    rule_mutable_image_tag,
]


def run_engine(manifest: K8sManifest) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(manifest))
    findings.sort(key=lambda f: f.severity.value, reverse=True)
    return findings
