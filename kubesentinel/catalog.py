"""Central catalog of checks.

Every finding is built from an entry here, so titles, severities, remediation text,
CIS/MITRE references and the linked Falco detections stay consistent.

NOTE: CIS references follow Kubernetes Benchmark v1.8 numbering and are approximate -
verify against the benchmark version you are assessed against.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .models import Finding, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    remediation: str
    cis: str = ""
    mitre: str = ""
    detection: tuple = ()


# Falco rule names (must exist in rules/falco/kubesentinel_rules.yaml - enforced by tests)
F_SHELL = "KubeSentinel Interactive Shell in Container"
F_TOKEN = "KubeSentinel ServiceAccount Token Read by Suspicious Process"
F_WRITE = "KubeSentinel Write to Sensitive Directory in Container"
F_PKG = "KubeSentinel Package Manager Run in Container"
F_MINER = "KubeSentinel Crypto Miner Activity in Container"
F_NSENTER = "KubeSentinel Container Escape via nsenter"
F_MOUNT = "KubeSentinel Mount Syscall in Container"
F_SOCK = "KubeSentinel Container Runtime Socket Connection"
F_API = "KubeSentinel Kubernetes API Client in Container"
F_REVSHELL = "KubeSentinel Reverse Shell in Container"
F_HOSTFILE = "KubeSentinel Sensitive Credential File Read in Container"

_R = Rule
RULES = {r.id: r for r in [
    # ---- workload hardening -------------------------------------------------
    _R("KS-WL-001", "Privileged container", Severity.CRITICAL, "workload",
       "Remove securityContext.privileged. Grant only the specific capabilities required.",
       "5.2.2", "T1611", (F_NSENTER, F_MOUNT)),
    _R("KS-WL-002", "Pod shares host namespaces", Severity.HIGH, "workload",
       "Remove hostPID/hostIPC/hostNetwork unless the workload is a node-level agent.",
       "5.2.3-5.2.5", "T1611", (F_NSENTER,)),
    _R("KS-WL-003", "hostPath volume mounted", Severity.HIGH, "workload",
       "Use emptyDir, PVCs or CSI volumes. If hostPath is unavoidable, mount a narrow read-only path.",
       "5.2.12", "T1611", (F_SOCK, F_HOSTFILE)),
    _R("KS-WL-004", "Dangerous Linux capabilities added", Severity.HIGH, "workload",
       "Drop ALL capabilities and add back only what is needed (never SYS_ADMIN, SYS_PTRACE, SYS_MODULE).",
       "5.2.9", "T1611", (F_MOUNT, F_NSENTER)),
    _R("KS-WL-005", "Container may run as root", Severity.MEDIUM, "workload",
       "Set runAsNonRoot: true and a non-zero runAsUser.",
       "5.2.7", "", (F_SHELL,)),
    _R("KS-WL-006", "Privilege escalation not disabled", Severity.MEDIUM, "workload",
       "Set securityContext.allowPrivilegeEscalation: false.",
       "5.2.6", "", ()),
    _R("KS-WL-007", "Root filesystem is writable", Severity.LOW, "workload",
       "Set readOnlyRootFilesystem: true and mount emptyDir volumes for paths that need writes.",
       "5.7.3", "", (F_WRITE, F_PKG)),
    _R("KS-WL-008", "No CPU/memory limits", Severity.LOW, "workload",
       "Set resources.limits for cpu and memory (limits cap the blast radius of crypto-mining abuse).",
       "", "T1496", (F_MINER,)),
    _R("KS-WL-009", "Image not pinned (latest / untagged)", Severity.LOW, "workload",
       "Pin images to a version tag or, better, an immutable digest.",
       "", "", ()),
    _R("KS-WL-010", "Default ServiceAccount token auto-mounted", Severity.LOW, "workload",
       "Create a dedicated ServiceAccount and set automountServiceAccountToken: false unless the pod calls the API.",
       "5.1.5-5.1.6", "T1552.007", (F_TOKEN, F_API)),
    _R("KS-WL-011", "No seccomp profile set", Severity.LOW, "workload",
       "Set securityContext.seccompProfile.type: RuntimeDefault.",
       "5.7.2", "", ()),
    # ---- RBAC ---------------------------------------------------------------
    _R("KS-RBAC-001", "cluster-admin granted to non-system subject", Severity.CRITICAL, "rbac",
       "Replace with a least-privilege Role/ClusterRole. Reserve cluster-admin for break-glass identities.",
       "5.1.1", "T1078", (F_TOKEN, F_API)),
    _R("KS-RBAC-002", "Wildcard permissions in role", Severity.HIGH, "rbac",
       "List explicit verbs and resources instead of '*'.",
       "5.1.3", "T1078", (F_API,)),
    _R("KS-RBAC-003", "Role allows escalate / bind / impersonate", Severity.HIGH, "rbac",
       "Remove escalate, bind and impersonate verbs from everything except trusted RBAC administrators.",
       "5.1.8", "T1078", (F_API,)),
    _R("KS-RBAC-004", "Role can read Secrets", Severity.MEDIUM, "rbac",
       "Restrict secrets access to named resources (resourceNames) and avoid list/watch.",
       "5.1.2", "T1552.007", (F_TOKEN, F_API)),
    _R("KS-RBAC-005", "Role allows pods/exec or pods/attach", Severity.HIGH, "rbac",
       "Remove exec/attach from workload and CI identities; keep it for audited break-glass roles.",
       "", "T1609", (F_SHELL, F_API)),
    _R("KS-RBAC-006", "Role can create workloads", Severity.MEDIUM, "rbac",
       "Limit workload creation to deployment pipelines and enforce Pod Security Admission on the namespace.",
       "5.1.4", "T1610", (F_MINER, F_NSENTER, F_MOUNT)),
    _R("KS-RBAC-007", "Binding targets the default ServiceAccount", Severity.MEDIUM, "rbac",
       "Bind roles to dedicated ServiceAccounts, never to 'default' (every pod in the namespace inherits it).",
       "5.1.5", "T1078", (F_TOKEN,)),
    _R("KS-RBAC-008", "Binding targets a broad built-in group", Severity.HIGH, "rbac",
       "Never bind custom roles to system:anonymous, system:unauthenticated, system:authenticated or all service accounts.",
       "5.1.7", "T1078", (F_API,)),
    _R("KS-RBAC-009", "Role allows nodes/proxy", Severity.HIGH, "rbac",
       "Remove nodes/proxy; it allows command execution on pods via the kubelet API.",
       "5.1.10", "T1611", (F_API,)),
    _R("KS-RBAC-010", "Role can mint ServiceAccount tokens", Severity.HIGH, "rbac",
       "Remove create on serviceaccounts/token from non-admin identities.",
       "", "T1528", (F_TOKEN, F_API)),
    # ---- secrets ------------------------------------------------------------
    _R("KS-SEC-001", "Credential in plain-text environment variable", Severity.HIGH, "secrets",
       "Move the value into a Secret (ideally from an external secret store) and reference it via valueFrom.",
       "5.4.1", "T1552.001", (F_TOKEN,)),
    _R("KS-SEC-002", "Credential-like data in ConfigMap", Severity.HIGH, "secrets",
       "ConfigMaps are not access-controlled like Secrets. Move credentials to a Secret or external store and rotate them.",
       "5.4.2", "T1552.001", ()),
    _R("KS-SEC-003", "Secret object committed in manifests", Severity.MEDIUM, "secrets",
       "Do not commit Secret manifests. Use sealed-secrets, SOPS or an external secrets operator.",
       "5.4.2", "T1552.001", ()),
    # ---- network / admission ------------------------------------------------
    _R("KS-NET-001", "Namespace has workloads but no NetworkPolicy", Severity.MEDIUM, "network",
       "Add a default-deny NetworkPolicy, then allow only required traffic.",
       "5.3.2", "", (F_REVSHELL,)),
    _R("KS-NET-002", "Namespace has no default-deny ingress policy", Severity.LOW, "network",
       "Add a NetworkPolicy selecting all pods (podSelector: {}) with policyTypes [Ingress] and no ingress rules.",
       "5.3.2", "", ()),
    _R("KS-ADM-001", "Pod Security Admission not enforced", Severity.MEDIUM, "admission",
       "Label the namespace pod-security.kubernetes.io/enforce=baseline (or restricted).",
       "5.2.1", "T1610", (F_NSENTER, F_MOUNT)),
    # ---- escalation paths ---------------------------------------------------
    _R("KS-ESC-001", "RBAC escalation path to cluster-admin", Severity.CRITICAL, "escalation",
       "Break the chain at its weakest hop: remove the workload-creation / exec / secret-read grant or the over-privileged target ServiceAccount.",
       "", "T1078", (F_TOKEN, F_API, F_SHELL)),
    _R("KS-ESC-002", "RBAC escalation path to node compromise", Severity.HIGH, "escalation",
       "Enforce Pod Security Admission (baseline+) on target namespaces and remove nodes/proxy.",
       "", "T1611", (F_NSENTER, F_MOUNT, F_SOCK)),
    _R("KS-ESC-003", "RBAC escalation path to all cluster Secrets", Severity.HIGH, "escalation",
       "Remove cluster-wide secrets read access from the target identity or the chain leading to it.",
       "", "T1552.007", (F_TOKEN, F_API)),
]}


def make_finding(rule_id: str, resource: str, message: str, *, severity: Severity | None = None,
                 evidence: List[str] | None = None, location: str = "cluster") -> Finding:
    r = RULES[rule_id]
    return Finding(
        rule_id=r.id, title=r.title, severity=severity if severity is not None else r.severity,
        category=r.category, resource=resource, message=message, remediation=r.remediation,
        cis=r.cis, mitre=r.mitre, detection=list(r.detection), evidence=evidence or [], location=location,
    )
