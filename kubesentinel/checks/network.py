"""Network policy and Pod Security Admission checks (KS-NET-*, KS-ADM-001)."""
from __future__ import annotations

from typing import List

from ..catalog import make_finding
from ..loader import Inventory
from ..models import Finding, Severity

PSA_ENFORCE = "pod-security.kubernetes.io/enforce"


def is_default_deny_ingress(np: dict) -> bool:
    spec = np.get("spec") or {}
    sel = spec.get("podSelector") or {}
    if sel.get("matchLabels") or sel.get("matchExpressions"):
        return False
    types = spec.get("policyTypes") or ["Ingress"]
    return "Ingress" in types and not spec.get("ingress")


def psa_level(inv: Inventory, namespace: str) -> str:
    """'privileged' (no enforcement / unknown), 'baseline' or 'restricted'."""
    ns = inv.namespaces.get(namespace)
    level = ((ns or {}).get("metadata") or {}).get("labels", {}) or {}
    return level.get(PSA_ENFORCE, "privileged")


def run(inv: Inventory, ctx) -> List[Finding]:
    out: List[Finding] = []
    nps_by_ns = {}
    for np in inv.network_policies:
        nps_by_ns.setdefault((np.get("metadata") or {}).get("namespace") or "default", []).append(np)

    workload_ns = sorted({w.namespace for w in inv.workloads} - set(ctx.exclude_namespaces))
    for ns in workload_ns:
        loc = inv.location(f"Namespace//{ns}")
        nps = nps_by_ns.get(ns, [])
        if not nps:
            out.append(make_finding("KS-NET-001", f"Namespace/{ns}",
                                    f"Namespace {ns} runs workloads but no NetworkPolicy was found "
                                    "(all pod-to-pod traffic is allowed). If policies are managed elsewhere, include them in the scan.",
                                    location=loc))
        elif not any(is_default_deny_ingress(np) for np in nps):
            out.append(make_finding("KS-NET-002", f"Namespace/{ns}",
                                    f"Namespace {ns} has NetworkPolicies but none is a default-deny ingress policy.",
                                    location=loc))

    for name, obj in sorted(inv.namespaces.items()):
        if name in ctx.exclude_namespaces or name in ("kube-public", "kube-node-lease"):
            continue
        labels = (obj.get("metadata") or {}).get("labels") or {}
        level = labels.get(PSA_ENFORCE)
        if level in (None, "privileged"):
            out.append(make_finding("KS-ADM-001", f"Namespace/{name}",
                                    f"Namespace {name} does not enforce Pod Security Standards "
                                    f"({PSA_ENFORCE} is {'unset' if level is None else 'privileged'}).",
                                    location=inv.location(f"Namespace//{name}")))
    return out
