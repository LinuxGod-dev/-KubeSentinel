"""RBAC definition and binding checks (KS-RBAC-*)."""
from __future__ import annotations

from typing import List, Optional

from ..catalog import make_finding
from ..loader import Inventory
from ..models import Finding, Severity
from ..rbac_model import BUILTIN_CLUSTER_ROLES, WORKLOAD_RESOURCES, RBACModel, Subject, rule_matches

BROAD_GROUPS = {"system:anonymous", "system:unauthenticated", "system:authenticated",
                "system:serviceaccounts"}


def _skip_role(kind: str, name: str, role: dict) -> bool:
    labels = (role.get("metadata") or {}).get("labels") or {}
    if labels.get("kubernetes.io/bootstrapping") == "rbac-defaults":
        return True
    return kind == "ClusterRole" and (name.startswith("system:") or name in BUILTIN_CLUSTER_ROLES)


def _any(rules: List[dict], resources, verbs) -> bool:
    return any(rule_matches(r, v, res) for r in rules for res in resources for v in verbs)


def run(inv: Inventory, ctx) -> List[Finding]:
    model = RBACModel(inv)
    out: List[Finding] = []

    # ---- role definition checks -------------------------------------------------------------
    for (ns, name), role in sorted(inv.roles.items(), key=lambda kv: (kv[0][0] or "", kv[0][1])):
        kind = "Role" if ns else "ClusterRole"
        if _skip_role(kind, name, role) or (ns and ns in ctx.exclude_namespaces):
            continue
        rules = role.get("rules") or []
        ref = f"{kind}/{ns + '/' if ns else ''}{name}"
        loc = inv.role_sources.get((ns, name), "cluster")
        bound = model.bound_subjects(kind, name, ns)
        who = (", ".join(sorted({str(s) for s in bound})) or "not bound in scanned scope")
        cluster_scope = kind == "ClusterRole"
        ev = [f"bound to: {who}"]

        def add(rule_id, msg, sev=None):
            out.append(make_finding(rule_id, ref, msg, severity=sev, evidence=ev, location=loc))

        wild = [r for r in rules if "*" in (r.get("verbs") or []) or "*" in (r.get("resources") or [])]
        if wild:
            both = any("*" in (r.get("verbs") or []) and "*" in (r.get("resources") or []) for r in wild)
            add("KS-RBAC-002", "Wildcard verbs and resources: equivalent to admin in its scope." if both
                else "Wildcard in verbs or resources.", Severity.CRITICAL if both and cluster_scope else Severity.HIGH)

        esc = [v for v in ("escalate", "bind") if _any(rules, ["roles", "clusterroles"], [v])]
        imp = _any(rules, ["users", "groups", "serviceaccounts"], ["impersonate"])
        if esc or imp:
            add("KS-RBAC-003", "Grants: " + ", ".join(esc + (["impersonate"] if imp else [])) + ".")

        if _any(rules, ["secrets"], ["get", "list", "watch"]):
            add("KS-RBAC-004", "Can read Secrets " + ("cluster-wide." if cluster_scope else f"in namespace {ns}."),
                Severity.HIGH if cluster_scope else Severity.MEDIUM)

        if _any(rules, ["pods/exec", "pods/attach"], ["create", "get"]):
            add("KS-RBAC-005", "Can exec/attach into pods.")

        if _any(rules, list(WORKLOAD_RESOURCES), ["create"]):
            add("KS-RBAC-006", "Can create workloads; each new pod can run as any ServiceAccount in its namespace.")

        if _any(rules, ["nodes/proxy"], ["get", "create"]):
            add("KS-RBAC-009", "Can reach the kubelet API through the API server.")

        if _any(rules, ["serviceaccounts/token"], ["create"]):
            add("KS-RBAC-010", "Can request tokens for ServiceAccounts.")

    # ---- binding checks ----------------------------------------------------------------------
    for b, kind, bns, subjects, label in model._bindings:
        meta = b.get("metadata") or {}
        bname = meta.get("name", "?")
        if bns and bns in ctx.exclude_namespaces:
            continue
        ref = f"{kind}/{bns + '/' if bns else ''}{bname}"
        loc = inv.binding_sources.get(id(b), "cluster")
        rref = b.get("roleRef") or {}
        role_name = rref.get("name", "")
        custom_role = not role_name.startswith("system:")

        for s in subjects:
            if rref.get("kind") == "ClusterRole" and role_name == "cluster-admin" and not s.is_system:
                out.append(make_finding(
                    "KS-RBAC-001", ref, f"{s} is bound to cluster-admin" +
                    (f" within namespace {bns}." if bns else " cluster-wide."), location=loc,
                    severity=Severity.CRITICAL if not bns else Severity.HIGH, evidence=[label]))
            if s.kind == "ServiceAccount" and s.name == "default" and custom_role:
                out.append(make_finding("KS-RBAC-007", ref, f"{s} receives role {role_name}.", location=loc, evidence=[label]))
            if s.kind in ("User", "Group") and s.name in BROAD_GROUPS and (custom_role or role_name == "cluster-admin"):
                sev = Severity.CRITICAL if (s.name in ("system:anonymous", "system:unauthenticated") or role_name == "cluster-admin") else Severity.HIGH
                out.append(make_finding("KS-RBAC-008", ref, f"{s} is bound to {role_name}: every matching identity inherits it.",
                                        severity=sev, location=loc, evidence=[label]))
    return out
