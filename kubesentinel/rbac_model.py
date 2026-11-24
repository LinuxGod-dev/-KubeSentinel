"""Effective-permission model built from Roles, ClusterRoles and bindings.

Simplifications (documented in README):
  * apiGroups are ignored when matching resources (lenient: may over-report).
  * Built-in ClusterRoles (cluster-admin/admin/edit/view) are approximated when not present
    in the scanned manifests; live mode reads the real, aggregated rules from the cluster.
  * Rules restricted by resourceNames are ignored for capability checks, except impersonation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .loader import Inventory

WORKLOAD_RESOURCES = ("pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "replicasets")

_ALL = {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}
_RW = ["get", "list", "watch", "create", "update", "patch", "delete"]
BUILTIN_CLUSTER_ROLES: Dict[str, List[dict]] = {
    "cluster-admin": [_ALL],
    "admin": [{"resources": ["pods", "pods/exec", "pods/attach", "pods/log", "secrets", "configmaps", "serviceaccounts",
                             "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs",
                             "services", "persistentvolumeclaims", "roles", "rolebindings", "networkpolicies"],
               "verbs": _RW},
              {"resources": ["serviceaccounts/token"], "verbs": ["create"]}],
    "edit": [{"resources": ["pods", "pods/exec", "pods/attach", "pods/log", "secrets", "configmaps", "serviceaccounts",
                            "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs",
                            "services", "persistentvolumeclaims"], "verbs": _RW},
             {"resources": ["serviceaccounts/token"], "verbs": ["create"]}],
    "view": [{"resources": ["pods", "pods/log", "configmaps", "serviceaccounts", "deployments", "daemonsets",
                            "statefulsets", "replicasets", "jobs", "cronjobs", "services", "persistentvolumeclaims"],
              "verbs": ["get", "list", "watch"]}],
}


@dataclass(frozen=True)
class Subject:
    kind: str                # User | Group | ServiceAccount
    namespace: Optional[str]
    name: str

    def __str__(self) -> str:
        if self.kind == "ServiceAccount":
            return f"ServiceAccount {self.namespace}/{self.name}"
        return f"{self.kind} {self.name}"

    @property
    def is_system(self) -> bool:
        return self.name.startswith("system:") and self.kind != "ServiceAccount"


@dataclass
class Grant:
    scope_ns: Optional[str]        # None = cluster-wide
    rules: List[dict]
    via: str                       # human-readable "RoleBinding dev/x -> Role dev/y"
    role_ref: str = ""


def groups_of(s: Subject) -> List[str]:
    if s.kind == "ServiceAccount":
        return ["system:serviceaccounts", f"system:serviceaccounts:{s.namespace}", "system:authenticated"]
    if s.kind == "User":
        return ["system:unauthenticated"] if s.name == "system:anonymous" else ["system:authenticated"]
    return []


def _match(values: Iterable[str], wanted: str) -> bool:
    vals = list(values or [])
    if "*" in vals or wanted in vals:
        return True
    if "/" in wanted:
        return f"{wanted.split('/', 1)[0]}/*" in vals
    return False


def rule_matches(rule: dict, verb: str, resource: str) -> bool:
    return _match(rule.get("verbs"), verb) and _match(rule.get("resources"), resource)


def subject_from_spec(spec: dict, default_ns: Optional[str]) -> Subject:
    kind = spec.get("kind", "User")
    ns = spec.get("namespace") or (default_ns if kind == "ServiceAccount" else None)
    return Subject(kind, ns, spec.get("name", ""))


class RBACModel:
    def __init__(self, inv: Inventory):
        self.inv = inv
        self._grants: Dict[Subject, List[Grant]] = {}
        self._bindings = self._index_bindings()

    # ---- role resolution -----------------------------------------------------------------
    def role_rules(self, kind: str, name: str, ns: Optional[str]) -> Optional[List[dict]]:
        key = (ns if kind == "Role" else None, name)
        role = self.inv.roles.get(key)
        if role is not None:
            return role.get("rules") or []
        if kind == "ClusterRole" and name in BUILTIN_CLUSTER_ROLES:
            return BUILTIN_CLUSTER_ROLES[name]
        return None   # unknown role (not in scan scope)

    def _index_bindings(self) -> List[Tuple[dict, str, Optional[str], List[Subject], str]]:
        out = []
        for b in self.inv.bindings:
            kind = b.get("kind")
            meta = b.get("metadata") or {}
            bns = None if kind == "ClusterRoleBinding" else (meta.get("namespace") or "default")
            ref = b.get("roleRef") or {}
            subjects = [subject_from_spec(s, bns) for s in b.get("subjects") or []]
            label = f"{kind} {(bns + '/') if bns else ''}{meta.get('name', '?')} -> {ref.get('kind')} {ref.get('name')}"
            out.append((b, kind, bns, subjects, label))
        return out

    # ---- grants ---------------------------------------------------------------------------
    def grants_for(self, subject: Subject) -> List[Grant]:
        if subject in self._grants:
            return self._grants[subject]
        identities = {subject} | {Subject("Group", None, g) for g in groups_of(subject)}
        grants: List[Grant] = []
        for b, kind, bns, subjects, label in self._index_bindings_cached():
            if not any(s in identities for s in subjects):
                continue
            ref = b.get("roleRef") or {}
            rules = self.role_rules(ref.get("kind", ""), ref.get("name", ""), bns)
            if rules is None:
                continue
            grants.append(Grant(bns, rules, label, f"{ref.get('kind')}/{ref.get('name')}"))
        self._grants[subject] = grants
        return grants

    def _index_bindings_cached(self):
        return self._bindings

    def can(self, subject: Subject, verb: str, resource: str, namespace: Optional[str] = None,
            allow_named: bool = False) -> Optional[Tuple[Grant, dict]]:
        """First grant/rule letting `subject` do verb on resource in `namespace` (None = cluster-wide)."""
        for g in self.grants_for(subject):
            if namespace is None and g.scope_ns is not None:
                continue
            if namespace is not None and g.scope_ns not in (None, namespace):
                continue
            for rule in g.rules:
                if rule.get("resourceNames") and not allow_named:
                    continue
                if rule_matches(rule, verb, resource):
                    return g, rule
        return None

    def cluster_admin_grant(self, subject: Subject) -> Optional[Grant]:
        for g in self.grants_for(subject):
            if g.scope_ns is None:
                for rule in g.rules:
                    if "*" in (rule.get("verbs") or []) and "*" in (rule.get("resources") or []) and not rule.get("resourceNames"):
                        return g
        return None

    # ---- universe of subjects ----------------------------------------------------------------
    def all_subjects(self) -> List[Subject]:
        subs = set()
        for _, _, _, subjects, _ in self._bindings:
            subs |= set(subjects)
        for ns, name in self.inv.service_accounts:
            subs.add(Subject("ServiceAccount", ns, name))
        for w in self.inv.workloads:
            subs.add(Subject("ServiceAccount", w.namespace, w.service_account))
        for ns in self.inv.namespaces_in_use():
            subs.add(Subject("ServiceAccount", ns, "default"))
        return sorted(subs, key=lambda s: (s.kind, s.namespace or "", s.name))

    def bound_subjects(self, role_kind: str, role_name: str, role_ns: Optional[str]) -> List[Subject]:
        out = []
        for b, kind, bns, subjects, _ in self._bindings:
            ref = b.get("roleRef") or {}
            if ref.get("kind") != role_kind or ref.get("name") != role_name:
                continue
            if role_kind == "Role" and bns != role_ns:
                continue
            out += subjects
        return out
