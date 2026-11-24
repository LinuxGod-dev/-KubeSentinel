"""RBAC escalation-path analysis (KS-ESC-*).

Builds a directed graph: subjects -> (subjects | terminal states). An edge means "this subject can
become / act as that target using only the permissions it already holds":

  create workload in ns   -> run a pod as any ServiceAccount in ns (and, if the namespace has no
                             Pod Security enforcement, as a privileged pod -> NODE_COMPROMISE)
  read secrets in ns      -> steal ServiceAccount token Secrets in ns
  pods/exec or attach     -> shell into pods and use their ServiceAccount token
  create serviceaccounts/token, impersonate, escalate/bind, nodes/proxy ...

Breadth-first search from every non-system subject finds the *shortest* chain to each terminal.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Union

from .catalog import make_finding
from .checks.network import psa_level
from .loader import Inventory
from .models import Finding
from .rbac_model import WORKLOAD_RESOURCES, RBACModel, Subject

CLUSTER_ADMIN, NODE, SECRETS = "CLUSTER_ADMIN", "NODE_COMPROMISE", "ALL_SECRETS"
TERMINAL_RULE = {CLUSTER_ADMIN: "KS-ESC-001", NODE: "KS-ESC-002", SECRETS: "KS-ESC-003"}
TERMINAL_LABEL = {CLUSTER_ADMIN: "CLUSTER-ADMIN", NODE: "NODE COMPROMISE", SECRETS: "ALL CLUSTER SECRETS"}

Node = Union[Subject, str]


@dataclass
class Edge:
    to: Node
    reason: str
    kind: str


@dataclass
class Step:
    frm: Node
    to: Node
    reason: str
    kind: str


@dataclass
class EscalationPath:
    source: Subject
    terminal: str
    steps: List[Step]


def _label(n: Node) -> str:
    return TERMINAL_LABEL.get(n, str(n)) if isinstance(n, str) else str(n)


def build_graph(inv: Inventory, model: RBACModel) -> Dict[Subject, List[Edge]]:
    subjects = model.all_subjects()
    all_ns = sorted(inv.namespaces_in_use())
    sas: Dict[str, List[Subject]] = {ns: [] for ns in all_ns}
    for s in subjects:
        if s.kind == "ServiceAccount":
            sas.setdefault(s.namespace, []).append(s)
    pod_sas: Dict[str, set] = {}
    for w in inv.workloads:
        pod_sas.setdefault(w.namespace, set()).add(Subject("ServiceAccount", w.namespace, w.service_account))
    users = [s for s in subjects if s.kind == "User"]
    groups = [s for s in subjects if s.kind == "Group"]

    graph: Dict[Subject, List[Edge]] = {s: [] for s in subjects}
    for s in subjects:
        edges = graph[s]

        g = model.cluster_admin_grant(s)
        if g:
            edges.append(Edge(CLUSTER_ADMIN, f"already holds cluster-admin-equivalent rights ({g.via})", "direct"))

        can = model.can
        if can(s, "escalate", "clusterroles") and (can(s, "update", "clusterroles") or can(s, "patch", "clusterroles")):
            edges.append(Edge(CLUSTER_ADMIN, "'escalate' + update/patch on clusterroles: edit a bound role to add wildcard rights", "rbac"))
        if can(s, "bind", "clusterroles") and can(s, "create", "clusterrolebindings"):
            edges.append(Edge(CLUSTER_ADMIN, "'bind' on clusterroles + create clusterrolebindings: bind cluster-admin to self", "rbac"))
        if can(s, "get", "nodes/proxy") or can(s, "create", "nodes/proxy"):
            edges.append(Edge(NODE, "nodes/proxy: reach the kubelet API and exec into pods on the node", "node"))
        if can(s, "get", "secrets") or can(s, "list", "secrets"):
            edges.append(Edge(SECRETS, "read Secrets cluster-wide", "secret"))

        r = can(s, "impersonate", "groups", None, allow_named=True)
        if r:
            names = r[1].get("resourceNames") or []
            if not names or "system:masters" in names:
                edges.append(Edge(CLUSTER_ADMIN, "impersonate group system:masters", "impersonate"))
        r = can(s, "impersonate", "users", None, allow_named=True)
        if r:
            names = r[1].get("resourceNames") or []
            for u in users:
                if u != s and (not names or u.name in names):
                    edges.append(Edge(u, f"impersonate {u}", "impersonate"))

        node_edge_added = False
        for ns in all_ns:
            wl = next((hit for res in WORKLOAD_RESOURCES if (hit := can(s, "create", res, ns))), None)
            if wl:
                for t in sas.get(ns, []):
                    if t != s:
                        edges.append(Edge(t, f"create a workload in '{ns}' that runs as {t.namespace}/{t.name} ({wl[0].via})", "workload"))
                if not node_edge_added and psa_level(inv, ns) == "privileged":
                    edges.append(Edge(NODE, f"create a privileged pod in '{ns}' (no Pod Security enforcement) and break out to the node", "node"))
                    node_edge_added = True
            if any(can(s, v, "secrets", ns) for v in ("get", "list")):
                for t in sas.get(ns, []):
                    if t != s:
                        edges.append(Edge(t, f"read token Secrets in '{ns}' for {t.namespace}/{t.name} (needs a long-lived token Secret)", "secret"))
            if can(s, "create", "pods/exec", ns) or can(s, "create", "pods/attach", ns):
                for t in sorted(pod_sas.get(ns, ()), key=str):
                    if t != s:
                        edges.append(Edge(t, f"exec into a pod in '{ns}' running as {t.namespace}/{t.name} and use its token", "exec"))
            if can(s, "create", "serviceaccounts/token", ns):
                for t in sas.get(ns, []):
                    if t != s:
                        edges.append(Edge(t, f"mint a token for {t.namespace}/{t.name}", "token"))
            r = can(s, "impersonate", "serviceaccounts", ns, allow_named=True)
            if r:
                names = r[1].get("resourceNames") or []
                for t in sas.get(ns, []):
                    if t != s and (not names or t.name in names):
                        edges.append(Edge(t, f"impersonate {t}", "impersonate"))
        # A subject that already holds cluster-admin subsumes every other capability: make it a sink so
        # paths *through* it report CLUSTER_ADMIN only (not redundant node/secret/SA edges).
        direct = [e for e in edges if e.kind == "direct"]
        if direct:
            graph[s] = direct
    return graph


def find_paths(graph: Dict[Subject, List[Edge]], sources: List[Subject]) -> List[EscalationPath]:
    paths: List[EscalationPath] = []
    for src in sources:
        if any(e.kind == "direct" for e in graph.get(src, [])):
            continue                                   # already admin: covered by KS-RBAC-001/002
        parents: Dict[Subject, Optional[tuple]] = {src: None}
        found: Dict[str, tuple] = {}
        queue = deque([src])
        while queue:
            node = queue.popleft()
            for e in graph.get(node, []):
                if isinstance(e.to, str):
                    found.setdefault(e.to, (node, e))
                elif e.to not in parents:
                    parents[e.to] = (node, e)
                    queue.append(e.to)
        for term, (last, edge) in found.items():
            steps = [Step(last, term, edge.reason, edge.kind)]
            n = last
            while parents[n] is not None:
                pn, pe = parents[n]
                steps.append(Step(pn, n, pe.reason, pe.kind))
                n = pn
            steps.reverse()
            paths.append(EscalationPath(src, term, steps))
    order = {CLUSTER_ADMIN: 0, SECRETS: 1, NODE: 2}
    return sorted(paths, key=lambda p: (order[p.terminal], len(p.steps), str(p.source)))


def analyze(inv: Inventory, ctx, model: Optional[RBACModel] = None) -> List[EscalationPath]:
    model = model or RBACModel(inv)
    graph = build_graph(inv, model)
    sources = [s for s in graph
               if (ctx.include_system or (not s.is_system and not (s.kind == "ServiceAccount" and s.namespace == "kube-system")))
               and not (s.kind == "ServiceAccount" and s.namespace in ctx.exclude_namespaces)]
    return find_paths(graph, sources)


def to_findings(paths: List[EscalationPath], inv: Inventory, model: RBACModel) -> List[Finding]:
    findings = []
    for p in paths:
        loc = "cluster"
        for b, _, _, subjects, _ in model._bindings:
            if p.source in subjects:
                loc = inv.binding_sources.get(id(b), "cluster")
                break
        chain = [_label(p.source)] + [_label(s.to) for s in p.steps]
        evidence = [f"{i}. {_label(s.frm)}  --[{s.reason}]-->  {_label(s.to)}" for i, s in enumerate(p.steps, 1)]
        findings.append(make_finding(
            TERMINAL_RULE[p.terminal], str(p.source),
            f"{p.source} can reach {_label(p.terminal)} in {len(p.steps)} hop(s): " + " → ".join(chain),
            evidence=evidence, location=loc))
    return findings


def to_mermaid(paths: List[EscalationPath]) -> str:
    ids: Dict[Node, str] = {}

    def nid(n: Node) -> str:
        return ids.setdefault(n, f"n{len(ids) + 1}")

    def esc(t: str, limit: int = 70) -> str:
        t = t.replace('"', "'").replace("|", "/")
        return t if len(t) <= limit else t[: limit - 1] + "…"

    edges, seen = [], set()
    for p in paths:
        for s in p.steps:
            key = (s.frm, s.to)
            if key in seen:
                continue
            seen.add(key)
            edges.append(f'    {nid(s.frm)} -->|"{esc(s.reason)}"| {nid(s.to)}')
    lines = ["graph LR"]
    for n, i in ids.items():
        lines.append(f'    {i}["{esc(_label(n), 60)}"]')
    lines += edges
    lines.append("    classDef term fill:#b71c1c,stroke:#7f0000,color:#fff;")
    terms = [i for n, i in ids.items() if isinstance(n, str)]
    if terms:
        lines.append("    class " + ",".join(terms) + " term;")
    return "\n".join(lines) + "\n"
