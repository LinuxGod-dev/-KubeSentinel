"""Build an Inventory of Kubernetes objects from manifest files or a live cluster (via kubectl)."""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import yaml

CLUSTER_SCOPED = {"Namespace", "ClusterRole", "ClusterRoleBinding"}
WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
LIVE_KINDS = [
    "namespaces", "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs",
    "roles", "rolebindings", "clusterroles", "clusterrolebindings",
    "serviceaccounts", "networkpolicies", "configmaps",
]


@dataclass
class Workload:
    kind: str
    namespace: str
    name: str
    spec: dict          # the PodSpec
    labels: dict
    source: str

    @property
    def ref(self) -> str:
        return f"{self.kind}/{self.namespace}/{self.name}"

    @property
    def service_account(self) -> str:
        return self.spec.get("serviceAccountName") or self.spec.get("serviceAccount") or "default"


@dataclass
class Inventory:
    workloads: List[Workload] = field(default_factory=list)
    roles: Dict[Tuple[Optional[str], str], dict] = field(default_factory=dict)      # (ns|None, name)
    role_sources: Dict[Tuple[Optional[str], str], str] = field(default_factory=dict)
    bindings: List[dict] = field(default_factory=list)                              # Role/ClusterRoleBindings
    binding_sources: Dict[int, str] = field(default_factory=dict)
    service_accounts: set = field(default_factory=set)                              # {(ns, name)}
    namespaces: Dict[str, dict] = field(default_factory=dict)
    network_policies: List[dict] = field(default_factory=list)
    configmaps: List[dict] = field(default_factory=list)
    secrets: List[dict] = field(default_factory=list)
    sources: Dict[str, str] = field(default_factory=dict)                           # "Kind/ns/name" -> file
    warnings: List[str] = field(default_factory=list)
    live: bool = False

    # -- helpers ---------------------------------------------------------------------------
    def namespaces_in_use(self) -> set:
        ns = set(self.namespaces)
        ns |= {w.namespace for w in self.workloads}
        ns |= {n for n, _ in self.service_accounts}
        ns |= {k[0] for k in self.roles if k[0]}
        return ns

    def location(self, ref: str) -> str:
        return self.sources.get(ref, "cluster")


def _meta(obj: dict) -> dict:
    return obj.get("metadata") or {}


def _ns(obj: dict) -> str:
    return _meta(obj).get("namespace") or "default"


def _pod_spec(obj: dict) -> Optional[dict]:
    kind, spec = obj.get("kind"), obj.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}:
        return (spec.get("template") or {}).get("spec")
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    return None


def _pod_labels(obj: dict) -> dict:
    if obj.get("kind") == "Pod":
        return _meta(obj).get("labels") or {}
    spec = obj.get("spec") or {}
    tpl = spec.get("template") or (spec.get("jobTemplate") or {}).get("spec", {}).get("template") or {}
    return (tpl.get("metadata") or {}).get("labels") or {}


def add_object(inv: Inventory, obj: dict, source: str, *, live: bool = False) -> None:
    """Register one Kubernetes object in the inventory."""
    if not isinstance(obj, dict) or "kind" not in obj:
        return
    kind = obj["kind"]
    name = _meta(obj).get("name", "")
    if kind == "List":
        for item in obj.get("items") or []:
            add_object(inv, item, source, live=live)
        return

    # In live mode, controller-owned pods/jobs duplicate their controller: skip them.
    if live and kind in {"Pod", "Job", "ReplicaSet"} and _meta(obj).get("ownerReferences"):
        return

    ns = None if kind in CLUSTER_SCOPED else _ns(obj)
    inv.sources[f"{kind}/{ns or ''}/{name}"] = source

    if kind in WORKLOAD_KINDS:
        spec = _pod_spec(obj)
        if spec is not None:
            inv.workloads.append(Workload(kind, ns or "default", name, spec, _pod_labels(obj), source))
            inv.sources[f"{kind}/{ns}/{name}"] = source
    elif kind in {"Role", "ClusterRole"}:
        key = (ns if kind == "Role" else None, name)
        inv.roles[key] = obj
        inv.role_sources[key] = source
    elif kind in {"RoleBinding", "ClusterRoleBinding"}:
        inv.bindings.append(obj)
        inv.binding_sources[id(obj)] = source
    elif kind == "ServiceAccount":
        inv.service_accounts.add((ns, name))
    elif kind == "Namespace":
        inv.namespaces[name] = obj
    elif kind == "NetworkPolicy":
        inv.network_policies.append(obj)
    elif kind == "ConfigMap":
        inv.configmaps.append(obj)
    elif kind == "Secret":
        inv.secrets.append(obj)


def load_paths(paths: Iterable[str]) -> Inventory:
    inv = Inventory()
    files: List[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            files += sorted(f for f in path.rglob("*") if f.suffix.lower() in {".yaml", ".yml", ".json"})
        elif path.is_file():
            files.append(path)
        else:
            inv.warnings.append(f"Path not found: {p}")
    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
            docs = list(yaml.safe_load_all(text))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            inv.warnings.append(f"Skipped {f}: could not parse ({type(exc).__name__}). "
                                "Render Helm/Kustomize first (helm template / kubectl kustomize).")
            continue
        for doc in docs:
            if doc:
                add_object(inv, doc, str(f).replace("\\", "/"))
    return inv


class KubectlError(RuntimeError):
    pass


def load_live(context: Optional[str] = None) -> Inventory:
    """Read-only snapshot of a cluster using kubectl. Secrets are intentionally NOT fetched."""
    inv = Inventory(live=True)
    base = ["kubectl"] + (["--context", context] if context else [])
    for kind in LIVE_KINDS:
        cmd = base + ["get", kind, "-o", "json"] + ([] if kind in {"namespaces", "clusterroles", "clusterrolebindings"} else ["-A"])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except FileNotFoundError as exc:
            raise KubectlError("kubectl not found on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise KubectlError(f"kubectl timed out reading {kind}") from exc
        if proc.returncode != 0:
            inv.warnings.append(f"kubectl get {kind} failed: {proc.stderr.strip()[:200]}")
            continue
        for item in json.loads(proc.stdout).get("items", []):
            add_object(inv, item, "cluster", live=True)
    inv.warnings.append("Live mode: Secret objects are not read (by design). KS-SEC-003 does not apply.")
    return inv
