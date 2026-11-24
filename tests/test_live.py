"""Live mode is tested against a fake kubectl that replays the lab manifests as API JSON."""
import json
import subprocess
from pathlib import Path

import yaml

from conftest import LABS
from kubesentinel import loader
from kubesentinel.scanner import scan

PLURAL = {"Namespace": "namespaces", "Pod": "pods", "Deployment": "deployments", "DaemonSet": "daemonsets",
          "StatefulSet": "statefulsets", "Job": "jobs", "CronJob": "cronjobs", "Role": "roles",
          "RoleBinding": "rolebindings", "ClusterRole": "clusterroles", "ClusterRoleBinding": "clusterrolebindings",
          "ServiceAccount": "serviceaccounts", "NetworkPolicy": "networkpolicies", "ConfigMap": "configmaps"}


def fake_kubectl(monkeypatch, extra_pods=()):
    by_kind = {}
    for f in sorted(Path(LABS / "vulnerable").glob("*.yaml")):
        for doc in yaml.safe_load_all(f.read_text()):
            if doc and doc["kind"] in PLURAL:      # Secrets deliberately absent: tool must never ask for them
                by_kind.setdefault(PLURAL[doc["kind"]], []).append(doc)
    by_kind.setdefault("pods", []).extend(extra_pods)
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        kind = cmd[cmd.index("get") + 1]
        return subprocess.CompletedProcess(cmd, 0, json.dumps({"items": by_kind.get(kind, [])}), "")

    monkeypatch.setattr(loader.subprocess, "run", run)
    return calls


def test_live_mode_finds_same_escalation_paths(monkeypatch):
    calls = fake_kubectl(monkeypatch)
    inv = loader.load_live(context="kind-kubesentinel")
    res = scan(inv)
    assert inv.live
    assert any(str(p.source) == "ServiceAccount dev/ci-runner" and p.terminal == "CLUSTER_ADMIN" for p in res.paths)
    assert all(c[:3] == ["kubectl", "--context", "kind-kubesentinel"] for c in calls)


def test_live_mode_never_reads_secrets_and_is_read_only(monkeypatch):
    calls = fake_kubectl(monkeypatch)
    loader.load_live()
    verbs = {c[c.index("get") if "get" in c else 0] for c in calls}
    assert verbs == {"get"}
    assert not any("secrets" in c for c in calls)
    inv = loader.load_live()
    assert any("Secret objects are not read" in w for w in inv.warnings)
    assert "KS-SEC-003" not in {f.rule_id for f in scan(inv).findings}


def test_live_mode_skips_controller_owned_pods(monkeypatch):
    owned = {"kind": "Pod", "metadata": {"name": "payments-api-abc", "namespace": "dev",
                                          "ownerReferences": [{"kind": "ReplicaSet", "name": "payments-api-abc"}]},
             "spec": {"containers": [{"name": "c", "image": "x:1", "securityContext": {"privileged": True}}]}}
    fake_kubectl(monkeypatch, extra_pods=[owned])
    inv = loader.load_live()
    assert "Pod/dev/payments-api-abc" not in {w.ref for w in inv.workloads}


def test_missing_kubectl_gives_clean_error(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError()
    monkeypatch.setattr(loader.subprocess, "run", boom)
    import pytest
    with pytest.raises(loader.KubectlError):
        loader.load_live()
