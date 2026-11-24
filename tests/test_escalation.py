from conftest import LABS, by_rule
from kubesentinel import escalation
from kubesentinel.loader import load_paths
from kubesentinel.scanner import scan

LAB = None


def lab():
    global LAB
    if LAB is None:
        LAB = scan(load_paths([str(LABS)]))
    return LAB


def path(source, terminal):
    for p in lab().paths:
        if str(p.source) == source and p.terminal == terminal:
            return p
    return None


def test_ci_runner_reaches_cluster_admin_via_tiller():
    p = path("ServiceAccount dev/ci-runner", "CLUSTER_ADMIN")
    assert p and len(p.steps) == 2
    assert str(p.steps[0].to) == "ServiceAccount dev/tiller"


def test_support_bot_three_hop_chain():
    p = path("ServiceAccount dev/support-bot", "CLUSTER_ADMIN")
    assert p and len(p.steps) == 3
    assert [s.kind for s in p.steps] == ["exec", "secret", "direct"]


def test_support_bot_reaches_all_secrets_in_two_hops():
    p = path("ServiceAccount dev/support-bot", "ALL_SECRETS")
    assert p and len(p.steps) == 2


def test_alice_can_self_escalate_via_rbac_verbs():
    p = path("User alice", "CLUSTER_ADMIN")
    assert p and len(p.steps) == 1 and p.steps[0].kind == "rbac"


def test_edit_group_reaches_node_via_privileged_pod():
    p = path("Group contractors", "NODE_COMPROMISE")
    assert p and p.steps[0].kind == "node"


def test_already_admin_not_reported_as_path():
    assert path("ServiceAccount dev/tiller", "CLUSTER_ADMIN") is None


def test_psa_enforcement_removes_node_edge(scan_yaml):
    manifest = """
    apiVersion: v1
    kind: Namespace
    metadata: {{name: dev, labels: {{pod-security.kubernetes.io/enforce: {level}}}}}
    ---
    apiVersion: v1
    kind: ServiceAccount
    metadata: {{name: bot, namespace: dev}}
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {{name: r, namespace: dev}}
    rules: [{{apiGroups: [""], resources: [pods], verbs: [create]}}]
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata: {{name: rb, namespace: dev}}
    roleRef: {{apiGroup: rbac.authorization.k8s.io, kind: Role, name: r}}
    subjects: [{{kind: ServiceAccount, name: bot, namespace: dev}}]
    """
    assert by_rule(scan_yaml(manifest.format(level="privileged")), "KS-ESC-002")
    assert not by_rule(scan_yaml(manifest.format(level="baseline")), "KS-ESC-002")


def test_resource_names_restrict_secret_reads(scan_yaml):
    r = scan_yaml("""
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata: {name: one-secret}
    rules: [{apiGroups: [""], resources: [secrets], resourceNames: [only-this], verbs: [get]}]
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata: {name: b}
    roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: one-secret}
    subjects: [{kind: ServiceAccount, name: s, namespace: dev}]
    """)
    assert not by_rule(r, "KS-ESC-003")


def test_baseline_has_no_paths():
    r = scan(load_paths([str(LABS / "baseline")]))
    assert r.paths == []


def test_mermaid_output():
    m = escalation.to_mermaid(lab().paths)
    assert m.startswith("graph LR") and "CLUSTER-ADMIN" in m and "classDef term" in m


def test_paths_never_continue_through_an_already_admin_subject():
    # dev/tiller is cluster-admin: it may END a CLUSTER_ADMIN path, but node/secret paths must not pass through it.
    for p in lab().paths:
        intermediates = [str(st.to) for st in p.steps[:-1]]
        if p.terminal != "CLUSTER_ADMIN":
            assert "ServiceAccount dev/tiller" not in intermediates, p


def test_pss_baseline_on_dev_removes_all_node_paths():
    import re, shutil, tempfile
    from pathlib import Path
    tmp = Path(tempfile.mkdtemp())
    shutil.copytree(LABS / "vulnerable", tmp / "v")
    ns = tmp / "v" / "00-namespaces.yaml"
    ns.write_text(ns.read_text().replace("metadata:\n  name: dev",
                  "metadata:\n  name: dev\n  labels:\n    pod-security.kubernetes.io/enforce: baseline"))
    r = scan(load_paths([str(tmp / "v")]))
    assert not [p for p in r.paths if p.terminal == "NODE_COMPROMISE"]
    assert not any(f.rule_id == "KS-ADM-001" and f.resource == "Namespace/dev" for f in r.findings)
