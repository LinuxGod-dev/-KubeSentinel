from conftest import by_rule, ids

CA_BINDING = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {{name: b}}
roleRef: {{apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}}
subjects: [{subject}]
"""


def test_cluster_admin_for_sa_is_critical(scan_yaml):
    r = scan_yaml(CA_BINDING.format(subject="{kind: ServiceAccount, name: ci, namespace: dev}"))
    f = by_rule(r, "KS-RBAC-001")
    assert f and f[0].severity.name == "CRITICAL"


def test_system_masters_is_ignored(scan_yaml):
    r = scan_yaml(CA_BINDING.format(subject="{kind: Group, name: 'system:masters', apiGroup: rbac.authorization.k8s.io}"))
    assert "KS-RBAC-001" not in ids(r)


def test_wildcard_role(scan_yaml):
    r = scan_yaml("""
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata: {name: god}
    rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
    """)
    assert by_rule(r, "KS-RBAC-002")[0].severity.name == "CRITICAL"


def test_exec_secrets_and_create_pods(scan_yaml):
    r = scan_yaml("""
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: r, namespace: dev}
    rules:
      - {apiGroups: [""], resources: ["pods/exec"], verbs: ["create"]}
      - {apiGroups: [""], resources: ["secrets"], verbs: ["get"]}
      - {apiGroups: [""], resources: ["pods"], verbs: ["create"]}
    """)
    assert {"KS-RBAC-004", "KS-RBAC-005", "KS-RBAC-006"} <= ids(r)


def test_default_sa_and_anonymous_bindings(scan_yaml):
    r = scan_yaml("""
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata: {name: b1, namespace: dev}
    roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: r}
    subjects: [{kind: ServiceAccount, name: default, namespace: dev}]
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata: {name: b2}
    roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: reader}
    subjects: [{kind: User, name: "system:anonymous", apiGroup: rbac.authorization.k8s.io}]
    """)
    assert "KS-RBAC-007" in ids(r)
    assert by_rule(r, "KS-RBAC-008")[0].severity.name == "CRITICAL"


def test_system_clusterroles_are_not_flagged(scan_yaml):
    r = scan_yaml("""
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata: {name: "system:thing"}
    rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
    """)
    assert "KS-RBAC-002" not in ids(r)
