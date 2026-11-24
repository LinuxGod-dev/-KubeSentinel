from conftest import by_rule, ids

DEPLOY = """
apiVersion: apps/v1
kind: Deployment
metadata: {{name: d, namespace: app}}
spec:
  selector: {{matchLabels: {{a: b}}}}
  template:
    metadata: {{labels: {{a: b}}}}
    spec:
      containers:
        - name: c
          image: x:1
          env: {env}
"""


def test_literal_password_env_flagged_and_masked(scan_yaml):
    r = scan_yaml(DEPLOY.format(env="[{name: DB_PASSWORD, value: 'SuperSecretValue123'}]"))
    f = by_rule(r, "KS-SEC-001")
    assert f and f[0].severity.name == "HIGH"
    assert "SuperSecretValue123" not in " ".join(f[0].evidence)   # masked


def test_secret_key_ref_is_fine(scan_yaml):
    env = "[{name: DB_PASSWORD, valueFrom: {secretKeyRef: {name: s, key: k}}}]"
    assert "KS-SEC-001" not in ids(scan_yaml(DEPLOY.format(env=env)))


def test_aws_key_pattern_is_critical_even_with_innocent_name(scan_yaml):
    r = scan_yaml(DEPLOY.format(env="[{name: BACKUP_ID, value: AKIAIOSFODNN7EXAMPLE}]"))
    assert by_rule(r, "KS-SEC-001")[0].severity.name == "CRITICAL"


def test_placeholder_not_flagged(scan_yaml):
    assert "KS-SEC-001" not in ids(scan_yaml(DEPLOY.format(env="[{name: API_TOKEN, value: changeme}]")))


def test_configmap_and_secret_manifest(scan_yaml):
    r = scan_yaml("""
    apiVersion: v1
    kind: ConfigMap
    metadata: {name: c, namespace: app}
    data: {db_password: hunter2, theme: dark}
    ---
    apiVersion: v1
    kind: Secret
    metadata: {name: s, namespace: app}
    data: {password: aHVudGVyMg==}
    """)
    assert {"KS-SEC-002", "KS-SEC-003"} <= ids(r)


NS = """
apiVersion: v1
kind: Namespace
metadata: {name: app, labels: {pod-security.kubernetes.io/enforce: baseline}}
---
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: app}
spec: {containers: [{name: c, image: "x:1"}]}
"""


def test_no_networkpolicy(scan_yaml):
    r = scan_yaml(NS)
    assert "KS-NET-001" in ids(r) and "KS-ADM-001" not in ids(r)


def test_default_deny_recognised(scan_yaml):
    r = scan_yaml(NS + """
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny, namespace: app}
spec: {podSelector: {}, policyTypes: [Ingress]}
""")
    assert not ({"KS-NET-001", "KS-NET-002"} & ids(r))


def test_allow_all_ingress_is_not_default_deny(scan_yaml):
    r = scan_yaml(NS + """
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: open, namespace: app}
spec: {podSelector: {}, policyTypes: [Ingress], ingress: [{}]}
""")
    assert "KS-NET-002" in ids(r)


def test_psa_missing_label(scan_yaml):
    r = scan_yaml("apiVersion: v1\nkind: Namespace\nmetadata: {name: loose}\n")
    assert "KS-ADM-001" in ids(r)
