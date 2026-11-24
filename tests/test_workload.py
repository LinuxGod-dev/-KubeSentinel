from conftest import by_rule, ids

POD = """
apiVersion: v1
kind: Pod
metadata: {{name: p, namespace: app}}
spec:
  {extra}
  containers:
    - name: c
      image: {image}
      {sc}
"""


def pod(extra="", image="busybox:1.36", sc=""):
    return POD.format(extra=extra, image=image, sc=sc)


def test_privileged_is_critical(scan_yaml):
    r = scan_yaml(pod(sc="securityContext: {privileged: true}"))
    f = by_rule(r, "KS-WL-001")
    assert f and f[0].severity.name == "CRITICAL"


def test_docker_socket_hostpath_is_critical(scan_yaml):
    r = scan_yaml(pod(extra="volumes: [{name: s, hostPath: {path: /var/run/docker.sock}}]"))
    f = by_rule(r, "KS-WL-003")
    assert f and f[0].severity.name == "CRITICAL"


def test_benign_hostpath_is_medium(scan_yaml):
    r = scan_yaml(pod(extra="volumes: [{name: s, hostPath: {path: /data/cache}}]"))
    assert by_rule(r, "KS-WL-003")[0].severity.name == "MEDIUM"


def test_host_pid_high(scan_yaml):
    r = scan_yaml(pod(extra="hostPID: true"))
    assert by_rule(r, "KS-WL-002")[0].severity.name == "HIGH"


def test_dangerous_capability(scan_yaml):
    r = scan_yaml(pod(sc="securityContext: {capabilities: {add: [SYS_ADMIN]}}"))
    assert "KS-WL-004" in ids(r)


def test_root_detection(scan_yaml):
    assert by_rule(scan_yaml(pod(sc="securityContext: {runAsUser: 0}")), "KS-WL-005")[0].severity.name == "HIGH"
    assert "KS-WL-005" not in ids(scan_yaml(pod(sc="securityContext: {runAsNonRoot: true}")))
    assert "KS-WL-005" not in ids(scan_yaml(pod(sc="securityContext: {runAsUser: 1000}")))


def test_pod_level_security_context_is_inherited(scan_yaml):
    r = scan_yaml(pod(extra="securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}"))
    assert "KS-WL-005" not in ids(r) and "KS-WL-011" not in ids(r)


def test_image_pinning(scan_yaml):
    assert "KS-WL-009" in ids(scan_yaml(pod(image="nginx:latest")))
    assert "KS-WL-009" in ids(scan_yaml(pod(image="nginx")))
    assert "KS-WL-009" not in ids(scan_yaml(pod(image="nginx:1.27")))
    assert "KS-WL-009" not in ids(scan_yaml(pod(image="registry.local:5000/app@sha256:" + "a" * 64)))
    assert "KS-WL-009" not in ids(scan_yaml(pod(image="registry.local:5000/app:1.2")))


def test_controller_templates_are_scanned(scan_yaml):
    r = scan_yaml("""
    apiVersion: batch/v1
    kind: CronJob
    metadata: {name: j, namespace: app}
    spec:
      schedule: "* * * * *"
      jobTemplate:
        spec:
          template:
            spec:
              containers: [{name: c, image: "x:1", securityContext: {privileged: true}}]
    """)
    assert by_rule(r, "KS-WL-001")[0].resource == "CronJob/app/j"


def test_exclude_namespace(scan_yaml):
    r = scan_yaml(pod(sc="securityContext: {privileged: true}"), exclude_namespaces=("app",))
    assert "KS-WL-001" not in ids(r)


def test_baseline_lab_is_clean():
    from conftest import LABS
    from kubesentinel.loader import load_paths
    from kubesentinel.scanner import scan
    r = scan(load_paths([str(LABS / "baseline")]))
    assert r.findings == []
