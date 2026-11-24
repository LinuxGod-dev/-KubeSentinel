"""Pod / workload hardening checks (KS-WL-*)."""
from __future__ import annotations

from typing import Iterator, List

from ..catalog import make_finding
from ..loader import Inventory, Workload
from ..models import Finding, Severity

DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
                  "DAC_READ_SEARCH", "DAC_OVERRIDE", "BPF", "SYS_BOOT", "MKNOD"}
SENSITIVE_HOST_PATHS = ("/", "/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
                        "/var/run/containerd/containerd.sock", "/var/run/crio/crio.sock", "/etc",
                        "/proc", "/sys", "/root", "/var/lib/kubelet", "/etc/kubernetes")


def iter_containers(spec: dict) -> Iterator[dict]:
    for key in ("containers", "initContainers", "ephemeralContainers"):
        for c in spec.get(key) or []:
            yield c


def _sc(obj: dict) -> dict:
    return obj.get("securityContext") or {}


def _effective(container: dict, pod_spec: dict, key: str):
    """Container-level securityContext wins over pod-level."""
    c = _sc(container).get(key)
    return c if c is not None else _sc(pod_spec).get(key)


def _is_sensitive_host_path(path: str) -> bool:
    p = path.rstrip("/") or "/"
    return any(p == s or (s != "/" and p.startswith(s + "/")) for s in SENSITIVE_HOST_PATHS)


def _image_unpinned(image: str) -> bool:
    if "@sha256:" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.endswith(":latest")


def check_workload(w: Workload) -> List[Finding]:
    out: List[Finding] = []
    spec, loc, res = w.spec, "", w.ref
    loc = w.source
    containers = list(iter_containers(spec))

    def add(rule, msg, **kw):
        out.append(make_finding(rule, res, msg, location=loc, **kw))

    # KS-WL-001 privileged
    priv = [c.get("name", "?") for c in containers if _sc(c).get("privileged") is True]
    if priv:
        add("KS-WL-001", f"Container(s) run privileged: {', '.join(priv)}. A privileged container can trivially escape to the node.")

    # KS-WL-002 host namespaces
    flags = [f for f in ("hostPID", "hostIPC", "hostNetwork") if spec.get(f) is True]
    if flags:
        sev = Severity.HIGH if "hostPID" in flags else Severity.MEDIUM
        add("KS-WL-002", f"Pod shares host namespace(s): {', '.join(flags)}.", severity=sev)

    # KS-WL-003 hostPath
    hp = [(v.get("name"), v["hostPath"].get("path", "")) for v in spec.get("volumes") or [] if v.get("hostPath")]
    if hp:
        sensitive = [(n, p) for n, p in hp if _is_sensitive_host_path(p)]
        sev = Severity.CRITICAL if sensitive else Severity.MEDIUM
        add("KS-WL-003", "hostPath volume(s): " + ", ".join(f"{n}={p}" for n, p in hp)
            + (" (includes sensitive host path / container runtime socket)" if sensitive else ""), severity=sev)

    # KS-WL-004 capabilities
    capmap = {}
    for c in containers:
        added = {str(x).upper() for x in (_sc(c).get("capabilities") or {}).get("add") or []}
        bad = added & DANGEROUS_CAPS
        if bad:
            capmap[c.get("name", "?")] = sorted(bad)
    if capmap:
        add("KS-WL-004", "Dangerous capabilities added: " + "; ".join(f"{k}: {','.join(v)}" for k, v in capmap.items()))

    # KS-WL-005 root
    roots, maybe = [], []
    for c in containers:
        if _sc(c).get("privileged") is True:
            continue
        uid = _effective(c, spec, "runAsUser")
        nonroot = _effective(c, spec, "runAsNonRoot")
        if uid == 0:
            roots.append(c.get("name", "?"))
        elif nonroot is True or (isinstance(uid, int) and uid > 0):
            continue
        else:
            maybe.append(c.get("name", "?"))
    if roots:
        add("KS-WL-005", f"Container(s) explicitly run as UID 0: {', '.join(roots)}.", severity=Severity.HIGH)
    if maybe:
        add("KS-WL-005", f"Container(s) do not enforce non-root (no runAsNonRoot/runAsUser): {', '.join(maybe)}.")

    # KS-WL-006 allowPrivilegeEscalation
    ape = [c.get("name", "?") for c in containers if _sc(c).get("allowPrivilegeEscalation") is not False]
    if ape:
        add("KS-WL-006", f"allowPrivilegeEscalation is not false for: {', '.join(ape)}.")

    # KS-WL-007 read-only rootfs
    rw = [c.get("name", "?") for c in containers if _sc(c).get("readOnlyRootFilesystem") is not True]
    if rw:
        add("KS-WL-007", f"Writable root filesystem for: {', '.join(rw)}.")

    # KS-WL-008 limits
    nolimit = [c.get("name", "?") for c in containers
               if not ((c.get("resources") or {}).get("limits") or {}).get("memory")
               or not ((c.get("resources") or {}).get("limits") or {}).get("cpu")]
    if nolimit:
        add("KS-WL-008", f"Missing cpu and/or memory limits for: {', '.join(nolimit)}.")

    # KS-WL-009 image pinning
    unpinned = [f"{c.get('name', '?')}={c.get('image', '')}" for c in containers if _image_unpinned(c.get("image", ""))]
    if unpinned:
        add("KS-WL-009", "Unpinned image(s): " + ", ".join(unpinned))

    # KS-WL-010 default SA token
    if w.service_account == "default" and spec.get("automountServiceAccountToken") is not False:
        add("KS-WL-010", "Uses the 'default' ServiceAccount with its API token auto-mounted.")

    # KS-WL-011 seccomp
    noseccomp = []
    for c in containers:
        prof = (_effective(c, spec, "seccompProfile") or {}).get("type")
        if prof not in ("RuntimeDefault", "Localhost"):
            noseccomp.append(c.get("name", "?"))
    if noseccomp:
        add("KS-WL-011", f"No seccomp profile (RuntimeDefault) for: {', '.join(noseccomp)}.")
    return out


def run(inv: Inventory, ctx) -> List[Finding]:
    findings: List[Finding] = []
    for w in inv.workloads:
        if w.namespace in ctx.exclude_namespaces:
            continue
        findings += check_workload(w)
    return findings
