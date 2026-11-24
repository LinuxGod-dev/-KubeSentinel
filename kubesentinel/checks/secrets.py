"""Exposed-secret checks (KS-SEC-*). Matched values are always masked in output."""
from __future__ import annotations

import base64
import re
from typing import List, Optional

from ..catalog import make_finding
from ..loader import Inventory
from ..models import Finding, Severity
from .workload import iter_containers

NAME_RE = re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth[_-]?key)")
VALUE_PATTERNS = {
    "AWS access key ID": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}
PLACEHOLDER_RE = re.compile(r"(?i)^(changeme|change-me|placeholder|<.*>|\$\{.*\}|\{\{.*\}\}|xxx+|none|null|true|false|)$")


def mask(value: str) -> str:
    value = str(value)
    return (value[:4] + "…" + f"({len(value)} chars)") if len(value) > 4 else "****"


def _pattern_hit(value: str) -> Optional[str]:
    for label, rx in VALUE_PATTERNS.items():
        if rx.search(value):
            return label
    return None


def run(inv: Inventory, ctx) -> List[Finding]:
    out: List[Finding] = []

    # ---- env vars in workloads ----------------------------------------------------------------
    for w in inv.workloads:
        if w.namespace in ctx.exclude_namespaces:
            continue
        hits, crit = [], False
        for c in iter_containers(w.spec):
            for env in c.get("env") or []:
                if "value" not in env:       # valueFrom (secretKeyRef etc.) is fine
                    continue
                name, value = str(env.get("name", "")), str(env.get("value", ""))
                label = _pattern_hit(value)
                if label:
                    hits.append(f"{c.get('name')}:{name} looks like {label} ({mask(value)})")
                    crit = True
                elif NAME_RE.search(name) and not PLACEHOLDER_RE.match(value):
                    hits.append(f"{c.get('name')}:{name} has a literal value ({mask(value)})")
        if hits:
            out.append(make_finding("KS-SEC-001", w.ref, "Plain-text credential(s) in env.",
                                    severity=Severity.CRITICAL if crit else Severity.HIGH,
                                    evidence=hits, location=w.source))

    # ---- ConfigMaps ------------------------------------------------------------------------------
    for cm in inv.configmaps:
        meta = cm.get("metadata") or {}
        ns, name = meta.get("namespace") or "default", meta.get("name", "?")
        if name == "kube-root-ca.crt" or ns in ctx.exclude_namespaces:
            continue
        hits, crit = [], False
        for key, value in {**(cm.get("data") or {})}.items():
            value = str(value)
            label = _pattern_hit(value)
            if label:
                hits.append(f"key '{key}' looks like {label} ({mask(value)})")
                crit = True
            elif NAME_RE.search(key) and not PLACEHOLDER_RE.match(value.strip()):
                hits.append(f"key '{key}' has a credential-like name and a literal value ({mask(value)})")
        if hits:
            ref = f"ConfigMap/{ns}/{name}"
            out.append(make_finding("KS-SEC-002", ref, "Credential-like data stored in a ConfigMap.",
                                    severity=Severity.CRITICAL if crit else Severity.HIGH,
                                    evidence=hits, location=inv.location(ref)))

    # ---- Secret objects committed to manifests ------------------------------------------------------
    for sec in inv.secrets:
        meta = sec.get("metadata") or {}
        ns, name = meta.get("namespace") or "default", meta.get("name", "?")
        stype = sec.get("type", "Opaque")
        if ns in ctx.exclude_namespaces or stype in ("kubernetes.io/service-account-token", "helm.sh/release.v1"):
            continue
        keys = sorted(set((sec.get("data") or {}).keys()) | set((sec.get("stringData") or {}).keys()))
        if not keys:
            continue
        ev = [f"keys: {', '.join(keys)}"]
        crit = False
        decoded = dict(sec.get("stringData") or {})
        for k, v in (sec.get("data") or {}).items():
            try:
                decoded[k] = base64.b64decode(str(v), validate=False).decode("utf-8", "ignore")
            except Exception:
                pass
        for k, v in decoded.items():
            label = _pattern_hit(v)
            if label:
                ev.append(f"key '{k}' decodes to {label} ({mask(v)})")
                crit = True
        ref = f"Secret/{ns}/{name}"
        out.append(make_finding("KS-SEC-003", ref,
                                "Secret values are stored in a manifest (base64 is encoding, not encryption).",
                                severity=Severity.HIGH if crit else Severity.MEDIUM, evidence=ev,
                                location=inv.location(ref)))
    return out
