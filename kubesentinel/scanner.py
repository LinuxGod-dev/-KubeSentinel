"""Orchestrates all checks into a single ScanResult."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from . import escalation
from .checks import network, rbac, secrets, workload
from .loader import Inventory
from .models import Finding, Severity
from .rbac_model import RBACModel


@dataclass
class ScanContext:
    exclude_namespaces: tuple = ()
    include_system: bool = False


@dataclass
class ScanResult:
    inventory: Inventory
    findings: List[Finding] = field(default_factory=list)
    paths: list = field(default_factory=list)

    def counts(self) -> dict:
        c = {s.name: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            c[f.severity.name] += 1
        return c

    def max_severity(self) -> Optional[Severity]:
        return max((f.severity for f in self.findings), default=None)


def scan(inv: Inventory, ctx: Optional[ScanContext] = None) -> ScanResult:
    ctx = ctx or ScanContext()
    findings: List[Finding] = []
    for module in (workload, rbac, secrets, network):
        findings += module.run(inv, ctx)
    model = RBACModel(inv)
    paths = escalation.analyze(inv, ctx, model)
    findings += escalation.to_findings(paths, inv, model)
    findings.sort(key=lambda f: (-int(f.severity), f.category, f.resource, f.rule_id))
    return ScanResult(inv, findings, paths)
