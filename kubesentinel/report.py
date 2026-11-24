"""Reporters: console (rich), JSON, SARIF 2.1.0 and a self-contained HTML page."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import List

from rich import box
from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from . import __version__
from .catalog import RULES
from .escalation import TERMINAL_LABEL, _label
from .models import Finding, Severity
from .scanner import ScanResult

SEV_STYLE = {Severity.CRITICAL: "bold white on red", Severity.HIGH: "bold red", Severity.MEDIUM: "yellow",
             Severity.LOW: "cyan", Severity.INFO: "dim"}


# ---------------------------------------------------------------------------------------------- console
def print_console(result: ScanResult, console: Console, *, verbose: bool = False, min_severity: Severity = Severity.LOW) -> None:
    inv = result.inventory
    console.print(f"[bold]KubeSentinel {__version__}[/bold]  "
                  f"{'live cluster' if inv.live else 'manifests'} · {len(inv.workloads)} workloads · "
                  f"{len(inv.roles)} roles · {len(inv.bindings)} bindings · {len(inv.namespaces_in_use())} namespaces")
    for w in inv.warnings:
        console.print(f"[yellow]warning:[/yellow] {w}")

    counts = result.counts()
    summary = Table(box=box.SIMPLE_HEAD, show_edge=False)
    for s in sorted(Severity, reverse=True):
        summary.add_column(s.name, justify="right", style=SEV_STYLE[s])
    summary.add_row(*[str(counts[s.name]) for s in sorted(Severity, reverse=True)])
    console.print(summary)

    shown: List[Finding] = [f for f in result.findings if f.severity >= min_severity and f.category != "escalation"]
    table = Table(title="Findings", box=box.SIMPLE_HEAD, header_style="bold", show_lines=False)
    for col in ("Severity", "Rule", "Resource", "Title"):
        table.add_column(col, overflow="fold")
    for f in shown:
        table.add_row(f"[{SEV_STYLE[f.severity]}]{f.severity.name}[/]", f.rule_id, f.resource, f.title)
    console.print(table)

    if verbose:
        for f in shown:
            console.print(f"\n[bold]{f.rule_id}[/bold] {f.resource}\n  {f.message}")
            for e in f.evidence:
                console.print(f"    · {e}")
            console.print(f"  [green]fix:[/green] {f.remediation}")
            if f.detection:
                console.print(f"  [magenta]runtime detection:[/magenta] {', '.join(f.detection)}")

    if result.paths:
        console.print("\n[bold]RBAC escalation paths[/bold] (shortest chain per source and target)")
        for term in ("CLUSTER_ADMIN", "ALL_SECRETS", "NODE_COMPROMISE"):
            group = [p for p in result.paths if p.terminal == term]
            if not group:
                continue
            tree = Tree(f"[bold red]→ {TERMINAL_LABEL[term]}[/bold red]  ({len(group)} source(s))")
            for p in group:
                branch = tree.add(f"[bold]{p.source}[/bold]  [dim]{len(p.steps)} hop(s)[/dim]")
                for s in p.steps:
                    branch.add(f"{_label(s.frm)} [dim]──[/dim] {s.reason} [dim]──▶[/dim] [bold]{_label(s.to)}[/bold]")
            console.print(tree)


# ------------------------------------------------------------------------------------------------ JSON
def to_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": {"name": "kubesentinel", "version": __version__},
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": result.counts(),
        "findings": [f.to_dict() for f in result.findings],
        "escalation_paths": [{
            "source": str(p.source), "terminal": p.terminal,
            "steps": [{"from": _label(s.frm), "to": _label(s.to), "reason": s.reason, "kind": s.kind} for s in p.steps],
        } for p in result.paths],
        "warnings": result.inventory.warnings,
    }, indent=2)


# ----------------------------------------------------------------------------------------------- SARIF
_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
          Severity.LOW: "note", Severity.INFO: "note"}
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                      Severity.LOW: "3.0", Severity.INFO: "1.0"}


def to_sarif(result: ScanResult) -> str:
    used = sorted({f.rule_id for f in result.findings})
    rules = []
    for rid in used:
        r = RULES[rid]
        rules.append({
            "id": r.id, "name": r.title.replace(" ", ""),
            "shortDescription": {"text": r.title},
            "help": {"text": r.remediation},
            "defaultConfiguration": {"level": _LEVEL[r.severity]},
            "properties": {"security-severity": _SECURITY_SEVERITY[r.severity],
                           "tags": ["security", "kubernetes", r.category] + ([r.mitre] if r.mitre else [])},
        })
    results = []
    for f in result.findings:
        uri = f.location if f.location != "cluster" else "kubernetes-cluster"
        text = f.message + ("\n" + "\n".join(f.evidence) if f.evidence else "")
        results.append({
            "ruleId": f.rule_id, "level": _LEVEL[f.severity], "message": {"text": text},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}},
                           "logicalLocations": [{"name": f.resource}]}],
            "properties": {"security-severity": _SECURITY_SEVERITY[f.severity]},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "KubeSentinel", "version": __version__,
                                       "informationUri": "https://github.com/LinuxGod-dev/kubesentinel",
                                       "rules": rules}}, "results": results}],
    }, indent=2)


# ------------------------------------------------------------------------------------------------ HTML
_CSS = """
:root{--bg:#fff;--fg:#1b1f23;--muted:#586069;--card:#f6f8fa;--bd:#d0d7de;--crit:#b71c1c;--high:#d84315;--med:#b26a00;--low:#0b6e99}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--card:#161b22;--bd:#30363d;--crit:#ff6b6b;--high:#ff8a65;--med:#ffb74d;--low:#4fc3f7}}
body{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;max-width:1100px;margin:auto}
h1{margin:0 0 4px}h2{margin-top:32px}.muted{color:var(--muted)}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:10px 18px;min-width:90px}
.card b{display:block;font-size:22px}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid var(--bd);padding:6px 8px;text-align:left;vertical-align:top}
.CRITICAL{color:var(--crit);font-weight:700}.HIGH{color:var(--high);font-weight:700}.MEDIUM{color:var(--med);font-weight:600}.LOW{color:var(--low)}
details{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:8px 12px;margin:8px 0}summary{cursor:pointer}
code{font-family:ui-monospace,monospace;font-size:12.5px}.wrap{overflow-x:auto}
"""


def to_html(result: ScanResult) -> str:
    e = html.escape
    counts = result.counts()
    cards = "".join(f'<div class="card"><span class="{k}">{k}</span><b>{v}</b></div>' for k, v in counts.items())
    rows = "".join(
        f'<tr><td class="{f.severity.name}">{f.severity.name}</td><td>{e(f.rule_id)}</td><td><code>{e(f.resource)}</code></td>'
        f'<td>{e(f.title)}<br><span class="muted">{e(f.message)}</span></td></tr>'
        for f in result.findings if f.category != "escalation")
    paths = ""
    for p in result.paths:
        steps = "".join(f"<li>{e(_label(s.frm))} — <i>{e(s.reason)}</i> → <b>{e(_label(s.to))}</b></li>" for s in p.steps)
        paths += f"<details><summary><b>{e(str(p.source))}</b> → <span class=\"CRITICAL\">{e(TERMINAL_LABEL[p.terminal])}</span> ({len(p.steps)} hop(s))</summary><ol>{steps}</ol></details>"
    detail = ""
    for f in result.findings:
        if f.category == "escalation":
            continue
        ev = "".join(f"<li><code>{e(x)}</code></li>" for x in f.evidence)
        detail += (f"<details><summary><span class=\"{f.severity.name}\">{f.severity.name}</span> {e(f.rule_id)} — {e(f.resource)}</summary>"
                   f"<p>{e(f.message)}</p><ul>{ev}</ul><p><b>Fix:</b> {e(f.remediation)}</p>"
                   + (f"<p><b>Runtime detection:</b> {e(', '.join(f.detection))}</p>" if f.detection else "")
                   + (f"<p class=\"muted\">CIS {e(f.cis)} · MITRE {e(f.mitre)}</p>" if f.cis or f.mitre else "") + "</details>")
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>KubeSentinel report</title><style>{_CSS}</style></head><body>"
            f"<h1>KubeSentinel report</h1><div class=\"muted\">v{__version__} · generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}</div>"
            f"<div class=\"cards\">{cards}</div>"
            f"<h2>RBAC escalation paths</h2>{paths or '<p class=\"muted\">None found.</p>'}"
            f"<h2>Findings</h2><div class=\"wrap\"><table><tr><th>Severity</th><th>Rule</th><th>Resource</th><th>Detail</th></tr>{rows}</table></div>"
            f"<h2>Details and remediation</h2>{detail}</body></html>")
