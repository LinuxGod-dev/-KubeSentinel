"""Command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__, escalation
from .catalog import RULES
from .loader import KubectlError, load_live, load_paths
from .models import Severity
from .report import print_console, to_html, to_json, to_sarif
from .scanner import ScanContext, scan


def _write(path: str, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="kubesentinel", description="Kubernetes security posture + RBAC escalation-path scanner")
    ap.add_argument("--version", action="version", version=f"kubesentinel {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="scan manifests (PATH...) or a live cluster (--live)")
    sc.add_argument("paths", nargs="*", help="manifest files or directories (YAML/JSON)")
    sc.add_argument("--live", action="store_true", help="read the current kubectl context instead of files (read-only)")
    sc.add_argument("--context", help="kubectl context to use with --live")
    sc.add_argument("--exclude-namespace", action="append", default=[], metavar="NS", help="skip a namespace (repeatable)")
    sc.add_argument("--include-system", action="store_true", help="include system:* and kube-system identities as path sources")
    sc.add_argument("--min-severity", default="low", choices=[s.name.lower() for s in Severity], help="minimum severity to display")
    sc.add_argument("--fail-on", default="none", choices=["none"] + [s.name.lower() for s in Severity if s > Severity.INFO],
                    help="exit 1 if any finding is at or above this severity (CI gate)")
    sc.add_argument("-v", "--verbose", action="store_true", help="show messages, evidence and remediation")
    sc.add_argument("--json", metavar="FILE")
    sc.add_argument("--sarif", metavar="FILE")
    sc.add_argument("--html", metavar="FILE")
    sc.add_argument("--mermaid", metavar="FILE", help="write the escalation graph as a Mermaid diagram")
    sc.add_argument("--quiet", action="store_true", help="no console output")

    sub.add_parser("rules", help="list all checks and their linked Falco detections")
    return ap


def cmd_rules(console: Console) -> int:
    t = Table(title="KubeSentinel checks", header_style="bold")
    for col in ("ID", "Severity", "Title", "MITRE", "Linked Falco rules"):
        t.add_column(col, overflow="fold")
    for r in RULES.values():
        t.add_row(r.id, r.severity.name, r.title, r.mitre or "-", "\n".join(r.detection) or "-")
    console.print(t)
    return 0


def cmd_scan(args, console: Console) -> int:
    if args.live == bool(args.paths):
        console.print("[red]error:[/red] give manifest paths OR --live (not both, not neither)")
        return 2
    try:
        inv = load_live(args.context) if args.live else load_paths(args.paths)
    except KubectlError as exc:
        console.print(f"[red]error:[/red] {exc}")
        return 2
    if not args.live and not (inv.workloads or inv.roles or inv.bindings or inv.namespaces or inv.configmaps or inv.secrets):
        console.print("[red]error:[/red] no Kubernetes objects found at the given path(s)")
        for w in inv.warnings:
            console.print(f"  {w}")
        return 2

    result = scan(inv, ScanContext(tuple(args.exclude_namespace), args.include_system))
    if not args.quiet:
        print_console(result, console, verbose=args.verbose, min_severity=Severity.parse(args.min_severity))
    if args.json:
        _write(args.json, to_json(result))
    if args.sarif:
        _write(args.sarif, to_sarif(result))
    if args.html:
        _write(args.html, to_html(result))
    if args.mermaid:
        _write(args.mermaid, escalation.to_mermaid(result.paths))
    for flag, path in (("JSON", args.json), ("SARIF", args.sarif), ("HTML", args.html), ("Mermaid", args.mermaid)):
        if path and not args.quiet:
            console.print(f"[green]wrote[/green] {flag}: {path}")

    if args.fail_on != "none":
        worst = result.max_severity()
        if worst is not None and worst >= Severity.parse(args.fail_on):
            return 1
    return 0


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):          # Windows consoles/pipes may default to a legacy codepage
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    console = Console(highlight=False)
    if args.cmd == "rules":
        return cmd_rules(console)
    return cmd_scan(args, console)


if __name__ == "__main__":
    sys.exit(main())
