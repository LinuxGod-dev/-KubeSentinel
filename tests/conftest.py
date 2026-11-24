import textwrap
from pathlib import Path

import pytest

from kubesentinel.loader import load_paths
from kubesentinel.scanner import ScanContext, scan

ROOT = Path(__file__).resolve().parents[1]
LABS = ROOT / "labs"
FALCO_RULES = ROOT / "rules" / "falco" / "kubesentinel_rules.yaml"


@pytest.fixture
def scan_yaml(tmp_path):
    """scan_yaml(\"\"\"<manifests>\"\"\", exclude=...) -> ScanResult"""
    def _scan(text: str, **ctx):
        f = tmp_path / "m.yaml"
        f.write_text(textwrap.dedent(text), encoding="utf-8")
        return scan(load_paths([str(f)]), ScanContext(**ctx))
    return _scan


def ids(result):
    return {f.rule_id for f in result.findings}


def by_rule(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]
