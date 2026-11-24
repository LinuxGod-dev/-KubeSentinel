import re

import yaml

from conftest import FALCO_RULES
from kubesentinel.catalog import RULES

VALID_PRIORITIES = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"}


def load():
    return yaml.safe_load(FALCO_RULES.read_text(encoding="utf-8"))


def test_rule_schema():
    rules = [d for d in load() if "rule" in d]
    assert len(rules) >= 10
    for r in rules:
        for key in ("rule", "desc", "condition", "output", "priority", "tags"):
            assert key in r, f"{r.get('rule')} missing {key}"
        assert r["priority"] in VALID_PRIORITIES
        assert "kubesentinel" in r["tags"]
        assert r["rule"].startswith("KubeSentinel ")


def test_rule_names_unique():
    names = [d["rule"] for d in load() if "rule" in d]
    assert len(names) == len(set(names))


def test_all_ks_macros_and_lists_are_defined():
    docs = load()
    defined = {d["macro"] for d in docs if "macro" in d} | {d["list"] for d in docs if "list" in d}
    for d in docs:
        text = " ".join(str(d.get(k, "")) for k in ("condition", "output"))
        for tok in set(re.findall(r"\bks_[a-z_]+\b", text)):
            assert tok in defined, f"{tok} used in {d.get('rule') or d.get('macro')} but not defined"


def test_every_catalog_detection_exists_in_rule_file():
    names = {d["rule"] for d in load() if "rule" in d}
    for r in RULES.values():
        for det in r.detection:
            assert det in names, f"{r.id} links to missing Falco rule: {det}"


def test_every_falco_rule_is_linked_from_a_finding():
    linked = {det for r in RULES.values() for det in r.detection}
    for d in load():
        if "rule" in d:
            assert d["rule"] in linked, f"{d['rule']} is not linked from any posture check"
