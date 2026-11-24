import json

from conftest import LABS
from kubesentinel.cli import main


def run(capsys, *args):
    code = main(list(args))
    return code, capsys.readouterr().out


def test_scan_vulnerable_lab_passes_without_gate(capsys):
    code, out = run(capsys, "scan", str(LABS / "vulnerable"))
    assert code == 0 and "KS-WL-001" in out and "escalation paths" in out


def test_fail_on_gate(capsys):
    assert run(capsys, "scan", str(LABS / "vulnerable"), "--fail-on", "high", "--quiet")[0] == 1
    assert run(capsys, "scan", str(LABS / "baseline"), "--fail-on", "low", "--quiet")[0] == 0


def test_reports_written(tmp_path, capsys):
    j, s, h, m = (tmp_path / n for n in ("r.json", "r.sarif", "r.html", "g.mmd"))
    code, _ = run(capsys, "scan", str(LABS / "vulnerable"), "--quiet", "--json", str(j), "--sarif", str(s),
                  "--html", str(h), "--mermaid", str(m))
    assert code == 0
    data = json.loads(j.read_text())
    assert data["summary"]["CRITICAL"] > 0 and data["escalation_paths"]
    sarif = json.loads(s.read_text())
    assert sarif["version"] == "2.1.0"
    run0 = sarif["runs"][0]
    assert run0["results"] and run0["tool"]["driver"]["rules"]
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in run0["results"])
    assert "<title>KubeSentinel report</title>" in h.read_text(encoding="utf-8")
    assert m.read_text().startswith("graph LR")


def test_secret_values_never_appear_in_reports(tmp_path, capsys):
    j = tmp_path / "r.json"
    run(capsys, "scan", str(LABS / "vulnerable"), "--quiet", "--json", str(j))
    blob = j.read_text()
    assert "Sup3rS3cretPassw0rd!" not in blob and "hunter2" not in blob and "AKIAIOSFODNN7EXAMPLE" not in blob


def test_bad_arguments(capsys, tmp_path):
    assert run(capsys, "scan")[0] == 2
    assert run(capsys, "scan", str(tmp_path / "missing"))[0] == 2


def test_rules_listing(capsys):
    code, out = run(capsys, "rules")
    assert code == 0 and "KS-ESC-001" in out
