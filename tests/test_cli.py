import json
from pathlib import Path

import pytest

from winsysinfo import cli, probe

FIXTURE = Path(__file__).parent / "fixtures" / "ps_raw.json"


def _data() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture
def fake_probe(monkeypatch):
    monkeypatch.setattr(probe, "run_probe", lambda timeout=60: probe.ProbeResult(_data(), None))


def test_writes_json_report(tmp_path, fake_probe, capsys):
    code = cli.main(["--format", "json", "--out", str(tmp_path)])
    assert code == 0
    files = list(tmp_path.glob("system_info_report_*.json"))
    assert len(files) == 1
    parsed = json.loads(files[0].read_text(encoding="utf-8"))
    assert parsed["schema_version"] == "1.0"
    assert parsed["redacted"] is True
    assert parsed["os"]["name"] == "Windows 11"
    assert '"schema_version"' in capsys.readouterr().out


def test_include_sensitive_keeps_hostname(tmp_path, fake_probe):
    cli.main(["--format", "json", "--out", str(tmp_path), "--include-sensitive"])
    parsed = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert parsed["redacted"] is False
    assert parsed["hostname"] != "REDACTED-HOST"


def test_multiple_formats_write_multiple_files(tmp_path, fake_probe):
    code = cli.main(["--format", "text,json,md,html", "--out", str(tmp_path), "-q"])
    assert code == 0
    assert {path.suffix for path in tmp_path.iterdir()} == {".txt", ".json", ".md", ".html"}


def test_probe_failure_degrades_and_exits_one(tmp_path, monkeypatch):
    monkeypatch.setattr(probe, "run_probe", lambda timeout=60: probe.ProbeResult(None, "probe: boom"))
    code = cli.main(["--format", "json", "--out", str(tmp_path), "-q"])
    assert code == 1
    parsed = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert "probe: boom" in parsed["errors"]


def test_unknown_format_exits_two(tmp_path, fake_probe, capsys):
    assert cli.main(["--format", "pdf", "--out", str(tmp_path)]) == 2
    assert "pdf" in capsys.readouterr().err


def test_non_windows_exits_two(tmp_path, fake_probe, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "platform", "linux")
    assert cli.main(["--out", str(tmp_path)]) == 2
    assert "Windows" in capsys.readouterr().err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    assert "2.0.0" in capsys.readouterr().out
