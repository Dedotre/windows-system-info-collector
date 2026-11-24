import dataclasses
import datetime as dt
import json
from pathlib import Path

import pytest

from winsysinfo import collect, health, models, redact, render

FIXTURE = Path(__file__).parent / "fixtures" / "ps_raw.json"


@pytest.fixture(autouse=True)
def _fixed_today(monkeypatch):
    monkeypatch.setattr(health, "_today", lambda: dt.date(2026, 11, 25))


def _report(redacted: bool = False) -> models.SystemReport:
    report = collect.build_report(json.loads(FIXTURE.read_text(encoding="utf-8")))
    checks, score = health.evaluate(report)
    return dataclasses.replace(report, checks=checks, health_score=score, redacted=redacted)


def test_extensions_cover_all_formats():
    assert render.EXTENSIONS == {"text": "txt", "json": "json", "md": "md", "html": "html"}


def test_text_contains_health_and_sections():
    out = render.render(_report(), "text")
    assert "Health:" in out
    assert "100/100" in out
    assert "--- DISK ---" in out
    assert "C:\\ [NTFS]" in out
    assert "AMD Ryzen 7 5800X" in out
    assert "KB5063878" in out


def test_text_marks_redaction():
    out = render.render(redact.apply(_report()), "text")
    assert "redacted" in out.lower()
    assert "REDACTED-HOST" in out


def test_json_roundtrip_matches_model():
    out = render.render(_report(), "json")
    parsed = json.loads(out)
    assert parsed == json.loads(json.dumps(_report().to_dict()))
    assert parsed["schema_version"] == "1.0"


def test_markdown_has_checks_table():
    out = render.render(_report(), "md")
    assert "## Checks" in out
    assert "| Check | Status |" in out
    assert "| Disk space | pass |" in out


def test_html_is_self_contained_and_escapes():
    report = dataclasses.replace(_report(), hostname="<script>alert(1)</script>")
    out = render.render(report, "html")
    assert out.startswith("<!DOCTYPE html>")
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
    assert "<style>" in out
    assert "100/100" in out


def test_unknown_format_raises():
    try:
        render.render(_report(), "pdf")
    except ValueError as exc:
        assert "pdf" in str(exc)
        return
    raise AssertionError("expected ValueError")
