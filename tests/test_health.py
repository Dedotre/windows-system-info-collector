import dataclasses
import datetime as dt
import json
from pathlib import Path

import pytest

from winsysinfo import collect, health, models

FIXTURE = Path(__file__).parent / "fixtures" / "ps_raw.json"


@pytest.fixture(autouse=True)
def _fixed_today(monkeypatch):
    monkeypatch.setattr(health, "_today", lambda: dt.date(2026, 11, 25))


def _report() -> models.SystemReport:
    return collect.build_report(json.loads(FIXTURE.read_text(encoding="utf-8")))


def _status(report: models.SystemReport, check_id: str) -> str | None:
    for check in report.checks:
        if check.id == check_id:
            return check.status
    return None


def _evaluate(report: models.SystemReport) -> models.SystemReport:
    checks, score = health.evaluate(report)
    return dataclasses.replace(report, checks=checks, health_score=score)


def test_healthy_fixture_score_is_100():
    report = _evaluate(_report())
    assert report.health_score == 100
    assert _status(report, "disk_space") == "pass"
    assert _status(report, "tpm") == "pass"
    assert _status(report, "secure_boot") == "pass"


def test_low_disk_fails():
    report = dataclasses.replace(_report(), disks=(models.DiskInfo("C:\\", "NTFS", 1000, 30, 97.0),))
    scored = _evaluate(report)
    assert _status(scored, "disk_space") == "fail"
    assert scored.health_score == 80


def test_medium_disk_warns():
    report = dataclasses.replace(_report(), disks=(models.DiskInfo("C:\\", "NTFS", 1000, 80, 92.0),))
    scored = _evaluate(report)
    assert _status(scored, "disk_space") == "warn"
    assert scored.health_score == 92


def test_small_ram_warns_and_tiny_ram_fails():
    small = dataclasses.replace(_report(), memory=models.MemoryInfo(total_bytes=6 * 1024**3, free_bytes=0))
    assert _status(_evaluate(small), "ram") == "warn"
    tiny = dataclasses.replace(_report(), memory=models.MemoryInfo(total_bytes=2 * 1024**3, free_bytes=0))
    assert _status(_evaluate(tiny), "ram") == "fail"


def test_win11_without_tpm_fails():
    report = _report()
    security = dataclasses.replace(report.security, tpm=models.TpmInfo(present=False, version=None, status=None))
    scored = _evaluate(dataclasses.replace(report, security=security))
    assert _status(scored, "tpm") == "fail"


def test_tpm_1_2_warns():
    report = _report()
    security = dataclasses.replace(report.security, tpm=models.TpmInfo(present=True, version="1.2", status="Ready"))
    scored = _evaluate(dataclasses.replace(report, security=security))
    assert _status(scored, "tpm") == "warn"


def test_defender_disabled_fails_and_skips_realtime():
    report = _report()
    security = dataclasses.replace(
        report.security,
        defender=models.DefenderInfo(av_enabled=False, realtime_enabled=False, signature_age_days=1),
    )
    scored = _evaluate(dataclasses.replace(report, security=security))
    assert _status(scored, "defender_av") == "fail"
    assert _status(scored, "defender_realtime") is None


def test_defender_realtime_off_fails():
    report = _report()
    security = dataclasses.replace(
        report.security,
        defender=models.DefenderInfo(av_enabled=True, realtime_enabled=False, signature_age_days=1),
    )
    scored = _evaluate(dataclasses.replace(report, security=security))
    assert _status(scored, "defender_av") == "pass"
    assert _status(scored, "defender_realtime") == "fail"


def test_defender_missing_produces_no_checks():
    report = _report()
    security = dataclasses.replace(
        report.security,
        defender=models.DefenderInfo(av_enabled=None, realtime_enabled=None, signature_age_days=None),
    )
    scored = _evaluate(dataclasses.replace(report, security=security))
    assert _status(scored, "defender_av") is None
    assert _status(scored, "defender_realtime") is None


def test_stale_hotfix_warns_and_old_uptime_is_info():
    report = dataclasses.replace(
        _report(),
        hotfixes=models.HotfixInfo(2, "2020-01-01", ("KB1", "KB2")),
        uptime_seconds=90 * 86400,
    )
    scored = _evaluate(report)
    assert _status(scored, "hotfix_age") == "warn"
    assert _status(scored, "uptime") == "info"
    assert scored.health_score == 92


def test_score_never_negative():
    base = _report()
    report = dataclasses.replace(
        base,
        disks=(models.DiskInfo("C:\\", "NTFS", 1000, 1, 99.9),),
        memory=models.MemoryInfo(total_bytes=1024**3, free_bytes=0),
        security=dataclasses.replace(
            base.security,
            tpm=models.TpmInfo(present=False, version=None, status=None),
            secure_boot=False,
            defender=models.DefenderInfo(av_enabled=False, realtime_enabled=False, signature_age_days=40),
        ),
        hotfixes=models.HotfixInfo(0, "2020-01-01", ()),
    )
    assert _evaluate(report).health_score == 0


def test_secure_boot_unavailable_is_info():
    report = _report()
    security = dataclasses.replace(report.security, secure_boot=None, secure_boot_reason="Access was denied")
    scored = _evaluate(dataclasses.replace(report, security=security))
    assert _status(scored, "secure_boot") == "info"
    assert scored.health_score == 100


def test_bitlocker_off_is_info_only():
    report = _report()
    security = dataclasses.replace(report.security, bitlocker=models.BitLockerInfo("FullyDecrypted", "Off"))
    scored = _evaluate(dataclasses.replace(report, security=security))
    assert _status(scored, "bitlocker") == "info"
    assert scored.health_score == 100
