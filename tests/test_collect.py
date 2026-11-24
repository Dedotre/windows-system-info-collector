import json
from pathlib import Path

from winsysinfo import collect, models

FIXTURE = Path(__file__).parent / "fixtures" / "ps_raw.json"


def _raw() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_builds_full_report_from_fixture():
    report = collect.build_report(_raw())
    assert report.os.name == "Windows 11"
    assert report.os.build == "26200"
    assert report.cpu is not None and report.cpu.cores == 8
    assert report.memory is not None
    assert report.memory.total_bytes == 16777216 * 1024
    assert len(report.memory.modules) == 2
    assert report.disks[0].mount == "C:\\"
    assert 87 < report.disks[0].percent_used < 89
    assert report.network.adapters[0].ipv4 == ("192.168.0.42",)
    assert report.network.adapters[0].gateways == ("192.168.0.1",)
    assert report.bios is not None and report.bios.board == "ROG STRIX B550-F"
    assert report.hotfixes.count == 2
    assert report.hotfixes.newest_date == "2026-10-14"
    assert report.security.tpm.status == "Ready"
    assert report.uptime_seconds is None or report.uptime_seconds >= 0


def test_single_object_arrays_are_normalised():
    raw = {"ram": {"Capacity": 1024, "Speed": 1, "Manufacturer": "X", "PartNumber": "Y"}}
    report = collect.build_report(raw)
    assert report.memory is not None
    assert len(report.memory.modules) == 1


def test_tpm_present_without_details():
    raw = {"tpm": None, "tpm_registry_present": True, "tpm_reason": "Access denied"}
    report = collect.build_report(raw)
    assert report.security.tpm.present is True
    assert report.security.tpm.status is None
    assert report.security.tpm.reason == "Access denied"


def test_defender_and_bitlocker_null():
    report = collect.build_report({})
    assert report.security.defender.av_enabled is None
    assert report.security.bitlocker.protection is None


def test_disk_fallback_used_when_probe_has_none(monkeypatch):
    monkeypatch.setattr(collect, "_fallback_disks", lambda: (models.DiskInfo("D:\\", "NTFS", 10, 5, 50.0),))
    report = collect.build_report({"disks": []})
    assert report.disks[0].mount == "D:\\"


def test_errors_are_preserved():
    report = collect.build_report({}, errors=["probe: boom"])
    assert report.errors == ("probe: boom",)


def test_uptime_invalid_date_is_none():
    report = collect.build_report({"os": {"LastBootUpTime": "not-a-date"}})
    assert report.uptime_seconds is None
