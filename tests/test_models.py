import json

from winsysinfo import models


def _minimal_report() -> models.SystemReport:
    return models.SystemReport(
        schema_version=models.SCHEMA_VERSION,
        generated_at="2026-11-25 10:00:00",
        hostname="PC",
        os=models.OsInfo(name="Windows 11", release="11", build="26200", edition="Pro", architecture="64-bit"),
        cpu=None,
        memory=None,
        gpus=(),
        disks=(),
        network=models.NetworkInfo(adapters=()),
        bios=None,
        security=models.SecurityInfo(
            tpm=models.TpmInfo(present=False, version=None, status=None),
            secure_boot=None,
            secure_boot_reason="unsupported",
            defender=models.DefenderInfo(av_enabled=None, realtime_enabled=None, signature_age_days=None),
            bitlocker=models.BitLockerInfo(volume_status=None, protection=None),
        ),
        hotfixes=models.HotfixInfo(count=0, newest_date=None, ids=()),
        battery=None,
        uptime_seconds=None,
    )


def test_to_dict_contains_every_key():
    data = _minimal_report().to_dict()
    expected = {
        "schema_version", "generated_at", "hostname", "os", "cpu", "memory", "gpus", "disks",
        "network", "bios", "security", "hotfixes", "battery", "uptime_seconds", "checks",
        "health_score", "redacted", "errors",
    }
    assert expected <= set(data)
    assert data["os"]["name"] == "Windows 11"
    assert data["security"]["tpm"]["present"] is False


def test_to_dict_is_json_serialisable():
    raw = json.loads(json.dumps(_minimal_report().to_dict()))
    assert raw["schema_version"] == "1.0"
    assert raw["redacted"] is False
    assert raw["health_score"] == 100


def test_models_are_frozen():
    report = _minimal_report()
    try:
        report.hostname = "other"  # type: ignore[misc]
    except AttributeError:
        return
    raise AssertionError("SystemReport should be frozen")
