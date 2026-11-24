import dataclasses
import json
from pathlib import Path

from winsysinfo import collect, redact

FIXTURE = Path(__file__).parent / "fixtures" / "ps_raw.json"


def _report():
    return collect.build_report(json.loads(FIXTURE.read_text(encoding="utf-8")))


def test_redacts_identity_fields():
    out = redact.apply(_report())
    assert out.redacted is True
    assert out.hostname == "REDACTED-HOST"
    assert out.bios is not None and out.bios.serial == "REDACTED-SERIAL"
    adapter = out.network.adapters[0]
    assert adapter.mac == "XX:XX:XX:XX:XX:XX"
    assert adapter.ipv4 == ("192.168.0.0",)
    assert adapter.gateways == ("192.168.0.1",)


def test_keeps_hardware_and_patch_facts():
    out = redact.apply(_report())
    assert out.cpu is not None and "Ryzen" in out.cpu.name
    assert out.hotfixes.ids == ("KB5063878", "KB5062660")
    assert out.memory is not None and out.memory.modules


def test_original_report_untouched():
    original = _report()
    redact.apply(original)
    assert original.hostname != "REDACTED-HOST"
    assert original.redacted is False


def test_empty_mac_is_not_faked():
    report = _report()
    adapter = dataclasses.replace(report.network.adapters[0], mac="")
    network = dataclasses.replace(report.network, adapters=(adapter,))
    out = redact.apply(dataclasses.replace(report, network=network))
    assert out.network.adapters[0].mac == ""


def test_ipv6_is_ignored_by_redaction():
    out = redact.apply(_report())
    assert all(":" not in ip for ip in out.network.adapters[0].ipv4)
