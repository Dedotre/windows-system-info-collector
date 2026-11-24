import json
from pathlib import Path

from winsysinfo import probe

FIXTURE = Path(__file__).parent / "fixtures" / "ps_raw.json"


def _fixture_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def test_parse_valid_output():
    result = probe.parse_probe_output(_fixture_text())
    assert result.error is None
    assert result.data is not None
    assert result.data["os"]["BuildNumber"] == "26200"
    assert result.data["ram"][0]["Capacity"] == 8589934592


def test_parse_strips_bom():
    result = probe.parse_probe_output("\ufeff" + _fixture_text())
    assert result.error is None


def test_parse_empty_output_is_error():
    result = probe.parse_probe_output("  \n")
    assert result.data is None
    assert result.error is not None
    assert "empty" in result.error


def test_parse_invalid_json_is_error():
    result = probe.parse_probe_output("{not json")
    assert result.error is not None
    assert "invalid JSON" in result.error


def test_parse_non_object_root_is_error():
    result = probe.parse_probe_output(json.dumps([1, 2]))
    assert result.error is not None


def test_nonzero_exit_is_error_with_stderr():
    result = probe.parse_probe_output("", returncode=1, stderr="powershell exploded")
    assert result.data is None
    assert "1" in (result.error or "")
    assert "powershell exploded" in (result.error or "")


def test_script_only_uses_cim_and_cmdlets():
    assert "wmic" not in probe.PS_SCRIPT.lower()
    assert "Get-WmiObject" not in probe.PS_SCRIPT
    assert "ConvertTo-Json" in probe.PS_SCRIPT


def test_command_round_trips_the_script():
    import base64

    command = probe.build_command()
    assert command[-2] == "-EncodedCommand"
    decoded = base64.b64decode(command[-1]).decode("utf-16-le")
    assert decoded == probe.PS_SCRIPT
