# winsysinfo v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the Windows system info collector as a typed, tested, zero-dependency CLI that gathers facts via one batched CIM probe, scores system health, redacts sensitive data by default, and renders text/JSON/Markdown/HTML.

**Architecture:** A `winsysinfo/` package: `probe` makes exactly one `powershell.exe` call that returns JSON; `collect` turns that JSON (plus stdlib facts) into frozen dataclasses in `models`; `health` derives checks + a score; `redact` masks PII; `render/*` produces four formats; `cli` wires it together. No runtime dependencies.

**Tech Stack:** Python ≥3.11 (stdlib only at runtime), PowerShell 5.1/CIM, pytest, ruff, mypy, GitHub Actions (`windows-latest`).

**Spec:** `docs/superpowers/specs/2026-11-25-winsysinfo-v2-design.md`

## Global Constraints

- Windows only: non-Windows runs exit `2` with a message on stderr.
- Zero runtime dependencies; dev extras only: `pytest>=8`, `pytest-cov>=5`, `ruff>=0.6`, `mypy>=1.11`.
- No bare `except:` anywhere. Catch specific exceptions.
- No parsing of human-readable command output. All facts come from CIM JSON or stdlib.
- All public functions fully annotated (mypy `disallow_untyped_defs`).
- Files are UTF-8, LF, 120-column limit (ruff).
- Never log or persist serials/hostname/MAC/IP unless `--include-sensitive` was passed.
- Commit after every task; branch `v2-rebuild`.

---

### Task 1: Scaffold package and byte formatting

**Files:**
- Create: `pyproject.toml`
- Create: `winsysinfo/__init__.py`
- Create: `winsysinfo/units.py`
- Create: `tests/test_units.py`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `winsysinfo.units.format_bytes(value: int) -> str`; `winsysinfo.units.percent_used(total: int, free: int) -> float`; `winsysinfo.__version__ = "2.0.0"`.

- [ ] **Step 1: Write the failing test**

`tests/test_units.py`:
```python
from winsysinfo.units import format_bytes, percent_used


def test_format_bytes_zero_and_negative():
    assert format_bytes(0) == "0B"
    assert format_bytes(-5) == "0B"


def test_format_bytes_boundaries():
    assert format_bytes(1023) == "1023B"
    assert format_bytes(1024) == "1.0KB"
    assert format_bytes(1536) == "1.5KB"
    assert format_bytes(1024**3) == "1.0GB"


def test_format_bytes_large_values():
    assert format_bytes(int(1024**4 * 2.5)) == "2.5TB"
    assert format_bytes(1024**5) == "1.0PB"


def test_percent_used():
    assert percent_used(100, 25) == 75.0
    assert percent_used(0, 0) == 0.0
    assert percent_used(3, 3) == 0.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_units.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'winsysinfo'`.

- [ ] **Step 3: Write minimal implementation**

`pyproject.toml`:
```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "winsysinfo"
version = "2.0.0"
description = "Windows system information collector with health checks and privacy-safe reports"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8", "pytest-cov>=5", "ruff>=0.6", "mypy>=1.11"]

[project.scripts]
winsysinfo = "winsysinfo.cli:main"

[tool.setuptools]
packages = ["winsysinfo", "winsysinfo.render"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q"

[tool.ruff]
line-length = 120
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM"]

[tool.mypy]
python_version = "3.11"
disallow_untyped_defs = true
warn_unused_ignores = true
warn_return_any = true
packages = ["winsysinfo"]

[tool.coverage.run]
source = ["winsysinfo"]
```

`winsysinfo/__init__.py`:
```python
"""Windows system information collector."""

__version__ = "2.0.0"
```

`winsysinfo/units.py`:
```python
"""Human-readable byte and percentage formatting."""

from __future__ import annotations

_AND_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def format_bytes(value: int) -> str:
    if value <= 0:
        return "0B"
    size = float(value)
    unit = _AND_UNITS[0]
    for unit in _AND_UNITS:
        if size < 1024 or unit == _AND_UNITS[-1]:
            break
        size /= 1024
    if unit == "B":
        return f"{int(size)}B"
    return f"{size:.1f}{unit}"


def percent_used(total: int, free: int) -> float:
    if total <= 0:
        return 0.0
    return round((total - free) / total * 100, 1)
```

`.gitignore` (replace whole file):
```gitignore
# Generated reports
system_info_report_*.txt
system_info_report_*.json
system_info_report_*.md
system_info_report_*.html
reports/
smoke/

# Python
__pycache__/
*.py[cod]
.venv/
*.egg-info/
dist/
build/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/

# Misc
*.log
temp/
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `python -m pytest tests/test_units.py -q`
Expected: `4 passed`.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml .gitignore winsysinfo/__init__.py winsysinfo/units.py tests/test_units.py
git commit -m "feat: scaffold winsysinfo package with byte formatting"
```

---

### Task 2: Data model

**Files:**
- Create: `winsysinfo/models.py`
- Create: `tests/test_models.py`

**Interfaces:**
- Produces: all report dataclasses and `SCHEMA_VERSION = "1.0"`; `SystemReport.to_dict() -> dict[str, Any]`. Field names exactly as below — every later task depends on them.

- [ ] **Step 1: Write the failing test**

`tests/test_models.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_models.py -q`
Expected: FAIL — `ImportError: cannot import name 'models'`.

- [ ] **Step 3: Write minimal implementation**

`winsysinfo/models.py`:
```python
"""Immutable report data model. Field names are the JSON schema."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class OsInfo:
    name: str
    release: str
    build: str
    edition: str
    architecture: str
    install_date: str | None = None


@dataclass(frozen=True)
class CpuInfo:
    name: str
    cores: int
    logical: int
    max_mhz: int


@dataclass(frozen=True)
class RamModule:
    capacity_bytes: int
    speed_mhz: int
    manufacturer: str
    part_number: str


@dataclass(frozen=True)
class MemoryInfo:
    total_bytes: int
    free_bytes: int
    modules: tuple[RamModule, ...] = ()


@dataclass(frozen=True)
class GpuInfo:
    name: str
    vram_bytes: int
    driver: str


@dataclass(frozen=True)
class DiskInfo:
    mount: str
    filesystem: str
    total_bytes: int
    free_bytes: int
    percent_used: float


@dataclass(frozen=True)
class NetworkAdapter:
    name: str
    ipv4: tuple[str, ...]
    gateways: tuple[str, ...]
    mac: str
    dhcp: bool


@dataclass(frozen=True)
class NetworkInfo:
    adapters: tuple[NetworkAdapter, ...]


@dataclass(frozen=True)
class BiosInfo:
    vendor: str
    board: str
    version: str
    release_date: str | None
    serial: str


@dataclass(frozen=True)
class TpmInfo:
    present: bool
    version: str | None
    status: str | None
    reason: str | None = None


@dataclass(frozen=True)
class DefenderInfo:
    av_enabled: bool | None
    realtime_enabled: bool | None
    signature_age_days: int | None
    reason: str | None = None


@dataclass(frozen=True)
class BitLockerInfo:
    volume_status: str | None
    protection: str | None
    reason: str | None = None


@dataclass(frozen=True)
class SecurityInfo:
    tpm: TpmInfo
    secure_boot: bool | None
    secure_boot_reason: str | None
    defender: DefenderInfo
    bitlocker: BitLockerInfo


@dataclass(frozen=True)
class HotfixInfo:
    count: int
    newest_date: str | None
    ids: tuple[str, ...]


@dataclass(frozen=True)
class BatteryInfo:
    percent: int
    charging: bool


@dataclass(frozen=True)
class Check:
    id: str
    status: str
    title: str
    detail: str
    fix: str


@dataclass(frozen=True)
class SystemReport:
    schema_version: str
    generated_at: str
    hostname: str
    os: OsInfo
    cpu: CpuInfo | None
    memory: MemoryInfo | None
    gpus: tuple[GpuInfo, ...]
    disks: tuple[DiskInfo, ...]
    network: NetworkInfo
    bios: BiosInfo | None
    security: SecurityInfo
    hotfixes: HotfixInfo
    battery: BatteryInfo | None
    uptime_seconds: int | None
    checks: tuple[Check, ...] = ()
    health_score: int = 100
    redacted: bool = False
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `python -m pytest tests/test_models.py -q`
Expected: `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add winsysinfo/models.py tests/test_models.py
git commit -m "feat: add frozen report data model"
```

---

### Task 3: PowerShell probe with pure parser

**Files:**
- Create: `winsysinfo/probe.py`
- Create: `tests/fixtures/ps_raw.json`
- Create: `tests/test_probe.py`

**Interfaces:**
- Produces: `probe.ProbeResult(data: dict[str, Any] | None, error: str | None)`; `probe.parse_probe_output(stdout: str, returncode: int = 0, stderr: str = "") -> ProbeResult`; `probe.run_probe(timeout: int = 60) -> ProbeResult`. The probe emits keys `os, cpu, ram, gpu, disks, net, bios, board, hotfixes, battery, tpm, tpm_registry_present, tpm_reason, secure_boot, secure_boot_reason, defender, defender_reason, bitlocker, bitlocker_reason` — Task 4 reads exactly these.

- [ ] **Step 1: Write the fixture**

`tests/fixtures/ps_raw.json`:
```json
{
  "os": {
    "Caption": "Microsoft Windows 11 Pro",
    "Version": "10.0.26200",
    "BuildNumber": "26200",
    "OSArchitecture": "64-bit",
    "TotalVisibleMemorySize": 16777216,
    "FreePhysicalMemory": 8388608,
    "InstallDate": "2025-03-01",
    "LastBootUpTime": "2026-11-20T08:00:00+04:00"
  },
  "cpu": {"Name": "AMD Ryzen 7 5800X 8-Core Processor", "NumberOfCores": 8, "NumberOfLogicalProcessors": 16, "MaxClockSpeed": 3800},
  "ram": [
    {"Capacity": 8589934592, "Speed": 3200, "Manufacturer": "Corsair", "PartNumber": "CMK16GX4M2B3200C16"},
    {"Capacity": 8589934592, "Speed": 3200, "Manufacturer": "Corsair", "PartNumber": "CMK16GX4M2B3200C16"}
  ],
  "gpu": [{"Name": "NVIDIA GeForce RTX 3070", "AdapterRAM": 8589934592, "DriverVersion": "31.0.15.3623"}],
  "disks": [{"DeviceID": "C:", "FileSystem": "NTFS", "Size": 998000000000, "FreeSpace": 120000000000}],
  "net": [
    {
      "Description": "Intel(R) Wi-Fi 6 AX200",
      "IPAddress": ["192.168.0.42", "fe80::1"],
      "DefaultIPGateway": ["192.168.0.1"],
      "MACAddress": "AA:BB:CC:DD:EE:FF",
      "DHCPEnabled": true
    }
  ],
  "bios": {"Manufacturer": "American Megatrends Inc.", "SMBIOSBIOSVersion": "1.2.3", "SerialNumber": "SN-BIOS-123", "ReleaseDate": "2024-05-01"},
  "board": {"Manufacturer": "ASUSTeK COMPUTER INC.", "Product": "ROG STRIX B550-F"},
  "tpm": {"SpecVersion": "2.0", "ManufacturerVersion": "7.63", "IsEnabled_InitialValue": true, "IsActivated_InitialValue": true},
  "tpm_registry_present": true,
  "tpm_reason": null,
  "secure_boot": true,
  "secure_boot_reason": null,
  "defender": {"av": true, "realtime": true, "signature_age_days": 1},
  "defender_reason": null,
  "bitlocker": {"status": "FullyDecrypted", "protection": "Off"},
  "bitlocker_reason": null,
  "hotfixes": [
    {"HotFixID": "KB5063878", "InstalledOn": "2026-10-14"},
    {"HotFixID": "KB5062660", "InstalledOn": "2026-09-10"}
  ],
  "battery": null
}
```

- [ ] **Step 2: Write the failing test**

`tests/test_probe.py`:
```python
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m pytest tests/test_probe.py -q`
Expected: FAIL — `ImportError`.

- [ ] **Step 4: Write minimal implementation**

`winsysinfo/probe.py`:
```python
"""One batched PowerShell CIM call. No human-readable output is ever parsed."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$tpm = $null; $tpmReason = $null
try {
  $tpm = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop |
    Select-Object SpecVersion, ManufacturerVersion, IsEnabled_InitialValue, IsActivated_InitialValue
} catch { $tpmReason = $_.Exception.Message }
$tpmRegistry = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TPM'

$secureBoot = $null; $secureBootReason = $null
try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop }
catch { $secureBootReason = $_.Exception.Message }

$defender = $null; $defenderReason = $null
try {
  $d = Get-MpComputerStatus -ErrorAction Stop
  $defender = [pscustomobject]@{
    av = $d.AntivirusEnabled
    realtime = $d.RealTimeProtectionEnabled
    signature_age_days = $d.AntivirusSignatureAge
  }
} catch { $defenderReason = $_.Exception.Message }

$bitlocker = $null; $bitlockerReason = $null
try {
  $b = Get-BitLockerVolume -MountPoint ($env:SystemDrive + '\') -ErrorAction Stop
  $bitlocker = [pscustomobject]@{ status = "$($b.VolumeStatus)"; protection = "$($b.ProtectionStatus)" }
} catch { $bitlockerReason = $_.Exception.Message }

$os = Get-CimInstance Win32_OperatingSystem | Select-Object -First 1 -Property Caption, Version, BuildNumber,
  OSArchitecture, TotalVisibleMemorySize, FreePhysicalMemory,
  @{n='InstallDate';e={ try { $_.InstallDate.ToString('yyyy-MM-dd') } catch { $null } }},
  @{n='LastBootUpTime';e={ try { $_.LastBootUpTime.ToString('o') } catch { $null } }}
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 -Property Name, NumberOfCores,
  NumberOfLogicalProcessors, MaxClockSpeed
$ram = @(Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity, Speed, Manufacturer, PartNumber)
$gpu = @(Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM, DriverVersion)
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID, FileSystem, Size, FreeSpace)
$nets = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
  Select-Object Description, IPAddress, DefaultIPGateway, MACAddress, DHCPEnabled)
$bios = Get-CimInstance Win32_BIOS | Select-Object -First 1 -Property Manufacturer, SMBIOSBIOSVersion, SerialNumber,
  @{n='ReleaseDate';e={ try { $_.ReleaseDate.ToString('yyyy-MM-dd') } catch { $null } }}
$board = Get-CimInstance Win32_BaseBoard | Select-Object -First 1 -Property Manufacturer, Product
$fixes = @(Get-CimInstance Win32_QuickFixEngineering | Select-Object HotFixID,
  @{n='InstalledOn';e={ try { $_.InstalledOn.ToString('yyyy-MM-dd') } catch { "$($_.InstalledOn)" } }})
$battery = Get-CimInstance Win32_Battery | Select-Object -First 1 -Property EstimatedChargeRemaining, BatteryStatus

[pscustomobject]@{
  os = $os; cpu = $cpu; ram = $ram; gpu = $gpu; disks = $disks; net = $nets
  bios = $bios; board = $board; hotfixes = $fixes; battery = $battery
  tpm = $tpm; tpm_registry_present = $tpmRegistry; tpm_reason = $tpmReason
  secure_boot = $secureBoot; secure_boot_reason = $secureBootReason
  defender = $defender; defender_reason = $defenderReason
  bitlocker = $bitlocker; bitlocker_reason = $bitlockerReason
} | ConvertTo-Json -Depth 6 -Compress
"""

_CMD = ("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-")


@dataclass(frozen=True)
class ProbeResult:
    data: dict[str, Any] | None
    error: str | None


def parse_probe_output(stdout: str, returncode: int = 0, stderr: str = "") -> ProbeResult:
    if returncode != 0:
        detail = " ".join(stderr.split())[:300]
        return ProbeResult(None, f"probe exited {returncode}: {detail or 'no stderr'}")
    raw = stdout.lstrip("\ufeff").strip()
    if not raw:
        return ProbeResult(None, "probe: empty output")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return ProbeResult(None, f"probe: invalid JSON ({exc})")
    if not isinstance(data, dict):
        return ProbeResult(None, "probe: unexpected JSON root")
    return ProbeResult(data, None)


def run_probe(timeout: int = 60) -> ProbeResult:
    try:
        proc = subprocess.run(
            _CMD,
            input=PS_SCRIPT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return ProbeResult(None, f"probe: timed out after {timeout}s")
    except OSError as exc:
        return ProbeResult(None, f"probe: {exc}")
    return parse_probe_output(proc.stdout, proc.returncode, proc.stderr)
```

- [ ] **Step 5: Run tests and verify they pass**

Run: `python -m pytest tests/test_probe.py -q`
Expected: `7 passed`.

- [ ] **Step 6: Commit**

```bash
git add winsysinfo/probe.py tests/test_probe.py tests/fixtures/ps_raw.json
git commit -m "feat: add single-shot CIM probe and JSON parser"
```

---

### Task 4: Map probe data to the report model

**Files:**
- Create: `winsysinfo/collect.py`
- Create: `tests/test_collect.py`

**Interfaces:**
- Consumes: `models.*`, `units.*`, probe keys from Task 3.
- Produces: `collect.build_report(raw: dict[str, Any], errors: tuple[str, ...] = ()) -> models.SystemReport`.

- [ ] **Step 1: Write the failing test**

`tests/test_collect.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_collect.py -q`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Write minimal implementation**

`winsysinfo/collect.py`:
```python
"""Turn probe JSON plus stdlib facts into a SystemReport. Pure, no I/O."""

from __future__ import annotations

import ctypes
import contextlib
import datetime as dt
import platform
import socket
from typing import Any, Iterable

from winsysinfo import models, units


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _number(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _os_info(raw: dict[str, Any]) -> models.OsInfo:
    data = raw.get("os") or {}
    fallback_build = platform.version().split(".")[-1] if platform.version() else ""
    build = _text(data.get("BuildNumber"), fallback_build)
    major = _number(build)
    if major >= 22000:
        name = "Windows 11"
    elif major >= 10240:
        name = "Windows 10"
    else:
        name = _text(data.get("Caption"), platform.system())
    edition = platform.win32_edition() if hasattr(platform, "win32_edition") else ""
    arch = _text(data.get("OSArchitecture"), platform.architecture()[0])
    release = platform.release()
    return models.OsInfo(
        name=name,
        release=release,
        build=build,
        edition=_text(edition, "Unknown"),
        architecture=arch,
        install_date=_text(data.get("InstallDate")) or None,
    )


def _cpu_info(raw: dict[str, Any]) -> models.CpuInfo | None:
    data = raw.get("cpu")
    if not isinstance(data, dict):
        return None
    return models.CpuInfo(
        name=_text(data.get("Name"), "Unknown CPU"),
        cores=_number(data.get("NumberOfCores")),
        logical=_number(data.get("NumberOfLogicalProcessors")),
        max_mhz=_number(data.get("MaxClockSpeed")),
    )


def _memory_info(raw: dict[str, Any]) -> models.MemoryInfo:
    os_data = raw.get("os") or {}
    modules = tuple(
        models.RamModule(
            capacity_bytes=_number(item.get("Capacity")),
            speed_mhz=_number(item.get("Speed")),
            manufacturer=_text(item.get("Manufacturer"), "Unknown"),
            part_number=_text(item.get("PartNumber"), "Unknown"),
        )
        for item in _as_list(raw.get("ram"))
        if isinstance(item, dict)
    )
    return models.MemoryInfo(
        total_bytes=_number(os_data.get("TotalVisibleMemorySize")) * 1024,
        free_bytes=_number(os_data.get("FreePhysicalMemory")) * 1024,
        modules=modules,
    )


def _gpus(raw: dict[str, Any]) -> tuple[models.GpuInfo, ...]:
    return tuple(
        models.GpuInfo(
            name=_text(item.get("Name"), "Unknown GPU"),
            vram_bytes=_number(item.get("AdapterRAM")),
            driver=_text(item.get("DriverVersion"), "Unknown"),
        )
        for item in _as_list(raw.get("gpu"))
        if isinstance(item, dict)
    )


def _disk_infos(raw: dict[str, Any]) -> tuple[models.DiskInfo, ...]:
    disks = []
    for item in _as_list(raw.get("disks")):
        if not isinstance(item, dict):
            continue
        total = _number(item.get("Size"))
        free = _number(item.get("FreeSpace"))
        mount = _text(item.get("DeviceID"), "?")
        if not mount.endswith("\\"):
            mount += "\\"
        disks.append(
            models.DiskInfo(
                mount=mount,
                filesystem=_text(item.get("FileSystem"), "Unknown"),
                total_bytes=total,
                free_bytes=free,
                percent_used=units.percent_used(total, free),
            )
        )
    return tuple(disks)


def _fallback_disks() -> tuple[models.DiskInfo, ...]:
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    buffer = ctypes.create_unicode_buffer(1024)
    if not kernel32.GetLogicalDriveStringsW(1024, buffer):
        return ()
    disks = []
    for drive in buffer.value.split("\x00"):
        if not drive:
            continue
        total = ctypes.c_ulonglong(0)
        free = ctypes.c_ulonglong(0)
        if not kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p(drive), None, ctypes.pointer(total), ctypes.pointer(free)):
            continue
        fs_buffer = ctypes.create_unicode_buffer(256)
        kernel32.GetVolumeInformationW(ctypes.c_wchar_p(drive), None, 0, None, None, None, fs_buffer, 256)
        disks.append(
            models.DiskInfo(
                mount=drive,
                filesystem=fs_buffer.value or "Unknown",
                total_bytes=total.value,
                free_bytes=free.value,
                percent_used=units.percent_used(total.value, free.value),
            )
        )
    return tuple(disks)


def _fallback_adapter() -> models.NetworkAdapter:
    ip = "127.0.0.1"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with contextlib.suppress(OSError):
            sock.connect(("10.255.255.255", 1))
            ip = sock.getsockname()[0]
    finally:
        sock.close()
    return models.NetworkAdapter(name="Primary", ipv4=(ip,), gateways=(), mac="", dhcp=False)


def _network_info(raw: dict[str, Any]) -> models.NetworkInfo:
    adapters = []
    for item in _as_list(raw.get("net")):
        if not isinstance(item, dict):
            continue
        ipv4 = tuple(ip for ip in (_text(v) for v in _as_list(item.get("IPAddress"))) if ip and ":" not in ip)
        gateways = tuple(g for g in (_text(v) for v in _as_list(item.get("DefaultIPGateway"))) if g and ":" not in g)
        adapters.append(
            models.NetworkAdapter(
                name=_text(item.get("Description"), "Adapter"),
                ipv4=ipv4,
                gateways=gateways,
                mac=_text(item.get("MACAddress"), "N/A"),
                dhcp=item.get("DHCPEnabled") is True,
            )
        )
    if not adapters:
        adapters.append(_fallback_adapter())
    return models.NetworkInfo(adapters=tuple(adapters))


def _bios_info(raw: dict[str, Any]) -> models.BiosInfo | None:
    bios = raw.get("bios")
    if not isinstance(bios, dict):
        return None
    board = raw.get("board") if isinstance(raw.get("board"), dict) else {}
    return models.BiosInfo(
        vendor=_text(bios.get("Manufacturer"), "Unknown"),
        board=_text(board.get("Product"), "Unknown"),
        version=_text(bios.get("SMBIOSBIOSVersion"), "Unknown"),
        release_date=_text(bios.get("ReleaseDate")) or None,
        serial=_text(bios.get("SerialNumber"), "N/A"),
    )


def _security_info(raw: dict[str, Any]) -> models.SecurityInfo:
    tpm_raw = raw.get("tpm")
    registry_present = raw.get("tpm_registry_present") is True
    if isinstance(tpm_raw, dict):
        ready = tpm_raw.get("IsEnabled_InitialValue") is True and tpm_raw.get("IsActivated_InitialValue") is True
        tpm = models.TpmInfo(
            present=True,
            version=_text(tpm_raw.get("SpecVersion")) or None,
            status="Ready" if ready else "Not Ready",
        )
    else:
        tpm = models.TpmInfo(
            present=registry_present,
            version=None,
            status=None,
            reason=_text(raw.get("tpm_reason")) or None,
        )

    defender_raw = raw.get("defender")
    if isinstance(defender_raw, dict):
        defender = models.DefenderInfo(
            av_enabled=_optional_bool(defender_raw.get("av")),
            realtime_enabled=_optional_bool(defender_raw.get("realtime")),
            signature_age_days=_optional_int(defender_raw.get("signature_age_days")),
        )
    else:
        defender = models.DefenderInfo(
            av_enabled=None,
            realtime_enabled=None,
            signature_age_days=None,
            reason=_text(raw.get("defender_reason")) or None,
        )

    bitlocker_raw = raw.get("bitlocker")
    if isinstance(bitlocker_raw, dict):
        bitlocker = models.BitLockerInfo(
            volume_status=_text(bitlocker_raw.get("status")) or None,
            protection=_text(bitlocker_raw.get("protection")) or None,
        )
    else:
        bitlocker = models.BitLockerInfo(
            volume_status=None,
            protection=None,
            reason=_text(raw.get("bitlocker_reason")) or None,
        )

    secure_boot = _optional_bool(raw.get("secure_boot"))
    return models.SecurityInfo(
        tpm=tpm,
        secure_boot=secure_boot,
        secure_boot_reason=_text(raw.get("secure_boot_reason")) or None,
        defender=defender,
        bitlocker=bitlocker,
    )


def _hotfix_info(raw: dict[str, Any]) -> models.HotfixInfo:
    ids = []
    dates = []
    for item in _as_list(raw.get("hotfixes")):
        if not isinstance(item, dict):
            continue
        hotfix_id = _text(item.get("HotFixID"))
        if not hotfix_id:
            continue
        ids.append(hotfix_id)
        installed = _text(item.get("InstalledOn"))
        if len(installed) == 10:
            dates.append(installed)
    return models.HotfixInfo(count=len(ids), newest_date=max(dates) if dates else None, ids=tuple(ids))


def _battery_info(raw: dict[str, Any]) -> models.BatteryInfo | None:
    item = raw.get("battery")
    if not isinstance(item, dict):
        return None
    percent = _optional_int(item.get("EstimatedChargeRemaining"))
    if percent is None:
        return None
    return models.BatteryInfo(percent=percent, charging=item.get("BatteryStatus") in (2, 6, 7, 8, 9))


def _uptime_seconds(raw: dict[str, Any]) -> int | None:
    stamp = _text((raw.get("os") or {}).get("LastBootUpTime"))
    if not stamp:
        return None
    try:
        boot = dt.datetime.fromisoformat(stamp)
    except ValueError:
        return None
    if boot.tzinfo is None:
        boot = boot.astimezone()
    delta = dt.datetime.now(dt.timezone.utc) - boot.astimezone(dt.timezone.utc)
    return max(0, int(delta.total_seconds()))


def build_report(raw: dict[str, Any], errors: Iterable[str] = ()) -> models.SystemReport:
    disks = _disk_infos(raw) or _fallback_disks()
    return models.SystemReport(
        schema_version=models.SCHEMA_VERSION,
        generated_at=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        hostname=socket.gethostname(),
        os=_os_info(raw),
        cpu=_cpu_info(raw),
        memory=_memory_info(raw),
        gpus=_gpus(raw),
        disks=disks,
        network=_network_info(raw),
        bios=_bios_info(raw),
        security=_security_info(raw),
        hotfixes=_hotfix_info(raw),
        battery=_battery_info(raw),
        uptime_seconds=_uptime_seconds(raw),
        errors=tuple(errors),
    )
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `python -m pytest tests/test_collect.py -q`
Expected: `7 passed`.

- [ ] **Step 5: Commit**

```bash
git add winsysinfo/collect.py tests/test_collect.py
git commit -m "feat: map CIM probe data into report model"
```

---

### Task 5: Health rules and score

**Files:**
- Create: `winsysinfo/health.py`
- Create: `tests/test_health.py`

**Interfaces:**
- Consumes: `models.SystemReport`, `models.Check`, `units.format_bytes`.
- Produces: `health.evaluate(report: models.SystemReport) -> tuple[tuple[models.Check, ...], int]`. Rule ids in order: `disk_space, ram, tpm, secure_boot, defender_av, defender_realtime, defender_signatures, hotfix_age, bitlocker, uptime`.

- [ ] **Step 1: Write the failing test**

`tests/test_health.py`:
```python
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
    report = _report()
    report = dataclasses.replace(
        report, disks=(models.DiskInfo("C:\\", "NTFS", 1000, 30, 97.0),)
    )
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


def test_defender_disabled_fails_and_realtime_off_fails():
    report = _report()
    security = dataclasses.replace(
        report.security,
        defender=models.DefenderInfo(av_enabled=False, realtime_enabled=False, signature_age_days=1),
    )
    scored = _evaluate(dataclasses.replace(report, security=security))
    assert _status(scored, "defender_av") == "fail"
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
    report = dataclasses.replace(_report(), hotfixes=models.HotfixInfo(2, "2020-01-01", ("KB1", "KB2")), uptime_seconds=90 * 86400)
    scored = _evaluate(report)
    assert _status(scored, "hotfix_age") == "warn"
    assert _status(scored, "uptime") == "info"
    assert scored.health_score == 92


def test_score_never_negative():
    report = dataclasses.replace(
        _report(),
        disks=(models.DiskInfo("C:\\", "NTFS", 1000, 1, 99.9),),
        memory=models.MemoryInfo(total_bytes=1024**3, free_bytes=0),
        security=dataclasses.replace(
            _report().security,
            tpm=models.TpmInfo(present=False, version=None, status=None),
            secure_boot=False,
            defender=models.DefenderInfo(av_enabled=False, realtime_enabled=False, signature_age_days=40),
        ),
        hotfixes=models.HotfixInfo(0, "2020-01-01", ()),
    )
    assert _evaluate(report).health_score == 0


def test_bitlocker_off_is_info_only():
    report = _report()
    security = dataclasses.replace(report.security, bitlocker=models.BitLockerInfo("FullyDecrypted", "Off"))
    scored = _evaluate(dataclasses.replace(report, security=security))
    assert _status(scored, "bitlocker") == "info"
    assert scored.health_score == 100
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_health.py -q`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Write minimal implementation**

`winsysinfo/health.py`:
```python
"""Rule-based health checks. Each rule emits at most one Check."""

from __future__ import annotations

import datetime as dt

from winsysinfo import models, units

GB = 1024**3
DEDUCTIONS = {"fail": 20, "warn": 8, "info": 0, "pass": 0}


def _check(check_id: str, status: str, title: str, detail: str, fix: str) -> models.Check:
    return models.Check(id=check_id, status=status, title=title, detail=detail, fix=fix)


def _disk_check(report: models.SystemReport) -> models.Check | None:
    if not report.disks:
        return None
    worst = min(report.disks, key=lambda disk: 100 - disk.percent_used)
    free_pct = round(100 - worst.percent_used, 1)
    if free_pct < 5:
        status = "fail"
    elif free_pct < 10:
        status = "warn"
    else:
        status = "pass"
    detail = (
        f"{worst.mount} has {free_pct}% free "
        f"({units.format_bytes(worst.free_bytes)} of {units.format_bytes(worst.total_bytes)})"
    )
    return _check("disk_space", status, "Disk space", detail, "Free at least 10% of the drive (Disk Cleanup or Storage Sense).")


def _ram_check(report: models.SystemReport) -> models.Check | None:
    if report.memory is None or report.memory.total_bytes <= 0:
        return None
    total_gb = report.memory.total_bytes / GB
    if total_gb < 4:
        status = "fail"
    elif total_gb < 8:
        status = "warn"
    else:
        status = "pass"
    return _check(
        "ram",
        status,
        "Memory",
        f"{total_gb:.1f} GB installed",
        "Add RAM if you regularly hit 90% memory usage.",
    )


def _tpm_check(report: models.SystemReport) -> models.Check | None:
    tpm = report.security.tpm
    build = int(report.os.build) if report.os.build.isdigit() else 0
    if not tpm.present:
        if build >= 22000:
            return _check("tpm", "fail", "TPM", "No TPM detected on Windows 11", "Enable firmware TPM (fTPM/PTT) in UEFI settings.")
        return _check("tpm", "warn", "TPM", "No TPM detected", "Enable firmware TPM in UEFI settings.")
    if tpm.version and tpm.version.startswith("1."):
        return _check("tpm", "warn", "TPM", f"TPM {tpm.version} detected", "TPM 2.0 is required by Windows 11; update firmware if possible.")
    detail = f"TPM {tpm.version} ({tpm.status})" if tpm.version else "TPM present, details unavailable"
    return _check("tpm", "pass", "TPM", detail, "No action needed.")


def _secure_boot_check(report: models.SystemReport) -> models.Check | None:
    if report.security.secure_boot is True:
        return _check("secure_boot", "pass", "Secure Boot", "Enabled", "No action needed.")
    reason = report.security.secure_boot_reason or "unsupported or disabled"
    return _check("secure_boot", "warn", "Secure Boot", reason, "Enable Secure Boot in UEFI settings.")


def _defender_av_check(report: models.SystemReport) -> models.Check | None:
    defender = report.security.defender
    if defender.av_enabled is None:
        return None
    if defender.av_enabled:
        return _check("defender_av", "pass", "Antivirus", "Windows Defender antivirus enabled", "No action needed.")
    return _check("defender_av", "fail", "Antivirus", "Antivirus is disabled", "Enable Microsoft Defender or another antivirus.")


def _defender_realtime_check(report: models.SystemReport) -> models.Check | None:
    defender = report.security.defender
    if defender.av_enabled is not True or defender.realtime_enabled is None:
        return None
    if defender.realtime_enabled:
        return _check("defender_realtime", "pass", "Real-time protection", "Enabled", "No action needed.")
    return _check("defender_realtime", "fail", "Real-time protection", "Disabled", "Turn on real-time protection in Windows Security.")


def _defender_signature_check(report: models.SystemReport) -> models.Check | None:
    age = report.security.defender.signature_age_days
    if age is None:
        return None
    if age > 7:
        return _check("defender_signatures", "warn", "Virus definitions", f"{age} days old", "Run Windows Update to refresh definitions.")
    return _check("defender_signatures", "pass", "Virus definitions", f"{age} days old", "No action needed.")


def _today() -> dt.date:
    return dt.date.today()


def _hotfix_check(report: models.SystemReport) -> models.Check | None:
    newest = report.hotfixes.newest_date
    if newest is None:
        return _check("hotfix_age", "info", "Updates", "Newest hotfix date unknown", "Run Windows Update to confirm patching.")
    try:
        installed = dt.date.fromisoformat(newest)
    except ValueError:
        return _check("hotfix_age", "info", "Updates", f"Unparsed hotfix date {newest}", "Run Windows Update to confirm patching.")
    age_days = (_today() - installed).days
    if age_days > 60:
        return _check("hotfix_age", "warn", "Updates", f"Newest hotfix is {age_days} days old", "Run Windows Update.")
    return _check("hotfix_age", "pass", "Updates", f"Newest hotfix is {age_days} days old", "No action needed.")


def _bitlocker_check(report: models.SystemReport) -> models.Check | None:
    info = report.security.bitlocker
    if info.protection is None:
        return _check("bitlocker", "info", "BitLocker", "Status unavailable", "Run as administrator to check BitLocker status.")
    if info.protection == "On":
        return _check("bitlocker", "pass", "BitLocker", f"System volume protected ({info.volume_status})", "No action needed.")
    return _check("bitlocker", "info", "BitLocker", f"System volume not protected ({info.protection})", "Consider enabling BitLocker for at-rest encryption.")


def _uptime_check(report: models.SystemReport) -> models.Check | None:
    if report.uptime_seconds is None:
        return None
    days = report.uptime_seconds // 86400
    if days > 30:
        return _check("uptime", "info", "Uptime", f"{days} days since last boot", "Restart to apply pending updates.")
    return _check("uptime", "pass", "Uptime", f"{days} days since last boot", "No action needed.")


def evaluate(report: models.SystemReport) -> tuple[tuple[models.Check, ...], int]:
    candidates = (
        _disk_check(report),
        _ram_check(report),
        _tpm_check(report),
        _secure_boot_check(report),
        _defender_av_check(report),
        _defender_realtime_check(report),
        _defender_signature_check(report),
        _hotfix_check(report),
        _bitlocker_check(report),
        _uptime_check(report),
    )
    checks = tuple(check for check in candidates if check is not None)
    score = max(0, 100 - sum(DEDUCTIONS[check.status] for check in checks))
    return checks, score
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `python -m pytest tests/test_health.py -q`
Expected: `11 passed`.

- [ ] **Step 5: Commit**

```bash
git add winsysinfo/health.py tests/test_health.py
git commit -m "feat: add rule-based health scoring"
```

---

### Task 6: Default-on redaction

**Files:**
- Create: `winsysinfo/redact.py`
- Create: `tests/test_redact.py`

**Interfaces:**
- Consumes: `models.SystemReport`.
- Produces: `redact.apply(report: models.SystemReport) -> models.SystemReport` (new report with `redacted=True`).

- [ ] **Step 1: Write the failing test**

`tests/test_redact.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_redact.py -q`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Write minimal implementation**

`winsysinfo/redact.py`:
```python
"""Privacy-first output: mask identity fields unless the user opts in."""

from __future__ import annotations

from dataclasses import replace

from winsysinfo import models

REDACTED_HOST = "REDACTED-HOST"
REDACTED_SERIAL = "REDACTED-SERIAL"
REDACTED_MAC = "XX:XX:XX:XX:XX:XX"


def _mask_ipv4(address: str) -> str:
    parts = address.split(".")
    if len(parts) != 4:
        return address
    return ".".join([*parts[:3], "0"])


def apply(report: models.SystemReport) -> models.SystemReport:
    adapters = tuple(
        replace(
            adapter,
            ipv4=tuple(_mask_ipv4(ip) for ip in adapter.ipv4),
            mac=REDACTED_MAC if adapter.mac else adapter.mac,
        )
        for adapter in report.network.adapters
    )
    bios = replace(report.bios, serial=REDACTED_SERIAL) if report.bios is not None else None
    return replace(
        report,
        hostname=REDACTED_HOST,
        bios=bios,
        network=replace(report.network, adapters=adapters),
        redacted=True,
    )
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `python -m pytest tests/test_redact.py -q`
Expected: `5 passed`.

- [ ] **Step 5: Commit**

```bash
git add winsysinfo/redact.py tests/test_redact.py
git commit -m "feat: redact identity fields by default"
```

---

### Task 7: Renderers (text, JSON, Markdown, HTML)

**Files:**
- Create: `winsysinfo/render/__init__.py`
- Create: `winsysinfo/render/text.py`
- Create: `winsysinfo/render/json_report.py`
- Create: `winsysinfo/render/markdown.py`
- Create: `winsysinfo/render/html.py`
- Create: `tests/test_render.py`

**Interfaces:**
- Consumes: `models.SystemReport`, `units.*`.
- Produces: `render.render(report, fmt: str) -> str` for `fmt ∈ {"text","json","md","html"}`; `render.EXTENSIONS = {"text": "txt", "json": "json", "md": "md", "html": "html"}`.

- [ ] **Step 1: Write the failing test**

`tests/test_render.py`:
```python
import dataclasses
import datetime as dt
import json
from pathlib import Path

import pytest

from winsysinfo import collect, health, models, render

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
    out = render.render(_report(redacted=True), "text")
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_render.py -q`
Expected: FAIL — `ModuleNotFoundError: winsysinfo.render`.

- [ ] **Step 3: Write minimal implementation**

`winsysinfo/render/__init__.py`:
```python
"""Report renderers. Each returns a complete document string."""

from __future__ import annotations

from winsysinfo.models import SystemReport
from winsysinfo.render import html, json_report, markdown, text

EXTENSIONS = {"text": "txt", "json": "json", "md": "md", "html": "html"}

_RENDERERS = {
    "text": text.render,
    "json": json_report.render,
    "md": markdown.render,
    "html": html.render,
}


def render(report: SystemReport, fmt: str) -> str:
    try:
        renderer = _RENDERERS[fmt]
    except KeyError as exc:
        raise ValueError(f"unknown report format: {fmt}") from exc
    return renderer(report)
```

`winsysinfo/render/text.py`:
```python
"""Fixed-width console report."""

from __future__ import annotations

from winsysinfo import units
from winsysinfo.models import SystemReport

_SEPARATOR = "=" * 26


def _health_line(report: SystemReport) -> str:
    fails = sum(1 for check in report.checks if check.status == "fail")
    warns = sum(1 for check in report.checks if check.status == "warn")
    infos = sum(1 for check in report.checks if check.status == "info")
    parts = []
    if fails:
        parts.append(f"{fails} failing")
    if warns:
        parts.append(f"{warns} warning{'s' if warns != 1 else ''}")
    if infos:
        parts.append(f"{infos} informational")
    summary = ", ".join(parts) if parts else "all checks passed"
    return f"Health:      {report.health_score}/100 ({summary})"


def _section(lines: list[str], title: str) -> None:
    lines.extend(["", f"--- {title} ---"])


def render(report: SystemReport) -> str:
    lines = ["WINDOWS SYSTEM INFORMATION", _SEPARATOR, ""]
    lines.append(f"Generated:   {report.generated_at}")
    lines.append(f"Computer:    {report.hostname}")
    lines.append(_health_line(report))
    if report.redacted:
        lines.append("Note:        identity fields are redacted (use --include-sensitive for full details)")
    for check in report.checks:
        if check.status in ("fail", "warn"):
            lines.append(f"[{check.status.upper()}] {check.title}: {check.detail}")
            lines.append(f"         fix: {check.fix}")

    _section(lines, "SYSTEM")
    os_info = report.os
    lines.append(f"OS:          {os_info.name} {os_info.edition}")
    lines.append(f"Version:     {os_info.release} (build {os_info.build})")
    lines.append(f"Architecture:{os_info.architecture}")
    if os_info.install_date:
        lines.append(f"Installed:   {os_info.install_date}")
    if report.uptime_seconds is not None:
        lines.append(f"Uptime:      {report.uptime_seconds // 86400} days")

    _section(lines, "CPU")
    if report.cpu:
        lines.append(f"{report.cpu.name} ({report.cpu.cores}C/{report.cpu.logical}T @ {report.cpu.max_mhz} MHz)")
    else:
        lines.append("(unavailable)")

    _section(lines, "MEMORY")
    if report.memory and report.memory.total_bytes:
        used = report.memory.total_bytes - report.memory.free_bytes
        lines.append(
            f"{units.format_bytes(used)} / {units.format_bytes(report.memory.total_bytes)} used, "
            f"{len(report.memory.modules)} module(s)"
        )
        for module in report.memory.modules[:4]:
            lines.append(f"  {units.format_bytes(module.capacity_bytes)} @ {module.speed_mhz} MHz ({module.manufacturer})")
    else:
        lines.append("(unavailable)")

    _section(lines, "GPU")
    if report.gpus:
        for gpu in report.gpus:
            lines.append(f"{gpu.name} [{units.format_bytes(gpu.vram_bytes)} VRAM, driver {gpu.driver}]")
    else:
        lines.append("(unavailable)")

    _section(lines, "DISK")
    if report.disks:
        for disk in report.disks:
            lines.append(
                f"{disk.mount} [{disk.filesystem}] "
                f"{units.format_bytes(disk.total_bytes - disk.free_bytes)}/{units.format_bytes(disk.total_bytes)} "
                f"used ({disk.percent_used}%)"
            )
    else:
        lines.append("(no fixed drives detected)")

    _section(lines, "NETWORK")
    for adapter in report.network.adapters:
        lines.append(f"{adapter.name}")
        lines.append(f"  IP:      {', '.join(adapter.ipv4) or 'none'}")
        if adapter.gateways:
            lines.append(f"  Gateway: {', '.join(adapter.gateways)}")
        if adapter.mac:
            lines.append(f"  MAC:     {adapter.mac}")
        lines.append(f"  DHCP:    {'yes' if adapter.dhcp else 'no'}")

    _section(lines, "SECURITY")
    tpm = report.security.tpm
    if tpm.present:
        detail = f"v{tpm.version} ({tpm.status})" if tpm.version else "present (details unavailable)"
        lines.append(f"TPM:         {detail}")
    else:
        lines.append("TPM:         Not detected")
    secure_boot = report.security.secure_boot
    lines.append(f"Secure Boot: {'enabled' if secure_boot else 'disabled or unsupported'}")
    defender = report.security.defender
    if defender.av_enabled is None:
        lines.append("Defender:    unavailable")
    else:
        lines.append(
            f"Defender:    AV {'on' if defender.av_enabled else 'off'}, "
            f"real-time {'on' if defender.realtime_enabled else 'off'}, "
            f"signatures {defender.signature_age_days}d old"
        )
    bitlocker = report.security.bitlocker
    lines.append(f"BitLocker:   {bitlocker.protection or 'unavailable'}")

    _section(lines, "PATCHES")
    hotfixes = report.hotfixes
    if hotfixes.ids:
        newest = f", newest {hotfixes.newest_date}" if hotfixes.newest_date else ""
        shown = ", ".join(hotfixes.ids[:5])
        more = f", +{len(hotfixes.ids) - 5} more" if len(hotfixes.ids) > 5 else ""
        lines.append(f"{hotfixes.count} installed{newest} ({shown}{more})")
    else:
        lines.append("No hotfixes reported")

    if report.battery is not None:
        _section(lines, "BATTERY")
        lines.append(f"{report.battery.percent}% ({'on power' if report.battery.charging else 'on battery'})")

    if report.errors:
        _section(lines, "WARNINGS")
        for error in report.errors:
            lines.append(error)

    lines.extend(["", _SEPARATOR])
    return "\n".join(lines)
```

`winsysinfo/render/json_report.py`:
```python
"""Machine-readable JSON report."""

from __future__ import annotations

import json

from winsysinfo.models import SystemReport


def render(report: SystemReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
```

`winsysinfo/render/markdown.py`:
```python
"""Markdown report for issues, wikis and PRs."""

from __future__ import annotations

from winsysinfo import units
from winsysinfo.models import SystemReport


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|")


def _table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(_cell(value) for value in row) + " |")
    return lines


def render(report: SystemReport) -> str:
    fails = sum(1 for check in report.checks if check.status == "fail")
    warns = sum(1 for check in report.checks if check.status == "warn")
    lines = [
        "# Windows system information",
        "",
        f"**Health:** {report.health_score}/100 ({fails} failing, {warns} warning(s))",
        "",
        f"**Computer:** `{report.hostname}`  ",
        f"**Generated:** {report.generated_at}",
        "",
        "## Checks",
        "",
    ]
    lines += _table(
        ["Check", "Status", "Detail", "Fix"],
        [[check.title, check.status, check.detail, check.fix if check.status != "pass" else "—"] for check in report.checks],
    )
    lines += ["", "## System", ""]
    os_info = report.os
    lines += _table(
        ["Field", "Value"],
        [
            ["OS", f"{os_info.name} {os_info.edition}"],
            ["Build", os_info.build],
            ["Architecture", os_info.architecture],
            ["Uptime", f"{report.uptime_seconds // 86400} days" if report.uptime_seconds is not None else "unknown"],
        ],
    )
    if report.cpu:
        lines += ["", "## CPU", "", f"{report.cpu.name} ({report.cpu.cores}C/{report.cpu.logical}T @ {report.cpu.max_mhz} MHz)"]
    if report.memory and report.memory.total_bytes:
        lines += ["", "## Memory", ""]
        lines += _table(
            ["Module", "Capacity", "Speed", "Manufacturer"],
            [
                [f"#{index + 1}", units.format_bytes(module.capacity_bytes), f"{module.speed_mhz} MHz", module.manufacturer]
                for index, module in enumerate(report.memory.modules)
            ],
        )
    if report.disks:
        lines += ["", "## Disks", ""]
        lines += _table(
            ["Mount", "Filesystem", "Used", "Total", "Free %"],
            [
                [
                    disk.mount,
                    disk.filesystem,
                    units.format_bytes(disk.total_bytes - disk.free_bytes),
                    units.format_bytes(disk.total_bytes),
                    f"{round(100 - disk.percent_used, 1)}%",
                ]
                for disk in report.disks
            ],
        )
    if report.network.adapters:
        lines += ["", "## Network", ""]
        lines += _table(
            ["Adapter", "IPv4", "Gateway", "MAC", "DHCP"],
            [
                [
                    adapter.name,
                    ", ".join(adapter.ipv4) or "—",
                    ", ".join(adapter.gateways) or "—",
                    adapter.mac or "—",
                    "yes" if adapter.dhcp else "no",
                ]
                for adapter in report.network.adapters
            ],
        )
    lines += ["", "## Security", ""]
    tpm = report.security.tpm
    defender = report.security.defender
    bitlocker = report.security.bitlocker
    lines += _table(
        ["Control", "State"],
        [
            ["TPM", f"v{tpm.version} ({tpm.status})" if tpm.version else ("present" if tpm.present else "absent")],
            ["Secure Boot", "enabled" if report.security.secure_boot else "disabled/unsupported"],
            ["Defender AV", "unknown" if defender.av_enabled is None else ("on" if defender.av_enabled else "off")],
            ["BitLocker", bitlocker.protection or "unavailable"],
        ],
    )
    lines += ["", "## Updates", ""]
    if report.hotfixes.ids:
        lines.append(f"{report.hotfixes.count} hotfixes installed; newest: {report.hotfixes.newest_date or 'unknown'}")
        lines.append("")
        lines.append(", ".join(f"`{hotfix}`" for hotfix in report.hotfixes.ids[:10]))
    else:
        lines.append("No hotfixes reported.")
    if report.redacted:
        lines += ["", "> Identity fields are redacted. Re-run with `--include-sensitive` for full details."]
    if report.errors:
        lines += ["", "## Warnings", ""]
        lines += [f"- {error}" for error in report.errors]
    return "\n".join(lines) + "\n"
```

`winsysinfo/render/html.py`:
```python
"""Self-contained HTML dashboard (inline CSS, no external assets)."""

from __future__ import annotations

import html
from typing import Any

from winsysinfo import units
from winsysinfo.models import SystemReport

_CSS = """
:root { color-scheme: light dark; }
body { font-family: "Segoe UI", system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem; }
h1 { font-size: 1.5rem; }
.score { display: inline-block; padding: .25rem .75rem; border-radius: 999px; background: #e8f5e9; color: #1b5e20; font-weight: 600; }
.score.warn { background: #fff8e1; color: #7f6000; }
.score.fail { background: #ffebee; color: #b71c1c; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1.5rem; }
th, td { border: 1px solid #ccc; padding: .4rem .6rem; text-align: left; font-size: .9rem; }
th { background: rgba(127,127,127,.12); }
tr.pass td:first-child { color: #2e7d32; }
tr.warn td:first-child { color: #a66300; font-weight: 600; }
tr.fail td:first-child { color: #c62828; font-weight: 600; }
.note { padding: .5rem .75rem; background: rgba(255,193,7,.15); border-left: 4px solid #ffc107; }
footer { margin-top: 2rem; font-size: .8rem; opacity: .7; }
"""


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _table(headers: list[str], rows: list[list[Any]], row_classes: list[str] | None = None) -> str:
    head = "".join(f"<th>{_esc(header)}</th>" for header in headers)
    body = []
    for index, row in enumerate(rows):
        row_class = f' class="{row_classes[index]}"' if row_classes else ""
        cells = "".join(f"<td>{_esc(cell)}</td>" for cell in row)
        body.append(f"<tr{row_class}>{cells}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def render(report: SystemReport) -> str:
    fails = sum(1 for check in report.checks if check.status == "fail")
    warns = sum(1 for check in report.checks if check.status == "warn")
    level = "fail" if fails else ("warn" if warns else "")
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>System report — {_esc(report.hostname)}</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>Windows system information</h1>",
        f'<p><span class="score {level}">{report.health_score}/100</span> '
        f"{fails} failing, {warns} warning(s)</p>",
    ]
    if report.redacted:
        parts.append('<p class="note">Identity fields are redacted. Re-run with <code>--include-sensitive</code> for full details.</p>')
    parts.append("<h2>Checks</h2>")
    parts.append(
        _table(
            ["Check", "Status", "Detail", "Fix"],
            [[check.title, check.status, check.detail, check.fix if check.status != "pass" else "—"] for check in report.checks],
            [check.status for check in report.checks],
        )
    )
    os_info = report.os
    parts.append("<h2>System</h2>")
    parts.append(
        _table(
            ["Field", "Value"],
            [
                ["OS", f"{os_info.name} {os_info.edition}"],
                ["Build", os_info.build],
                ["Architecture", os_info.architecture],
                ["Computer", report.hostname],
                ["Generated", report.generated_at],
                ["Uptime", f"{report.uptime_seconds // 86400} days" if report.uptime_seconds is not None else "unknown"],
            ],
        )
    )
    if report.cpu:
        parts.append("<h2>CPU</h2>")
        parts.append(f"<p>{_esc(report.cpu.name)} — {report.cpu.cores}C/{report.cpu.logical}T @ {report.cpu.max_mhz} MHz</p>")
    if report.gpus:
        parts.append("<h2>GPU</h2>")
        parts.append(
            _table(
                ["GPU", "VRAM", "Driver"],
                [[gpu.name, units.format_bytes(gpu.vram_bytes), gpu.driver] for gpu in report.gpus],
            )
        )
    if report.disks:
        parts.append("<h2>Disks</h2>")
        parts.append(
            _table(
                ["Mount", "Filesystem", "Used", "Total", "Used %"],
                [
                    [
                        disk.mount,
                        disk.filesystem,
                        units.format_bytes(disk.total_bytes - disk.free_bytes),
                        units.format_bytes(disk.total_bytes),
                        f"{disk.percent_used}%",
                    ]
                    for disk in report.disks
                ],
            )
        )
    if report.network.adapters:
        parts.append("<h2>Network</h2>")
        parts.append(
            _table(
                ["Adapter", "IPv4", "Gateway", "MAC", "DHCP"],
                [
                    [
                        adapter.name,
                        ", ".join(adapter.ipv4) or "—",
                        ", ".join(adapter.gateways) or "—",
                        adapter.mac or "—",
                        "yes" if adapter.dhcp else "no",
                    ]
                    for adapter in report.network.adapters
                ],
            )
        )
    tpm = report.security.tpm
    defender = report.security.defender
    bitlocker = report.security.bitlocker
    parts.append("<h2>Security</h2>")
    parts.append(
        _table(
            ["Control", "State"],
            [
                ["TPM", f"v{tpm.version} ({tpm.status})" if tpm.version else ("present" if tpm.present else "absent")],
                ["Secure Boot", "enabled" if report.security.secure_boot else "disabled/unsupported"],
                ["Defender AV", "unknown" if defender.av_enabled is None else ("on" if defender.av_enabled else "off")],
                ["BitLocker", bitlocker.protection or "unavailable"],
            ],
        )
    )
    parts.append("<h2>Updates</h2>")
    if report.hotfixes.ids:
        parts.append(f"<p>{report.hotfixes.count} hotfixes installed; newest: {_esc(report.hotfixes.newest_date or 'unknown')}</p>")
        parts.append("<p>" + ", ".join(_esc(hotfix) for hotfix in report.hotfixes.ids[:10]) + "</p>")
    else:
        parts.append("<p>No hotfixes reported.</p>")
    if report.errors:
        parts.append("<h2>Warnings</h2><ul>")
        parts.extend(f"<li>{_esc(error)}</li>" for error in report.errors)
        parts.append("</ul>")
    parts.append("<footer>Generated by winsysinfo. Health score is heuristic, not a security audit.</footer>")
    parts.append("</body></html>")
    return "\n".join(parts)
```

Note: remove the unused `dataclasses` import in `html.py` — ruff will flag it. The plan's code must be lint-clean, so use only `import html` and `from typing import Any`.

- [ ] **Step 4: Run tests and verify they pass**

Run: `python -m pytest tests/test_render.py -q`
Expected: `7 passed`.

- [ ] **Step 5: Lint and format**

Run: `python -m ruff check winsysinfo tests && python -m ruff format --check winsysinfo tests`
Expected: no findings; if formatting differs, run `python -m ruff format winsysinfo tests` and re-run tests.

- [ ] **Step 6: Commit**

```bash
git add winsysinfo/render tests/test_render.py
git commit -m "feat: add text, JSON, Markdown and HTML renderers"
```

---

### Task 8: CLI, entry point, legacy cleanup

**Files:**
- Create: `winsysinfo/cli.py`
- Create: `winsysinfo/__main__.py`
- Create: `tests/test_cli.py`
- Modify: `run_system_info_collector.bat`
- Delete: `windows_system_info_collector.py`

**Interfaces:**
- Consumes: `probe.run_probe`, `collect.build_report`, `health.evaluate`, `redact.apply`, `render.render`, `render.EXTENSIONS`.
- Produces: `cli.main(argv: Sequence[str] | None = None) -> int`; console script `winsysinfo`.

- [ ] **Step 1: Write the failing test**

`tests/test_cli.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli.py -q`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Write minimal implementation**

`winsysinfo/cli.py`:
```python
"""Command-line entry point."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import sys
from pathlib import Path
from typing import Sequence

from winsysinfo import __version__, collect, health, probe, redact
from winsysinfo import render as render_pkg


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="winsysinfo",
        description="Collect Windows system information, score its health and write a report.",
    )
    parser.add_argument(
        "--format",
        default="text",
        help="Comma-separated output formats: text,json,md,html (default: text)",
    )
    parser.add_argument("--out", default=".", help="Directory for report files (default: current directory)")
    parser.add_argument(
        "--include-sensitive",
        action="store_true",
        help="Do not redact hostname, serials, MAC addresses and IPs",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Do not print the report to stdout")
    parser.add_argument("--verbose", action="store_true", help="Print collector warnings to stderr")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    formats = [item.strip() for item in args.format.split(",") if item.strip()]
    unknown = [item for item in formats if item not in render_pkg.EXTENSIONS]
    if not formats or unknown:
        return _fail(f"unknown format: {', '.join(unknown) or '(none)'} (choose from text, json, md, html)")
    if sys.platform != "win32":
        return _fail("winsysinfo only supports Windows")

    result = probe.run_probe()
    errors = (result.error,) if result.error else ()
    report = collect.build_report(result.data or {}, errors=errors)
    checks, score = health.evaluate(report)
    report = dataclasses.replace(report, checks=checks, health_score=score)
    if not args.include_sensitive:
        report = redact.apply(report)

    out_dir = Path(args.out)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return _fail(f"cannot create output directory {out_dir}: {exc}")

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    saved = []
    for fmt in formats:
        path = out_dir / f"system_info_report_{stamp}.{render_pkg.EXTENSIONS[fmt]}"
        try:
            path.write_text(render_pkg.render(report, fmt), encoding="utf-8")
        except OSError as exc:
            return _fail(f"cannot write {path}: {exc}")
        saved.append(path)

    if not args.quiet:
        print(render_pkg.render(report, formats[0] if len(formats) == 1 else "text"))
    for path in saved:
        print(f"Report saved to: {path.resolve()}", file=sys.stderr)
    if args.verbose and report.errors:
        print("Warnings:", file=sys.stderr)
        for error in report.errors:
            print(f"  {error}", file=sys.stderr)

    if argv is None and sys.stdin.isatty():
        with contextlib.suppress(EOFError, KeyboardInterrupt):
            input("\nPress Enter to exit...")

    return 1 if report.errors else 0
```

`winsysinfo/__main__.py`:
```python
"""python -m winsysinfo"""

import sys

from winsysinfo.cli import main

if __name__ == "__main__":
    sys.exit(main())
```

`run_system_info_collector.bat` (replace whole file):
```bat
@echo off
python -m winsysinfo %*
if errorlevel 2 pause
```

Delete the legacy script:
```bash
git rm windows_system_info_collector.py
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `python -m pytest tests/test_cli.py -q`
Expected: `7 passed`.

- [ ] **Step 5: Run the whole suite**

Run: `python -m pytest -q`
Expected: all tests pass (no failures, no errors).

- [ ] **Step 6: Smoke-run the real tool**

Run: `python -m winsysinfo --format text,json --out reports`
Expected: exit 0, health banner printed, both files created. Inspect the JSON: `schema_version` `1.0`, `redacted` true, hotfix count > 0.

- [ ] **Step 7: Commit**

```bash
git add winsysinfo/cli.py winsysinfo/__main__.py tests/test_cli.py run_system_info_collector.bat
git commit -m "feat: add CLI, module entry point and retire legacy script"
```

---

### Task 9: CI, README, final verification

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `README.md`
- Create: `tests/test_probe_integration.py`

**Interfaces:**
- Consumes: everything above.
- Produces: green CI on `windows-latest`; README that documents the new CLI.

- [ ] **Step 1: Write the integration test (skipped off Windows)**

`tests/test_probe_integration.py`:
```python
import sys

import pytest

from winsysinfo import probe


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_live_probe_returns_json():
    result = probe.run_probe(timeout=120)
    assert result.error is None
    assert result.data is not None
    assert "os" in result.data
    assert "hotfixes" in result.data
```

- [ ] **Step 2: Run it**

Run: `python -m pytest tests/test_probe_integration.py -q`
Expected: `1 passed` on Windows. If it fails with a PowerShell error, fix `PS_SCRIPT` (the test prints no diagnostics — run `python -c "from winsysinfo.probe import run_probe; print(run_probe())"` to inspect).

- [ ] **Step 3: Write CI workflow**

`.github/workflows/ci.yml`:
```yaml
name: ci

on:
  push:
    branches: [main, v2-rebuild]
  pull_request:

jobs:
  test:
    runs-on: windows-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.11", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install
        run: python -m pip install -e ".[dev]"
      - name: Lint
        run: ruff check .
      - name: Format check
        run: ruff format --check .
      - name: Type check
        run: mypy winsysinfo
      - name: Tests
        run: pytest --cov=winsysinfo --cov-fail-under=85
      - name: Smoke run
        run: python -m winsysinfo -q --format json --out smoke
      - name: Validate smoke report
        run: python -c "import json,pathlib; [json.loads(p.read_text(encoding='utf-8')) for p in pathlib.Path('smoke').glob('*.json')]"
```

- [ ] **Step 4: Rewrite README**

`README.md`:
```markdown
# Windows System Info Collector (winsysinfo)

Collect Windows hardware/OS/security facts, get a 0–100 health score, and export a report as text, JSON, Markdown or a self-contained HTML page. No external dependencies — just Python 3.11+ and the PowerShell that ships with Windows.

## Why this rewrite

The v1 script scraped `wmic` and `ipconfig` text. `wmic` is gone from Windows 11 24H2+, `ipconfig` output is localized, and most failures were swallowed by bare `except:` blocks. v2 uses a single CIM/PowerShell call that returns JSON, so it works on any Windows locale, needs no admin rights for most facts, and runs in one process instead of five.

## Quick start

```bat
git clone https://github.com/Dedotre/windows-system-info-collector.git
cd windows-system-info-collector
python -m winsysinfo
```

Or install it as a command:

```bat
pip install .
winsysinfo --format text,json,md,html --out reports
```

Double-clicking `run_system_info_collector.bat` still works.

## Options

| Flag | Meaning |
|---|---|
| `--format text,json,md,html` | Output formats (default `text`). Multiple formats write multiple files. |
| `--out DIR` | Directory for reports (default: current directory). |
| `--include-sensitive` | Disable redaction of hostname, serials, MACs and IPs. |
| `-q`, `--quiet` | Do not print the report to stdout. |
| `--verbose` | Print collector warnings to stderr. |
| `--version` | Print version. |

Exit codes: `0` success, `1` completed with warnings, `2` fatal (non-Windows, bad format, unwritable directory).

## Privacy

Reports are **redacted by default**: hostname becomes `REDACTED-HOST`, serials become `REDACTED-SERIAL`, MACs become `XX:XX:XX:XX:XX:XX`, and the last IPv4 octet is zeroed. Use `--include-sensitive` only for your own machine. JSON reports carry `"redacted": true/false`.

## Health score

Each rule emits at most one check (`pass`/`warn`/`fail`/`info`); failures cost 20 points, warnings 8. Rules: disk free space, RAM size, TPM presence/version, Secure Boot, Defender AV + real-time protection + signature age, hotfix freshness (60 days), BitLocker (info only), uptime (info only). The score is heuristic — it is not a security audit.

## What gets collected

OS/build/edition, uptime, CPU, RAM modules, GPUs, fixed disks, network adapters (IPv4, gateway, MAC, DHCP), BIOS/board version + serial, TPM, Secure Boot, Defender, BitLocker, hotfixes, battery. Values that need elevation (TPM details, BitLocker) render as `unavailable (…)` instead of failing the run.

## Requirements

- Windows 10/11
- Python 3.11+
- Windows PowerShell 5.1 (present by default); PowerShell 7 works too

## Development

```bat
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy winsysinfo
```

CI runs the same commands on `windows-latest` for Python 3.11 and 3.13, including a live probe smoke test.

## Migrating from v1

`windows_system_info_collector.py` was removed. Use `python -m winsysinfo` (or the `.bat`) instead. The default text report contains the same sections plus CPU/memory/GPU, a health summary and redaction.

## License

MIT
```

- [ ] **Step 5: Full local verification**

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy winsysinfo
python -m pytest -q
python -m winsysinfo --format text,json,md,html --out reports
```

Expected: ruff/mypy clean, all tests pass, exit 0, four files under `reports/`.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml README.md tests/test_probe_integration.py
git commit -m "ci: add Windows CI and document winsysinfo v2"
```

---

## Self-Review Notes

- Spec coverage: probe/fallbacks (Tasks 3–4), data model & JSON schema (2, 4, 7), health rules (5), redaction (6), renderers (7), CLI/exit codes/pause (8), tests (all), CI (9), packaging & README (1, 9). Deferred items (exe, SQLite, diff) intentionally absent.
- Known deviation from spec text, already reflected in the spec: `build_report` takes `errors`; `BiosInfo` has `board`; exit-code semantics for degraded runs; saved paths always go to stderr.
- Time-dependent rules (`hotfix_age`) read `health._today()`; tests pin it with an autouse fixture so the suite does not rot.
- `html.py` must not import `dataclasses` (unused → ruff F401). Use only `html` and `Any`.
- If coverage lands below 85, add tests for `_fallback_adapter`, battery rendering and the unwritable-`--out` branch — do not lower the gate.
- Long f-strings may exceed the 120-column limit; run `ruff check` and split strings before each commit.
