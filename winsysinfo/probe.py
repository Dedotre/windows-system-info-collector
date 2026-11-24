"""One batched PowerShell CIM call. No human-readable output is ever parsed."""

from __future__ import annotations

import base64
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
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' |
  Select-Object DeviceID, FileSystem, Size, FreeSpace)
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

# `-Command -` silently drops output when stdin is a pipe, so the script travels base64-encoded.
_CMD_PREFIX = ("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand")


@dataclass(frozen=True)
class ProbeResult:
    data: dict[str, Any] | None
    error: str | None


def build_command() -> tuple[str, ...]:
    encoded = base64.b64encode(PS_SCRIPT.encode("utf-16-le")).decode("ascii")
    return (*_CMD_PREFIX, encoded)


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
            build_command(),
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
