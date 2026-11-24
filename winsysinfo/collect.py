"""Turn probe JSON plus stdlib facts into a SystemReport. Pure, no I/O."""

from __future__ import annotations

import contextlib
import ctypes
import datetime as dt
import platform
import socket
from collections.abc import Iterable
from typing import Any

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
    version = platform.version()
    fallback_build = version.split(".")[-1] if version else ""
    build = _text(data.get("BuildNumber"), fallback_build)
    major = _number(build)
    if major >= 22000:
        name = "Windows 11"
    elif major >= 10240:
        name = "Windows 10"
    else:
        name = _text(data.get("Caption"), platform.system())
    edition = platform.win32_edition() if hasattr(platform, "win32_edition") else ""
    return models.OsInfo(
        name=name,
        release=platform.release(),
        build=build,
        edition=_text(edition, "Unknown"),
        architecture=_text(data.get("OSArchitecture"), platform.architecture()[0]),
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

    return models.SecurityInfo(
        tpm=tpm,
        secure_boot=_optional_bool(raw.get("secure_boot")),
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
    delta = dt.datetime.now(dt.UTC) - boot.astimezone(dt.UTC)
    return max(0, int(delta.total_seconds()))


def build_report(raw: dict[str, Any], errors: Iterable[str] = ()) -> models.SystemReport:
    return models.SystemReport(
        schema_version=models.SCHEMA_VERSION,
        generated_at=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        hostname=socket.gethostname(),
        os=_os_info(raw),
        cpu=_cpu_info(raw),
        memory=_memory_info(raw),
        gpus=_gpus(raw),
        disks=_disk_infos(raw) or _fallback_disks(),
        network=_network_info(raw),
        bios=_bios_info(raw),
        security=_security_info(raw),
        hotfixes=_hotfix_info(raw),
        battery=_battery_info(raw),
        uptime_seconds=_uptime_seconds(raw),
        errors=tuple(errors),
    )
