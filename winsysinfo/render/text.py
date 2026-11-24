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
        lines.append(f"Uptime:      {units.format_days(report.uptime_seconds // 86400)}")

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
            size = units.format_bytes(module.capacity_bytes)
            lines.append(f"  {size} @ {module.speed_mhz} MHz ({module.manufacturer})")
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
            used_str = units.format_bytes(disk.total_bytes - disk.free_bytes)
            total_str = units.format_bytes(disk.total_bytes)
            lines.append(f"{disk.mount} [{disk.filesystem}] {used_str}/{total_str} used ({disk.percent_used}%)")
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
    if secure_boot is None:
        lines.append("Secure Boot: unavailable")
    else:
        lines.append(f"Secure Boot: {'enabled' if secure_boot else 'disabled'}")
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
        state = "on power" if report.battery.charging else "on battery"
        lines.append(f"{report.battery.percent}% ({state})")

    if report.errors:
        _section(lines, "WARNINGS")
        lines.extend(report.errors)

    lines.extend(["", _SEPARATOR])
    return "\n".join(lines)
