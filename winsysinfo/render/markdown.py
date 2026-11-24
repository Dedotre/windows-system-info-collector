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


def _secure_boot_label(report: SystemReport) -> str:
    if report.security.secure_boot is None:
        return "unavailable"
    return "enabled" if report.security.secure_boot else "disabled"


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
        [
            [check.title, check.status, check.detail, check.fix if check.status != "pass" else "—"]
            for check in report.checks
        ],
    )
    lines += ["", "## System", ""]
    os_info = report.os
    uptime = units.format_days(report.uptime_seconds // 86400) if report.uptime_seconds is not None else "unknown"
    lines += _table(
        ["Field", "Value"],
        [
            ["OS", f"{os_info.name} {os_info.edition}"],
            ["Build", os_info.build],
            ["Architecture", os_info.architecture],
            ["Uptime", uptime],
        ],
    )
    if report.cpu:
        lines += [
            "",
            "## CPU",
            "",
            f"{report.cpu.name} ({report.cpu.cores}C/{report.cpu.logical}T @ {report.cpu.max_mhz} MHz)",
        ]
    if report.memory and report.memory.total_bytes:
        lines += ["", "## Memory", ""]
        lines += _table(
            ["Module", "Capacity", "Speed", "Manufacturer"],
            [
                [
                    f"#{index + 1}",
                    units.format_bytes(module.capacity_bytes),
                    f"{module.speed_mhz} MHz",
                    module.manufacturer,
                ]
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
            ["Secure Boot", _secure_boot_label(report)],
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
