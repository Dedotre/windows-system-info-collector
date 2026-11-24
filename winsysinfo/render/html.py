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
.score { display: inline-block; padding: .25rem .75rem; border-radius: 999px;
  background: #e8f5e9; color: #1b5e20; font-weight: 600; }
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


def _secure_boot_label(report: SystemReport) -> str:
    if report.security.secure_boot is None:
        return "unavailable"
    return "enabled" if report.security.secure_boot else "disabled"


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
        f'<p><span class="score {level}">{report.health_score}/100</span> {fails} failing, {warns} warning(s)</p>',
    ]
    if report.redacted:
        parts.append(
            '<p class="note">Identity fields are redacted. '
            "Re-run with <code>--include-sensitive</code> for full details.</p>"
        )
    parts.append("<h2>Checks</h2>")
    parts.append(
        _table(
            ["Check", "Status", "Detail", "Fix"],
            [
                [check.title, check.status, check.detail, check.fix if check.status != "pass" else "—"]
                for check in report.checks
            ],
            [check.status for check in report.checks],
        )
    )
    os_info = report.os
    uptime = units.format_days(report.uptime_seconds // 86400) if report.uptime_seconds is not None else "unknown"
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
                ["Uptime", uptime],
            ],
        )
    )
    if report.cpu:
        parts.append("<h2>CPU</h2>")
        cpu = report.cpu
        parts.append(f"<p>{_esc(cpu.name)} — {cpu.cores}C/{cpu.logical}T @ {cpu.max_mhz} MHz</p>")
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
                ["Secure Boot", _secure_boot_label(report)],
                ["Defender AV", "unknown" if defender.av_enabled is None else ("on" if defender.av_enabled else "off")],
                ["BitLocker", bitlocker.protection or "unavailable"],
            ],
        )
    )
    parts.append("<h2>Updates</h2>")
    if report.hotfixes.ids:
        newest = report.hotfixes.newest_date or "unknown"
        parts.append(f"<p>{report.hotfixes.count} hotfixes installed; newest: {_esc(newest)}</p>")
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
