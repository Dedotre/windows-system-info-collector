"""Rule-based health checks. Each rule emits at most one Check."""

from __future__ import annotations

import datetime as dt

from winsysinfo import models, units

GB = 1024**3
DEDUCTIONS = {"fail": 20, "warn": 8, "info": 0, "pass": 0}


def _today() -> dt.date:
    return dt.date.today()


def _check(check_id: str, status: str, title: str, detail: str, fix: str) -> models.Check:
    return models.Check(id=check_id, status=status, title=title, detail=detail, fix=fix)


def _disk_check(report: models.SystemReport) -> models.Check | None:
    if not report.disks:
        return None
    worst = max(report.disks, key=lambda disk: disk.percent_used)
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
    return _check(
        "disk_space",
        status,
        "Disk space",
        detail,
        "Free at least 10% of the drive (Disk Cleanup or Storage Sense).",
    )


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
            return _check(
                "tpm",
                "fail",
                "TPM",
                "No TPM detected on Windows 11",
                "Enable firmware TPM (fTPM/PTT) in UEFI settings.",
            )
        return _check("tpm", "warn", "TPM", "No TPM detected", "Enable firmware TPM in UEFI settings.")
    if tpm.version and tpm.version.startswith("1."):
        return _check(
            "tpm",
            "warn",
            "TPM",
            f"TPM {tpm.version} detected",
            "TPM 2.0 is required by Windows 11; update firmware if possible.",
        )
    detail = f"TPM {tpm.version} ({tpm.status})" if tpm.version else "TPM present, details unavailable"
    return _check("tpm", "pass", "TPM", detail, "No action needed.")


def _secure_boot_check(report: models.SystemReport) -> models.Check | None:
    if report.security.secure_boot is True:
        return _check("secure_boot", "pass", "Secure Boot", "Enabled", "No action needed.")
    if report.security.secure_boot is False:
        return _check("secure_boot", "warn", "Secure Boot", "Disabled", "Enable Secure Boot in UEFI settings.")
    reason = report.security.secure_boot_reason or "not reported"
    return _check(
        "secure_boot",
        "info",
        "Secure Boot",
        f"Status unavailable ({reason})",
        "Run elevated to confirm Secure Boot state.",
    )


def _defender_av_check(report: models.SystemReport) -> models.Check | None:
    defender = report.security.defender
    if defender.av_enabled is None:
        return None
    if defender.av_enabled:
        return _check("defender_av", "pass", "Antivirus", "Windows Defender antivirus enabled", "No action needed.")
    return _check(
        "defender_av",
        "fail",
        "Antivirus",
        "Antivirus is disabled",
        "Enable Microsoft Defender or another antivirus.",
    )


def _defender_realtime_check(report: models.SystemReport) -> models.Check | None:
    defender = report.security.defender
    if defender.av_enabled is not True or defender.realtime_enabled is None:
        return None
    if defender.realtime_enabled:
        return _check("defender_realtime", "pass", "Real-time protection", "Enabled", "No action needed.")
    return _check(
        "defender_realtime",
        "fail",
        "Real-time protection",
        "Disabled",
        "Turn on real-time protection in Windows Security.",
    )


def _defender_signature_check(report: models.SystemReport) -> models.Check | None:
    age = report.security.defender.signature_age_days
    if age is None:
        return None
    if age > 7:
        return _check(
            "defender_signatures",
            "warn",
            "Virus definitions",
            f"{age} days old",
            "Run Windows Update to refresh definitions.",
        )
    return _check("defender_signatures", "pass", "Virus definitions", f"{age} days old", "No action needed.")


def _hotfix_check(report: models.SystemReport) -> models.Check | None:
    newest = report.hotfixes.newest_date
    if newest is None:
        return _check(
            "hotfix_age",
            "info",
            "Updates",
            "Newest hotfix date unknown",
            "Run Windows Update to confirm patching.",
        )
    try:
        installed = dt.date.fromisoformat(newest)
    except ValueError:
        return _check(
            "hotfix_age",
            "info",
            "Updates",
            f"Unparsed hotfix date {newest}",
            "Run Windows Update to confirm patching.",
        )
    age_days = (_today() - installed).days
    if age_days > 60:
        return _check("hotfix_age", "warn", "Updates", f"Newest hotfix is {age_days} days old", "Run Windows Update.")
    return _check("hotfix_age", "pass", "Updates", f"Newest hotfix is {age_days} days old", "No action needed.")


def _bitlocker_check(report: models.SystemReport) -> models.Check | None:
    info = report.security.bitlocker
    if info.protection is None:
        return _check(
            "bitlocker",
            "info",
            "BitLocker",
            "Status unavailable",
            "Run as administrator to check BitLocker status.",
        )
    if info.protection == "On":
        return _check(
            "bitlocker",
            "pass",
            "BitLocker",
            f"System volume protected ({info.volume_status})",
            "No action needed.",
        )
    return _check(
        "bitlocker",
        "info",
        "BitLocker",
        f"System volume not protected ({info.protection})",
        "Consider enabling BitLocker for at-rest encryption.",
    )


def _uptime_check(report: models.SystemReport) -> models.Check | None:
    if report.uptime_seconds is None:
        return None
    days = report.uptime_seconds // 86400
    if days > 30:
        return _check(
            "uptime",
            "info",
            "Uptime",
            f"{units.format_days(days)} since last boot",
            "Restart to apply pending updates.",
        )
    return _check("uptime", "pass", "Uptime", f"{units.format_days(days)} since last boot", "No action needed.")


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
