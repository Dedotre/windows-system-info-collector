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
