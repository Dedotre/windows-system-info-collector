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
