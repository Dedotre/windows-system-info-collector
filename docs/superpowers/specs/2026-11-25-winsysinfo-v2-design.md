# Windows System Info Collector v2 — Design

Date: 2026-11-25
Status: Draft for review
Branch: `v2-rebuild`

## Problem

The current tool is a single 317-line script. Verified on a Windows 11 26200 machine:

- Hotfix collection is broken: `wmic` is absent on Win11 24H2+, and the `wmic /format:csv` parser reads the hostname column instead of `HotFixID` (L165–182).
- TPM details never resolve: `Get-WmiObject` is unavailable under PowerShell 7, and `Win32_Tpm` returns `Access denied` without elevation (L136–157). Output degrades to `N/A vN/A (Present)`.
- Gateway parsing matches the English literal `Default Gateway` in `ipconfig`, so it fails on localized Windows; `subprocess.run(text=True)` decodes OEM output with the wrong codec (L232–246).
- ~8 bare `except:` blocks convert every defect into "Unknown"/"N/A", so failures are indistinguishable from absence.
- Output goes to `os.getcwd()`, which is read-only or System32 under Task Scheduler and packaged executables.
- Five sequential PowerShell/WMIC spawns cost ~2 s per run.
- No package structure, types, tests, CI, or machine-readable output.

## Goals

1. Correct facts on a stock, non-elevated Windows 11/10 machine, independent of system locale.
2. Machine-readable JSON with a versioned schema, plus human renderers (text, Markdown, HTML).
3. A rule-based health assessment (checks + 0–100 score) so a report answers "is anything wrong?".
4. Privacy-safe output by default; sensitive fields require explicit opt-in.
5. Engineering baseline: zero runtime dependencies, fully typed, pytest suite with fixtures, lint + type check + tests on Windows CI.

## Non-Goals

- Cross-platform support (Windows only; non-Windows exits with code 2).
- GUI/tray app, remote/multi-host inventory, SQLite history, packaged `.exe` (deferred; see Open Questions).
- Live hardware sensors (temperature, fan RPM) — requires vendor SDKs.

## Architecture

Zero runtime dependencies (stdlib only). Flat package layout at the repo root so `python -m winsysinfo` works directly from a clone without installation, preserving the double-click `.bat` UX.

```
windows-system-info-collector/
  winsysinfo/
    __init__.py          # __version__, schema version
    __main__.py          # python -m winsysinfo -> cli.main()
    cli.py               # argparse, orchestration, exit codes, file writing
    probe.py             # one batched PowerShell CIM call -> parsed dict
    collect.py           # probe data + stdlib facts -> SystemReport
    models.py            # frozen dataclasses + to_dict()
    health.py            # rules -> checks + score
    redact.py            # default redaction of sensitive fields
    units.py             # format_bytes
    render/
      __init__.py        # format dispatch
      text.py
      json_report.py
      markdown.py
      html.py
  tests/
    fixtures/ps_raw.json           # captured probe output
    fixtures/sample_report.json    # canonical report used by renderer tests
    test_units.py
    test_probe.py
    test_health.py
    test_redact.py
    test_render.py
    test_cli.py
  .github/workflows/ci.yml
  pyproject.toml
  run_system_info_collector.bat   # now runs `python -m winsysinfo`
  windows_system_info_collector.py  # REMOVED
  README.md                       # rewritten
```

Module contracts:

- `probe.collect_raw(timeout=60) -> ProbeResult(data: dict, error: str | None)`. Runs exactly one `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <script>`; the script sets console output encoding to UTF-8, wraps each section in `try/catch`, emits a single hashtable via `ConvertTo-Json -Depth 6 -Compress`. Parse with `json.loads` after stripping a UTF-8 BOM. Never raises; failures land in `ProbeResult.error` and in `SystemReport.errors`.
- `collect.build_report(raw: dict) -> SystemReport`. Uses stdlib (`platform`, `socket`, `ctypes` disk fallback) for OS/hostname and as a fallback for disks if the probe produced none. Pure function over its inputs; no I/O. Redaction is applied afterwards by `redact.apply`.
- `health.evaluate(report) -> (checks: list[Check], score: int)`.
- `redact.apply(report) -> SystemReport` (mutates a copy; sets `redacted=True`).
- `render.render(report, fmt: str) -> str` for `text|json|md|html`.

## Data Model

`SystemReport` fields (all `dataclass(frozen=True)` where practical):

| Field | Type | Source |
|---|---|---|
| `schema_version` | `"1.0"` | constant |
| `generated_at` | ISO-8601 local time | `datetime` |
| `hostname` | str | `socket.gethostname()` |
| `os` | `OsInfo(name, release, build, edition, architecture, install_date: str \| None)` | `platform` + CIM `Win32_OperatingSystem` |
| `cpu` | `CpuInfo(name, cores, logical, max_mhz)` | `Win32_Processor` |
| `memory` | `MemoryInfo(total_bytes, free_bytes, modules[])` | `Win32_OperatingSystem`, `Win32_PhysicalMemory` |
| `gpus` | `list[GpuInfo(name, vram_bytes, driver)]` | `Win32_VideoController` |
| `disks` | `list[DiskInfo(mount, filesystem, total_bytes, free_bytes, percent_used)]` | `Win32_LogicalDisk` (DriveType=3), `ctypes` fallback |
| `network` | `NetworkInfo(adapters[])` where adapter = `(name, ipv4[], gateway[], mac, dhcp)` | `Win32_NetworkAdapterConfiguration` |
| `bios` | `BiosInfo(vendor, version, release_date, serial)` | `Win32_BIOS` + `Win32_BaseBoard` |
| `security` | `SecurityInfo(tpm, secure_boot, defender, bitlocker)` | CIM + cmdlets (see below) |
| `hotfixes` | `HotfixInfo(count, newest_date, ids[])` | `Win32_QuickFixEngineering` |
| `battery` | `BatteryInfo(percent, charging) \| None` | `Win32_Battery` |
| `uptime_seconds` | int | `LastBootUpTime` |
| `checks` | `list[Check(id, status, title, detail, fix)]` | `health` |
| `health_score` | int 0–100 | `health` |
| `redacted` | bool | `redact` |
| `errors` | `list[str]` | probe/collector failures |

JSON shape mirrors field names, `null` for unavailable values, never omits keys. `"checks"` uses `status ∈ {pass, warn, fail, info}`.

## Probe Design

One PowerShell script; per-section `try { … } catch { $null }` so one denied section (TPM/BitLocker without admin) cannot kill the others. Confirmed on the target machine:

- `wmic` → missing (so remove it entirely).
- `Get-CimInstance Win32_QuickFixEngineering` → 4 items (works non-elevated).
- `Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm Win32_Tpm` → `Access denied` non-elevated → TPM details are `null`, `present` inferred from registry key `HKLM\SYSTEM\CurrentControlSet\Services\TPM`.
- `Confirm-SecureBootUEFI` throws on legacy BIOS → `null`.
- `Get-MpComputerStatus` may be absent (Server / third-party AV) → `null`.
- `Get-BitLockerVolume` may require elevation → `null`.
- `Get-CimInstance Win32_Battery` → `null` on desktops.

Fallbacks are represented explicitly: `{"available": false, "reason": "requires admin"}` rather than a bare null, so the text renderer can print `TPM: unavailable (requires admin)` instead of `N/A vN/A`.

## Health Rules

Statuses deduct points; each rule emits at most one check, floor at 0, cap at 100. Rule order is stable for deterministic output. "Win11" means OS build ≥ 22000.

| id | Condition | Status | Points |
|---|---|---|---|
| `disk_space` | any fixed disk < 5% free | fail | −20 |
| | any fixed disk < 10% free | warn | −8 |
| `defender_av` | AV disabled | fail | −20 |
| `defender_realtime` | real-time protection off (when Defender present) | fail | −20 |
| `defender_signatures` | signature age > 7 days | warn | −8 |
| `secure_boot` | Secure Boot off / unsupported | warn | −8 |
| `tpm` | Win11 and TPM absent | fail | −20 |
| | TPM present, version < 2.0 | warn | −8 |
| `ram` | total < 4 GB | fail | −20 |
| | total < 8 GB | warn | −8 |
| `hotfix_age` | newest hotfix older than 60 days | warn | −8 |
| `bitlocker` | system volume not protected | info | 0 |
| `uptime` | > 30 days | info | 0 |

Every check carries a one-line `fix` (e.g. "Free at least 10% of C:, run Disk Cleanup or Storage Sense."). Unavailable facts produce no check rather than a fail.

## Redaction (default on)

| Field | Default output |
|---|---|
| `hostname` | `REDACTED-HOST` |
| BIOS/board serial | `REDACTED-SERIAL` |
| adapter MAC | `XX:XX:XX:XX:XX:XX` |
| IPv4 | last octet replaced with `.0` (e.g. `192.168.0.11` → `192.168.0.0`) |
| RAM part numbers | kept (not identifying) |
| hotfix IDs, OS/CPU/GPU names, disk sizes | kept |

`--include-sensitive` bypasses redaction entirely and sets `"redacted": false` in JSON. Text/HTML/Markdown renderers show a one-line notice when redaction is active.

## Renderers

- **text** — existing section style, preceded by a health banner: `Health: 82/100 — 2 warnings, 1 info`. Unavailable facts print `(unavailable: <reason>)`.
- **json** — `json.dumps(asdict, indent=2, ensure_ascii=False)`; key order fixed by model definition.
- **md** — headline + checks table + one table per section.
- **html** — single self-contained file, inline CSS, `prefers-color-scheme`, no external assets; score badge, checks table, facts tables.

## CLI

```
winsysinfo [--format text,json,md,html] [--out DIR] [--include-sensitive]
           [-q/--quiet] [--verbose] [--version]
```

- Default: `--format text --out .`; files named `system_info_report_YYYYmmdd_HHMMSS.<ext>`.
- Report is printed to stdout unless `-q`.
- `-q` still prints the saved paths to stderr.
- Exit codes: `0` success; `1` completed with `report.errors`; `2` fatal (non-Windows, probe produced nothing parseable).
- Pause on "Press Enter to exit" only when `len(sys.argv) == 1 and sys.stdin.isatty()` (preserves double-click behavior).
- Non-Windows: print a clear message to stderr, exit 2.

## Error Handling

- No bare `except:`. Catch `subprocess.TimeoutExpired`, `OSError`, `ValueError`, `json.JSONDecodeError` specifically.
- Collector failures append `"<section>: <error>"` to `report.errors` and render `(unavailable: …)`; the run continues.
- `--verbose` prints `report.errors` and probe stderr to stderr.
- File writes: create `--out` directory, `OSError` exits 2 with the path in the message.

## Testing

- `test_units.py` — `format_bytes` boundaries (0, 1023, 1024, TB, rounding).
- `test_probe.py` — parse `fixtures/ps_raw.json`: missing keys, `null` sections, BOM stripped, malformed JSON → error result.
- `test_health.py` — table-driven: each rule at/over its threshold, combined score with floor, unavailable facts produce no check.
- `test_redact.py` — each sensitive field masked; `--include-sensitive` round-trip unchanged.
- `test_render.py` — golden comparison for text/md/json against `sample_report.json`; HTML contains score and check rows.
- `test_cli.py` — monkeypatched probe; `--format json` writes a valid file to `tmp_path`; exit codes 0/1/2.

All tests OS-independent (no live PowerShell); the live probe is exercised by a `--self-check` manual step documented in README, and by CI smoke run on `windows-latest` that only asserts exit code 0.

## CI

`.github/workflows/ci.yml` on push/PR, `windows-latest`, Python 3.11 + 3.13: `pip install -e .[dev]`, `ruff check`, `ruff format --check`, `mypy winsysinfo`, `pytest --cov=winsysinfo --cov-fail-under=85`, then a smoke run `python -m winsysinfo -q --format json --out smoke/` asserting exit 0 and a parseable report.

## Packaging

`pyproject.toml` (setuptools, `requires-python >=3.11`, `dependencies = []`, extras `dev = [pytest, pytest-cov, ruff, mypy]`, console script `winsysinfo = winsysinfo.cli:main`). README documents both `pipx install .` and double-click `.bat`.

## Risks / Mitigations

| Risk | Mitigation |
|---|---|
| CIM blocked by policy on some machines | stdlib falls back for OS/hostname/disks; report still renders with `errors` |
| PowerShell 7 only (no 5.1) | script uses cmdlets available in both; `Get-MpComputerStatus`/`Confirm-SecureBootUEFI` are wrapped |
| Localized Windows | no output-string parsing anywhere; all facts come from CIM JSON |
| Default redaction surprises existing users | README top-line note + `--include-sensitive`; JSON says `redacted: true` |
| Removing `windows_system_info_collector.py` breaks old bookmarks | README migration note; `.bat` updated; single commit, revertable |

## Open Questions (deferred, not in v2)

- CI-built single-file `.exe` via PyInstaller (nice for non-Python users).
- SQLite history / `--watch` trend mode.
- `--diff` between two JSON reports.
