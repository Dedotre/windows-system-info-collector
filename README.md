# Windows System Info Collector (winsysinfo)

Collect Windows hardware/OS/security facts, get a 0–100 health score, and export a report as text, JSON, Markdown or a self-contained HTML page. No external dependencies — just Python 3.11+ and the PowerShell that ships with Windows.

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

## License

MIT
