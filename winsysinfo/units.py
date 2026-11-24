"""Human-readable byte and percentage formatting."""

from __future__ import annotations

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def format_bytes(value: int) -> str:
    if value <= 0:
        return "0B"
    size = float(value)
    unit = _UNITS[0]
    for unit in _UNITS:
        if size < 1024 or unit == _UNITS[-1]:
            break
        size /= 1024
    if unit == "B":
        return f"{int(size)}B"
    return f"{size:.1f}{unit}"


def percent_used(total: int, free: int) -> float:
    if total <= 0:
        return 0.0
    return round((total - free) / total * 100, 1)


def format_days(value: int) -> str:
    return f"{value} day" if value == 1 else f"{value} days"
