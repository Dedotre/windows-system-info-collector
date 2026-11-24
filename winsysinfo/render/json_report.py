"""Machine-readable JSON report."""

from __future__ import annotations

import json

from winsysinfo.models import SystemReport


def render(report: SystemReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
