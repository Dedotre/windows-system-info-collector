"""Report renderers. Each returns a complete document string."""

from __future__ import annotations

from winsysinfo.models import SystemReport
from winsysinfo.render import html, json_report, markdown, text

EXTENSIONS = {"text": "txt", "json": "json", "md": "md", "html": "html"}

_RENDERERS = {
    "text": text.render,
    "json": json_report.render,
    "md": markdown.render,
    "html": html.render,
}


def render(report: SystemReport, fmt: str) -> str:
    try:
        renderer = _RENDERERS[fmt]
    except KeyError as exc:
        raise ValueError(f"unknown report format: {fmt}") from exc
    return renderer(report)
