"""Command-line entry point."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import sys
from collections.abc import Sequence
from pathlib import Path

from winsysinfo import __version__, collect, health, probe, redact
from winsysinfo import render as render_pkg


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="winsysinfo",
        description="Collect Windows system information, score its health and write a report.",
    )
    parser.add_argument(
        "--format",
        default="text",
        help="Comma-separated output formats: text,json,md,html (default: text)",
    )
    parser.add_argument("--out", default=".", help="Directory for report files (default: current directory)")
    parser.add_argument(
        "--include-sensitive",
        action="store_true",
        help="Do not redact hostname, serials, MAC addresses and IPs",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Do not print the report to stdout")
    parser.add_argument("--verbose", action="store_true", help="Print collector warnings to stderr")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    formats = [item.strip() for item in args.format.split(",") if item.strip()]
    unknown = [item for item in formats if item not in render_pkg.EXTENSIONS]
    if not formats or unknown:
        return _fail(f"unknown format: {', '.join(unknown) or '(none)'} (choose from text, json, md, html)")
    if sys.platform != "win32":
        return _fail("winsysinfo only supports Windows")

    result = probe.run_probe()
    errors = (result.error,) if result.error else ()
    report = collect.build_report(result.data or {}, errors=errors)
    checks, score = health.evaluate(report)
    report = dataclasses.replace(report, checks=checks, health_score=score)
    if not args.include_sensitive:
        report = redact.apply(report)

    out_dir = Path(args.out)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return _fail(f"cannot create output directory {out_dir}: {exc}")

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    saved = []
    for fmt in formats:
        path = out_dir / f"system_info_report_{stamp}.{render_pkg.EXTENSIONS[fmt]}"
        try:
            path.write_text(render_pkg.render(report, fmt), encoding="utf-8")
        except OSError as exc:
            return _fail(f"cannot write {path}: {exc}")
        saved.append(path)

    if not args.quiet:
        print(render_pkg.render(report, formats[0] if len(formats) == 1 else "text"))
    for path in saved:
        print(f"Report saved to: {path.resolve()}", file=sys.stderr)
    if args.verbose and report.errors:
        print("Warnings:", file=sys.stderr)
        for error in report.errors:
            print(f"  {error}", file=sys.stderr)

    if argv is None and sys.stdin.isatty():
        with contextlib.suppress(EOFError, KeyboardInterrupt):
            input("\nPress Enter to exit...")

    return 1 if report.errors else 0
