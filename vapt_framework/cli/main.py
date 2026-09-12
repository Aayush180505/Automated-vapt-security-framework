"""CLI: target validation, recon, assessment, and optional MySQL history.

This command-line interface does not perform exploitation.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from vapt_framework import __app_name__, __version__
from vapt_framework.cli.output import (
    format_assessment_errors,
    format_attack_surfaces,
    format_discovery_summary,
    format_findings,
    format_history,
    format_http_services,
    format_persistence,
    format_scan_details,
)
from vapt_framework.config.settings import Settings
from vapt_framework.core.exceptions import TargetValidationError, VAPTFrameworkError
from vapt_framework.core.target import parse_target
from vapt_framework.recon.engine import require_nmap, run_scan
from vapt_framework.reporting.service import ReportService
from vapt_framework.storage.service import ScanStorageService, persist_scan
from vapt_framework.utils.logging import configure_logging, get_logger

AUTHORIZATION_WARNING = (
    "WARNING:\n"
    "Only scan systems you are explicitly authorized to assess.\n"
    "This tool is for local labs, CTFs, HTB/Academy, and other systems\n"
    "where you have written permission. Do not use it for unauthorized testing."
)

SEPARATOR = "=" * 50


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="vapt_framework.cli.main",
        description=(
            f"{__app_name__} - authorized security assessment orchestration. "
            "Phase 8 validates targets, assesses them, scores findings, "
            "optionally stores scan history, and renders HTML reports."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Validate a target, enumerate services, and run security assessments.",
    )
    scan_parser.add_argument(
        "--target",
        required=True,
        help="Authorized target URL, hostname, or IP address.",
    )
    scan_parser.add_argument(
        "--report",
        action="store_true",
        help="Write an HTML report from this scan's completed results (does not rescan).",
    )

    db_parser = subparsers.add_parser("db", help="Database maintenance commands.")
    db_sub = db_parser.add_subparsers(dest="db_command")
    db_sub.add_parser("init", help="Create MySQL tables for scan history.")

    history_parser = subparsers.add_parser(
        "history", help="List recent persisted scans."
    )
    history_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of scans to list (default 20).",
    )

    show_parser = subparsers.add_parser(
        "show", help="Display a persisted scan by ID."
    )
    show_parser.add_argument("scan_id", help="UUID of a saved scan.")

    report_parser = subparsers.add_parser(
        "report", help="Generate an HTML report from a stored scan."
    )
    report_parser.add_argument("scan_id", help="UUID of a saved scan.")
    report_parser.add_argument(
        "--format",
        choices=("html",),
        default="html",
        help="Output format. HTML is supported. PDF is not implemented.",
    )

    subparsers.add_parser("version", help="Print the framework version.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        if exc.code in (0, None):
            return 0
        return int(exc.code) if isinstance(exc.code, int) else 2

    if args.command is None:
        parser.print_help()
        return 0

    try:
        settings = Settings.from_env()
        configure_logging(settings.log_level)
        if args.command == "version":
            return _cmd_version()
        if args.command == "scan":
            return _cmd_scan(args.target, settings, generate_report=args.report)
        if args.command == "db":
            if getattr(args, "db_command", None) != "init":
                print("usage: python -m vapt_framework.cli.main db init")
                return 0
            return _cmd_db_init(settings)
        if args.command == "history":
            limit = args.limit if args.limit and args.limit > 0 else 20
            return _cmd_history(settings, limit)
        if args.command == "show":
            return _cmd_show(settings, args.scan_id)
        if args.command == "report":
            return _cmd_report(settings, args.scan_id)
        parser.print_help()
        return 1
    except TargetValidationError as exc:
        print(f"Error: Invalid target: {exc}", file=sys.stderr)
        return 2
    except VAPTFrameworkError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


def _cmd_version() -> int:
    print(__version__)
    return 0


def _cmd_scan(raw_target: str, settings: Settings, *, generate_report: bool = False) -> int:
    logger = get_logger("vapt_framework.cli")
    print(SEPARATOR, flush=True)
    print(__app_name__, flush=True)
    print(SEPARATOR, flush=True)
    print(flush=True)
    print(AUTHORIZATION_WARNING, flush=True)
    print(flush=True)

    print("[INFO] Validating target...", flush=True)
    logger.info("Starting scan")
    target = parse_target(raw_target)
    print("[INFO] Target accepted.", flush=True)
    print(f"[INFO] Normalized target: {target.normalized}", flush=True)
    logger.info("Target accepted: %s", target.normalized)

    print("[INFO] Checking Nmap...", flush=True)
    require_nmap()
    print("[INFO] Nmap found.", flush=True)
    print("[INFO] Starting service discovery...", flush=True)

    context = run_scan(target, settings)
    discovery = context.discovery_results
    if discovery is None:
        print("Error: Service discovery produced no results.", file=sys.stderr)
        return 2

    print(flush=True)
    print(format_discovery_summary(discovery, target.normalized), flush=True)
    print(flush=True)
    print("[INFO] Detecting HTTP/HTTPS services...", flush=True)
    print(format_http_services(context.http_services), flush=True)
    print(flush=True)
    print("[INFO] Enumerating web attack surface...", flush=True)
    print(format_attack_surfaces(context.web_attack_surfaces), flush=True)
    print(flush=True)
    print("[INFO] Running security assessment plugins...", flush=True)
    print(
        format_findings(
            context.findings,
            executed=context.executed_plugins,
            skipped=context.skipped_plugins,
            active_requests=context.active_requests,
            errors=context.assessment_errors,
            active_enabled=settings.enable_active_scanners,
            summary=context.assessment_summary,
        ),
        flush=True,
    )
    errors = format_assessment_errors(context.assessment_errors)
    if errors:
        print(flush=True)
        print(errors, flush=True)

    outcome = persist_scan(context, settings)
    print(format_persistence(outcome), flush=True)
    if context.assessment_summary is not None:
        print(f"Findings: {context.assessment_summary.total_findings}", flush=True)
        print(
            f"Risk score: {context.assessment_summary.maximum_risk:.1f}",
            flush=True,
        )

    print(flush=True)
    print("Reconnaissance complete.", flush=True)
    if generate_report:
        path = ReportService(settings).write_from_context(context)
        print(flush=True)
        print("Report generated successfully.", flush=True)
        print("Scan ID:", flush=True)
        print(context.scan_id, flush=True)
        print("Output:", flush=True)
        print(path.as_posix(), flush=True)
    logger.info("Reconnaissance complete")
    return 0


def _cmd_db_init(settings: Settings) -> int:
    with ScanStorageService.from_settings(settings) as store:
        store.initialize()
    print("Database schema initialized.")
    return 0


def _cmd_history(settings: Settings, limit: int) -> int:
    with ScanStorageService.from_settings(settings) as store:
        items = store.list_scans(limit=limit)
    print(format_history(items))
    return 0


def _cmd_show(settings: Settings, scan_id: str) -> int:
    with ScanStorageService.from_settings(settings) as store:
        details = store.get_scan(scan_id)
    if details is None:
        print("Error: Scan not found.", file=sys.stderr)
        return 2
    print(format_scan_details(details))
    return 0


def _cmd_report(settings: Settings, scan_id: str) -> int:
    with ScanStorageService.from_settings(settings) as store:
        path = ReportService(settings).write_from_scan_id(scan_id, store)
    print("Report generated successfully.")
    print("Scan ID:")
    print(scan_id)
    print("Output:")
    print(path.as_posix())
    return 0


if __name__ == "__main__":
    sys.exit(main())
