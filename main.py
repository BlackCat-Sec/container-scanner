from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Sequence

from scanner.advisories import AdvisoryLookupError, lookup_vulnerabilities
from scanner.code_checks import scan_code_risks
from scanner.dependencies import analyze_path_dependencies, analyze_sbom_dependencies
from scanner.models import ScanReport
from scanner.reporting import render_text_report, reports_to_json_payload
from scanner.scoring import build_risk_summary
from scanner.sources import SourceResolutionError, cleanup_targets, collect_input_specs, resolve_target
from utils.helpers import utc_now_iso


LOGGER = logging.getLogger("container_scanner")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="container-scanner",
        description="Scan local source trees, Git repositories, and SBOM files for dependency and code risk.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="scan",
        choices=["scan"],
        help="Subcommand to run. Defaults to 'scan'.",
    )
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        help="Local file or directory to scan. Repeat for multiple targets.",
    )
    parser.add_argument(
        "--git-url",
        action="append",
        default=[],
        help="Git repository URL or local Git path to clone and scan. Repeat for multiple targets.",
    )
    parser.add_argument(
        "--sbom",
        action="append",
        default=[],
        help="CycloneDX or SPDX JSON SBOM file to scan. Repeat for multiple SBOMs.",
    )
    parser.add_argument(
        "--advisory-db",
        help="Path to a local advisory database JSON file. Useful for offline or deterministic scans.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Disable OSV API calls. Use with --advisory-db for air-gapped scans.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON output.",
    )
    parser.add_argument(
        "--api-timeout",
        type=int,
        default=15,
        help="Timeout in seconds for OSV API requests. Defaults to 15.",
    )
    parser.add_argument(
        "--git-timeout",
        type=int,
        default=120,
        help="Timeout in seconds for git clone operations. Defaults to 120.",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=10,
        help="Maximum number of vulnerability and code-risk rows to print per target. Defaults to 10.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity. Defaults to INFO.",
    )
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not any((args.path, args.git_url, args.sbom)):
        parser.error("Provide at least one of --path, --git-url, or --sbom.")
    if args.api_timeout <= 0:
        parser.error("--api-timeout must be a positive integer.")
    if args.git_timeout <= 0:
        parser.error("--git-timeout must be a positive integer.")
    if args.max_findings <= 0:
        parser.error("--max-findings must be a positive integer.")


def configure_logging(level_name: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level_name, logging.INFO),
        format="%(levelname)s: %(message)s",
    )


def scan_targets(args: argparse.Namespace) -> tuple[list[ScanReport], list[dict[str, str]]]:
    specs = collect_input_specs(paths=args.path, git_urls=args.git_url, sboms=args.sbom)
    reports: list[ScanReport] = []
    failures: list[dict[str, str]] = []
    resolved_targets = []

    try:
        for spec in specs:
            try:
                resolved_targets.append(resolve_target(spec, git_timeout=args.git_timeout))
            except SourceResolutionError as exc:
                failures.append({"target": spec.value, "error": str(exc)})

        for target in resolved_targets:
            LOGGER.info("Scanning %s", target.display_name)
            try:
                if target.source_kind == "sbom":
                    dependencies, dependency_issues, warnings = analyze_sbom_dependencies(target.sbom_path)
                    code_issues = []
                else:
                    dependencies, dependency_issues, warnings = analyze_path_dependencies(target.work_path)
                    code_issues = scan_code_risks(target.work_path)

                vulnerabilities, advisory_warnings = lookup_vulnerabilities(
                    dependencies=dependencies,
                    advisory_db_path=args.advisory_db,
                    offline=args.offline,
                    timeout=args.api_timeout,
                )
                all_issues = [*dependency_issues, *code_issues]
                risk_summary = build_risk_summary(vulnerabilities=vulnerabilities, issues=all_issues)

                reports.append(
                    ScanReport(
                        target=target.display_name,
                        source_kind=target.source_kind,
                        source=target.source,
                        scanned_at=utc_now_iso(),
                        dependency_count=len(dependencies),
                        dependencies=dependencies,
                        vulnerabilities=vulnerabilities,
                        risk_issues=all_issues,
                        risk_summary=risk_summary,
                        warnings=[*warnings, *advisory_warnings],
                    )
                )
            except (AdvisoryLookupError, ValueError) as exc:
                failures.append({"target": target.display_name, "error": str(exc)})
    finally:
        cleanup_targets(resolved_targets)

    return reports, failures


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    configure_logging(args.log_level)

    reports, failures = scan_targets(args)
    if args.json:
        print(json.dumps(reports_to_json_payload(reports, failures), indent=2))
    else:
        print(render_text_report(reports, failures, max_findings=args.max_findings))

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
