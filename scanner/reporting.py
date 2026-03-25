from __future__ import annotations

from tabulate import tabulate

from scanner.models import ScanReport


def reports_to_json_payload(reports: list[ScanReport], failures: list[dict[str, str]]) -> dict[str, object]:
    payload: dict[str, object] = {"reports": [report.to_dict() for report in reports]}
    if failures:
        payload["failures"] = failures
    return payload


def render_text_report(reports: list[ScanReport], failures: list[dict[str, str]], *, max_findings: int) -> str:
    sections: list[str] = []

    for report in reports:
        summary = report.risk_summary
        sections.append(
            f"{report.target} | score {summary['score']} {summary['level']} | "
            f"deps {report.dependency_count} | vulns {summary['vulnerability_total']} | issues {summary['issue_total']}"
        )

        if report.vulnerabilities:
            vulnerability_rows = [
                [
                    finding.package,
                    finding.version or "-",
                    finding.vuln_id,
                    finding.severity,
                    ", ".join(finding.fix_versions[:2]) or "-",
                ]
                for finding in report.vulnerabilities[:max_findings]
            ]
            sections.append("Vulnerabilities:")
            sections.append(
                tabulate(
                    vulnerability_rows,
                    headers=["Package", "Version", "ID", "Severity", "Fix"],
                    tablefmt="github",
                )
            )

        if report.risk_issues:
            issue_rows = [
                [
                    issue.severity,
                    issue.rule_id,
                    issue.file_path or "-",
                    issue.line or "-",
                    issue.title,
                ]
                for issue in report.risk_issues[:max_findings]
            ]
            sections.append("Risk issues:")
            sections.append(
                tabulate(
                    issue_rows,
                    headers=["Severity", "Rule", "File", "Line", "Title"],
                    tablefmt="github",
                )
            )

        if report.warnings:
            sections.append("Warnings:")
            sections.extend(f"- {warning}" for warning in report.warnings)

    if failures:
        failure_rows = [[failure["target"], failure["error"]] for failure in failures]
        sections.append("Failures:")
        sections.append(tabulate(failure_rows, headers=["Target", "Error"], tablefmt="github"))

    return "\n\n".join(sections) if sections else "No scan results were produced."
