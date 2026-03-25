from __future__ import annotations

from scanner.models import RiskIssue, VulnerabilityFinding
from utils.helpers import normalize_severity, score_to_level


VULNERABILITY_WEIGHTS = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 4,
    "UNKNOWN": 8,
}

ISSUE_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "UNKNOWN": 5,
}


def build_risk_summary(
    *,
    vulnerabilities: list[VulnerabilityFinding],
    issues: list[RiskIssue],
) -> dict[str, int | str]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
        "vulnerability_total": len(vulnerabilities),
        "issue_total": len(issues),
    }

    score = 0
    for vulnerability in vulnerabilities:
        severity = normalize_severity(vulnerability.severity)
        counts[severity.lower()] += 1
        score += VULNERABILITY_WEIGHTS[severity]

    for issue in issues:
        severity = normalize_severity(issue.severity)
        counts[severity.lower()] += 1
        score += ISSUE_WEIGHTS[severity]

    bounded_score = min(score, 100)
    counts["score"] = bounded_score
    counts["level"] = score_to_level(bounded_score)
    return counts
