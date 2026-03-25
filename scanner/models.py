from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class InputSpec:
    kind: Literal["path", "git_url", "sbom"]
    value: str


@dataclass
class ScanTarget:
    source_kind: Literal["path", "git_url", "sbom"]
    source: str
    display_name: str
    work_path: str | None = None
    sbom_path: str | None = None
    cleanup_path: str | None = None


@dataclass
class Dependency:
    name: str
    version: str | None
    ecosystem: str | None
    manifest: str
    source: str
    direct: bool = True
    raw_spec: str | None = None
    purl: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "manifest": self.manifest,
            "source": self.source,
            "direct": self.direct,
            "raw_spec": self.raw_spec,
            "purl": self.purl,
        }


@dataclass
class VulnerabilityFinding:
    vuln_id: str
    aliases: list[str]
    package: str
    version: str | None
    ecosystem: str | None
    severity: str
    summary: str
    fix_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    advisory_source: str = "unknown"
    manifest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.vuln_id,
            "aliases": self.aliases,
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "severity": self.severity,
            "summary": self.summary,
            "fix_versions": self.fix_versions,
            "references": self.references,
            "advisory_source": self.advisory_source,
            "manifest": self.manifest,
        }


@dataclass
class RiskIssue:
    rule_id: str
    severity: str
    title: str
    message: str
    recommendation: str | None = None
    file_path: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "recommendation": self.recommendation,
            "file_path": self.file_path,
            "line": self.line,
        }


@dataclass
class ScanReport:
    target: str
    source_kind: str
    source: str
    scanned_at: str
    dependency_count: int
    dependencies: list[Dependency]
    vulnerabilities: list[VulnerabilityFinding]
    risk_issues: list[RiskIssue]
    risk_summary: dict[str, Any]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "source_kind": self.source_kind,
            "source": self.source,
            "scanned_at": self.scanned_at,
            "dependency_count": self.dependency_count,
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
            "vulnerabilities": [finding.to_dict() for finding in self.vulnerabilities],
            "risk_issues": [issue.to_dict() for issue in self.risk_issues],
            "risk_summary": self.risk_summary,
            "warnings": self.warnings,
        }
