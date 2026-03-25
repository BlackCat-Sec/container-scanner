from __future__ import annotations

import json
from pathlib import Path

import requests

from scanner.models import Dependency, VulnerabilityFinding
from utils.helpers import normalize_severity, severity_rank


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def lookup_vulnerabilities(
    *,
    dependencies: list[Dependency],
    advisory_db_path: str | None,
    offline: bool,
    timeout: int,
) -> tuple[list[VulnerabilityFinding], list[str]]:
    if not dependencies:
        return [], []

    if advisory_db_path:
        provider = LocalAdvisoryDatabase(advisory_db_path)
        return provider.query(dependencies), []

    if offline:
        return [], ["Offline mode enabled without a local advisory database. Vulnerability lookup was skipped."]

    try:
        provider = OsvAdvisoryClient(timeout=timeout)
        return provider.query(dependencies), []
    except AdvisoryLookupError as exc:
        return [], [str(exc)]


class AdvisoryLookupError(RuntimeError):
    """Raised when an advisory source cannot be queried."""


class LocalAdvisoryDatabase:
    def __init__(self, path: str) -> None:
        self.path = Path(path).resolve()
        if not self.path.exists():
            raise AdvisoryLookupError(f"Advisory database does not exist: {self.path}")
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        advisories = payload.get("advisories")
        if not isinstance(advisories, list):
            raise AdvisoryLookupError("Local advisory database must contain an 'advisories' list.")
        self._index: dict[tuple[str | None, str, str | None], list[dict[str, object]]] = {}
        for advisory in advisories:
            package = advisory.get("package", {})
            key = (
                _normalize_ecosystem(package.get("ecosystem")),
                str(package.get("name", "")).lower(),
                package.get("version"),
            )
            self._index.setdefault(key, []).append(advisory)

    def query(self, dependencies: list[Dependency]) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for dependency in dependencies:
            key = (_normalize_ecosystem(dependency.ecosystem), dependency.name.lower(), dependency.version)
            for advisory in self._index.get(key, []):
                findings.append(_build_local_finding(advisory, dependency))
        return _sort_findings(findings)


class OsvAdvisoryClient:
    def __init__(self, *, timeout: int) -> None:
        self.timeout = timeout

    def query(self, dependencies: list[Dependency]) -> list[VulnerabilityFinding]:
        queries = []
        dep_index: list[Dependency] = []
        for dependency in dependencies:
            ecosystem = _normalize_ecosystem(dependency.ecosystem)
            if not ecosystem or not dependency.version:
                continue
            queries.append(
                {
                    "package": {"name": dependency.name, "ecosystem": ecosystem},
                    "version": dependency.version,
                }
            )
            dep_index.append(dependency)

        if not queries:
            return []

        try:
            response = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=self.timeout)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise AdvisoryLookupError(f"OSV API lookup failed: {exc}") from exc

        payload = response.json()
        results = payload.get("results", [])
        findings: list[VulnerabilityFinding] = []
        for dependency, result in zip(dep_index, results):
            for vulnerability in result.get("vulns", []) or []:
                findings.append(_build_osv_finding(vulnerability, dependency))
        return _sort_findings(findings)


def _build_local_finding(advisory: dict[str, object], dependency: Dependency) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vuln_id=str(advisory.get("id", "UNKNOWN")),
        aliases=[str(item) for item in advisory.get("aliases", [])],
        package=dependency.name,
        version=dependency.version,
        ecosystem=dependency.ecosystem,
        severity=normalize_severity(str(advisory.get("severity", "UNKNOWN"))),
        summary=str(advisory.get("summary", "No summary provided.")),
        fix_versions=[str(item) for item in advisory.get("fix_versions", [])],
        references=[str(item) for item in advisory.get("references", [])],
        advisory_source=str(advisory.get("source", "local-advisory-db")),
        manifest=dependency.manifest,
    )


def _build_osv_finding(vulnerability: dict[str, object], dependency: Dependency) -> VulnerabilityFinding:
    database_specific = vulnerability.get("database_specific", {}) or {}
    severity = normalize_severity(str(database_specific.get("severity", "UNKNOWN")))
    references = [ref.get("url") for ref in vulnerability.get("references", []) or [] if ref.get("url")]
    return VulnerabilityFinding(
        vuln_id=str(vulnerability.get("id", "UNKNOWN")),
        aliases=[str(item) for item in vulnerability.get("aliases", []) or []],
        package=dependency.name,
        version=dependency.version,
        ecosystem=dependency.ecosystem,
        severity=severity,
        summary=str(vulnerability.get("summary", "No summary provided.")),
        fix_versions=_extract_fix_versions(vulnerability),
        references=[str(item) for item in references],
        advisory_source="osv",
        manifest=dependency.manifest,
    )


def _extract_fix_versions(vulnerability: dict[str, object]) -> list[str]:
    fixes: list[str] = []
    for affected in vulnerability.get("affected", []) or []:
        for range_item in affected.get("ranges", []) or []:
            for event in range_item.get("events", []) or []:
                fixed = event.get("fixed")
                if fixed and fixed not in fixes:
                    fixes.append(str(fixed))
    return fixes


def _normalize_ecosystem(ecosystem: object) -> str | None:
    if ecosystem is None:
        return None
    mapping = {
        "pypi": "PyPI",
        "npm": "npm",
    }
    normalized = str(ecosystem)
    return mapping.get(normalized.lower(), normalized)


def _sort_findings(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    return sorted(findings, key=lambda item: (severity_rank(item.severity), item.package, item.vuln_id))
