from __future__ import annotations

from pathlib import Path

from scanner.advisories import lookup_vulnerabilities
from scanner.dependencies import analyze_path_dependencies


FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def test_lookup_vulnerabilities_uses_local_advisory_database() -> None:
    dependencies, _, _ = analyze_path_dependencies(str(FIXTURE_ROOT / "sample_project"))

    findings, warnings = lookup_vulnerabilities(
        dependencies=dependencies,
        advisory_db_path=str(FIXTURE_ROOT / "sample_advisories.json"),
        offline=True,
        timeout=5,
    )

    assert warnings == []
    assert len(findings) == 2
    assert findings[0].severity == "HIGH"
    assert {finding.package for finding in findings} == {"lodash", "requests"}
