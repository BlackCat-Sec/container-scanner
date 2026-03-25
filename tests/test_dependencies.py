from __future__ import annotations

from pathlib import Path

from scanner.dependencies import analyze_path_dependencies, analyze_sbom_dependencies


FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def test_analyze_path_dependencies_finds_multiple_ecosystems() -> None:
    dependencies, issues, warnings = analyze_path_dependencies(str(FIXTURE_ROOT / "sample_project"))

    assert warnings == []
    names = {(dependency.ecosystem, dependency.name, dependency.version) for dependency in dependencies}
    assert ("PyPI", "requests", "2.19.0") in names
    assert ("npm", "lodash", "4.17.20") in names
    assert any(issue.rule_id == "CS-DEP-002" for issue in issues)


def test_analyze_sbom_dependencies_reads_cyclonedx_components() -> None:
    dependencies, issues, warnings = analyze_sbom_dependencies(str(FIXTURE_ROOT / "sample_sbom_cyclonedx.json"))

    assert warnings == []
    assert issues == []
    assert len(dependencies) == 2
    assert dependencies[0].source == "sbom"
