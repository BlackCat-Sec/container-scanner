from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from scanner.models import Dependency, RiskIssue
from utils.helpers import parse_name_and_version, should_skip_path


SUPPORTED_MANIFESTS = {
    "requirements.txt",
    "package-lock.json",
    "package.json",
    "pyproject.toml",
}


def analyze_path_dependencies(
    root_path: str | None,
) -> tuple[list[Dependency], list[RiskIssue], list[str]]:
    if root_path is None:
        raise ValueError("A path-based scan target must include a work path.")

    root = Path(root_path)
    if not root.exists():
        raise ValueError(f"Scan path does not exist: {root}")

    manifests = _discover_manifests(root)
    dependencies: list[Dependency] = []
    issues: list[RiskIssue] = []

    package_lock_dirs = {
        manifest.parent for manifest in manifests if manifest.name == "package-lock.json"
    }

    for manifest in manifests:
        if manifest.name == "requirements.txt":
            parsed_dependencies, parsed_issues = _parse_requirements_file(manifest)
        elif manifest.name == "pyproject.toml":
            parsed_dependencies, parsed_issues = _parse_pyproject_file(manifest)
        elif manifest.name == "package-lock.json":
            parsed_dependencies, parsed_issues = _parse_package_lock_file(manifest)
        elif manifest.name == "package.json":
            include_dependencies = manifest.parent not in package_lock_dirs
            parsed_dependencies, parsed_issues = _parse_package_json_file(
                manifest,
                include_dependencies=include_dependencies,
            )
        else:
            parsed_dependencies, parsed_issues = [], []
        dependencies.extend(parsed_dependencies)
        issues.extend(parsed_issues)

    dependencies = _deduplicate_dependencies(dependencies)
    warnings = [] if manifests else ["No supported dependency manifests were found under the supplied path."]
    return dependencies, issues, warnings


def analyze_sbom_dependencies(sbom_path: str | None) -> tuple[list[Dependency], list[RiskIssue], list[str]]:
    if sbom_path is None:
        raise ValueError("An SBOM scan target must include an SBOM path.")

    path = Path(sbom_path)
    if not path.exists():
        raise ValueError(f"SBOM file does not exist: {path}")

    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("bomFormat") == "CycloneDX":
        dependencies, issues = _parse_cyclonedx_sbom(path, payload)
        return _deduplicate_dependencies(dependencies), issues, []
    if payload.get("spdxVersion"):
        dependencies, issues = _parse_spdx_sbom(path, payload)
        return _deduplicate_dependencies(dependencies), issues, []
    raise ValueError("Unsupported SBOM format. Provide CycloneDX JSON or SPDX JSON.")


def _discover_manifests(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if root.name in SUPPORTED_MANIFESTS else []

    manifests: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file() and path.name in SUPPORTED_MANIFESTS and not should_skip_path(path):
            manifests.append(path)
    return sorted(manifests)


def _parse_requirements_file(path: Path) -> tuple[list[Dependency], list[RiskIssue]]:
    dependencies: list[Dependency] = []
    issues: list[RiskIssue] = []

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith("-"):
            continue
        name, version, pinned = parse_name_and_version(stripped)
        if not name:
            continue
        dependencies.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="PyPI",
                manifest=str(path),
                source="requirements.txt",
                raw_spec=stripped,
            )
        )
        if not pinned:
            issues.append(
                RiskIssue(
                    rule_id="CS-DEP-001",
                    severity="MEDIUM",
                    title="Unpinned Python dependency",
                    message=f"{name} in {path.name} is not pinned to an exact version.",
                    recommendation="Use == pins for reproducible builds and deterministic vulnerability lookups.",
                    file_path=str(path),
                    line=line_number,
                )
            )
    return dependencies, issues


def _parse_pyproject_file(path: Path) -> tuple[list[Dependency], list[RiskIssue]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    dependencies: list[Dependency] = []
    issues: list[RiskIssue] = []

    project_deps = data.get("project", {}).get("dependencies", [])
    for dependency in project_deps:
        parsed_dependencies, parsed_issues = _dependency_from_string_spec(path, dependency, ecosystem="PyPI")
        dependencies.extend(parsed_dependencies)
        issues.extend(parsed_issues)

    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry_deps.items():
        if name.lower() == "python":
            continue
        parsed_dependencies, parsed_issues = _dependency_from_poetry_spec(path, name, spec)
        dependencies.extend(parsed_dependencies)
        issues.extend(parsed_issues)

    return dependencies, issues


def _parse_package_lock_file(path: Path) -> tuple[list[Dependency], list[RiskIssue]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    dependencies: list[Dependency] = []

    packages = payload.get("packages")
    if isinstance(packages, dict):
        for package_path, package_data in packages.items():
            if not package_path or "node_modules/" not in package_path:
                continue
            name = package_data.get("name") or package_path.split("node_modules/", 1)[1]
            version = package_data.get("version")
            if name and version:
                dependencies.append(
                    Dependency(
                        name=str(name),
                        version=str(version),
                        ecosystem="npm",
                        manifest=str(path),
                        source="package-lock.json",
                        direct=False,
                    )
                )
        return dependencies, []

    nested = payload.get("dependencies", {})
    _walk_package_lock_tree(path, nested, dependencies)
    return dependencies, []


def _parse_package_json_file(path: Path, *, include_dependencies: bool) -> tuple[list[Dependency], list[RiskIssue]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    dependencies: list[Dependency] = []
    issues: list[RiskIssue] = []

    for section in ("dependencies", "devDependencies"):
        for name, raw_spec in (payload.get(section, {}) or {}).items():
            version = str(raw_spec)
            exact = bool(re.match(r"^\d+(?:\.\d+){0,3}(?:[-+][A-Za-z0-9_.-]+)?$", version))
            if include_dependencies:
                dependencies.append(
                    Dependency(
                        name=name,
                        version=version if exact else None,
                        ecosystem="npm",
                        manifest=str(path),
                        source="package.json",
                        raw_spec=version,
                    )
                )
            if not exact:
                issues.append(
                    RiskIssue(
                        rule_id="CS-DEP-002",
                        severity="MEDIUM",
                        title="Unpinned npm dependency",
                        message=f"{name} in {path.name} uses a non-exact version specifier: {version}.",
                        recommendation=(
                            "Pin npm dependencies using an exact lockfile-backed version "
                            "for deterministic analysis."
                        ),
                        file_path=str(path),
                    )
                )
    return dependencies, issues


def _parse_cyclonedx_sbom(path: Path, payload: dict[str, object]) -> tuple[list[Dependency], list[RiskIssue]]:
    dependencies: list[Dependency] = []
    issues: list[RiskIssue] = []

    for component in payload.get("components", []) or []:
        ecosystem, name, version = _parse_component_identity(
            component.get("purl"),
            component.get("name"),
            component.get("version"),
        )
        if not name:
            continue
        dependencies.append(
            Dependency(
                name=name,
                version=version,
                ecosystem=ecosystem,
                manifest=str(path),
                source="sbom",
                purl=component.get("purl"),
            )
        )
        if not version:
            issues.append(
                RiskIssue(
                    rule_id="CS-SBOM-001",
                    severity="MEDIUM",
                    title="SBOM component has no exact version",
                    message=f"Component {name} in {path.name} does not include a version.",
                    recommendation="Generate an SBOM with component versions for accurate vulnerability correlation.",
                    file_path=str(path),
                )
            )
    return dependencies, issues


def _parse_spdx_sbom(path: Path, payload: dict[str, object]) -> tuple[list[Dependency], list[RiskIssue]]:
    dependencies: list[Dependency] = []
    issues: list[RiskIssue] = []

    for package in payload.get("packages", []) or []:
        purl = None
        for external_ref in package.get("externalRefs", []) or []:
            if external_ref.get("referenceType") == "purl":
                purl = external_ref.get("referenceLocator")
                break
        ecosystem, name, version = _parse_component_identity(
            purl,
            package.get("name"),
            package.get("versionInfo"),
        )
        if not name:
            continue
        dependencies.append(
            Dependency(
                name=name,
                version=version,
                ecosystem=ecosystem,
                manifest=str(path),
                source="sbom",
                purl=purl,
            )
        )
        if not version:
            issues.append(
                RiskIssue(
                    rule_id="CS-SBOM-001",
                    severity="MEDIUM",
                    title="SBOM component has no exact version",
                    message=f"Component {name} in {path.name} does not include a version.",
                    recommendation="Generate an SBOM with component versions for accurate vulnerability correlation.",
                    file_path=str(path),
                )
            )
    return dependencies, issues


def _dependency_from_string_spec(
    path: Path,
    dependency: str,
    *,
    ecosystem: str,
) -> tuple[list[Dependency], list[RiskIssue]]:
    name, version, pinned = parse_name_and_version(dependency)
    if not name:
        return [], []
    issues = []
    if not pinned:
        issues.append(
            RiskIssue(
                rule_id="CS-DEP-001",
                severity="MEDIUM",
                title="Unpinned Python dependency",
                message=f"{name} in {path.name} is not pinned to an exact version.",
                recommendation="Use == pins for reproducible builds and deterministic vulnerability lookups.",
                file_path=str(path),
            )
        )
    return [
        Dependency(
            name=name,
            version=version,
            ecosystem=ecosystem,
            manifest=str(path),
            source="pyproject.toml",
            raw_spec=dependency,
        )
    ], issues


def _dependency_from_poetry_spec(path: Path, name: str, spec: object) -> tuple[list[Dependency], list[RiskIssue]]:
    version = spec.get("version") if isinstance(spec, dict) else spec
    version_string = str(version) if version is not None else ""
    exact = bool(re.match(r"^\d+(?:\.\d+){0,3}(?:[-+][A-Za-z0-9_.-]+)?$", version_string))
    issues = []
    if not exact:
        issues.append(
            RiskIssue(
                rule_id="CS-DEP-001",
                severity="MEDIUM",
                title="Unpinned Python dependency",
                message=f"{name} in {path.name} is not pinned to an exact version.",
                recommendation="Use exact versions for reproducible builds and deterministic vulnerability lookups.",
                file_path=str(path),
            )
        )
    return [
        Dependency(
            name=name,
            version=version_string if exact else None,
            ecosystem="PyPI",
            manifest=str(path),
            source="pyproject.toml",
            raw_spec=version_string or None,
        )
    ], issues


def _parse_component_identity(purl: object, name: object, version: object) -> tuple[str | None, str | None, str | None]:
    if isinstance(purl, str) and purl.startswith("pkg:"):
        body = purl[4:]
        package_type, _, remainder = body.partition("/")
        package_name, _, package_version = remainder.partition("@")
        ecosystem = {"pypi": "PyPI", "npm": "npm"}.get(package_type.lower(), package_type)
        return ecosystem, package_name or None, package_version or None
    return None, str(name) if name else None, str(version) if version else None


def _walk_package_lock_tree(path: Path, tree: dict[str, object], dependencies: list[Dependency]) -> None:
    for name, metadata in tree.items():
        version = metadata.get("version") if isinstance(metadata, dict) else None
        if version:
            dependencies.append(
                Dependency(
                    name=name,
                    version=str(version),
                    ecosystem="npm",
                    manifest=str(path),
                    source="package-lock.json",
                    direct=False,
                )
            )
        nested = metadata.get("dependencies") if isinstance(metadata, dict) else None
        if isinstance(nested, dict):
            _walk_package_lock_tree(path, nested, dependencies)


def _deduplicate_dependencies(dependencies: list[Dependency]) -> list[Dependency]:
    deduplicated: list[Dependency] = []
    seen: set[tuple[str | None, str, str | None, str]] = set()
    for dependency in dependencies:
        key = (
            dependency.ecosystem.lower() if dependency.ecosystem else None,
            dependency.name.lower(),
            dependency.version,
            dependency.manifest,
        )
        if key not in seen:
            seen.add(key)
            deduplicated.append(dependency)
    return deduplicated
