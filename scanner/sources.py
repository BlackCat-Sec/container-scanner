from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from scanner.models import InputSpec, ScanTarget
from utils.helpers import safe_display_name


class SourceResolutionError(RuntimeError):
    """Raised when an input source cannot be prepared for scanning."""


def collect_input_specs(*, paths: list[str], git_urls: list[str], sboms: list[str]) -> list[InputSpec]:
    specs: list[InputSpec] = []
    for value in paths:
        specs.append(InputSpec(kind="path", value=str(Path(value).expanduser())))
    for value in git_urls:
        specs.append(InputSpec(kind="git_url", value=value))
    for value in sboms:
        specs.append(InputSpec(kind="sbom", value=str(Path(value).expanduser())))

    deduplicated: list[InputSpec] = []
    seen: set[tuple[str, str]] = set()
    for spec in specs:
        key = (spec.kind, spec.value)
        if key not in seen:
            seen.add(key)
            deduplicated.append(spec)
    return deduplicated


def resolve_target(spec: InputSpec, *, git_timeout: int) -> ScanTarget:
    if spec.kind == "path":
        path = Path(spec.value).resolve()
        if not path.exists():
            raise SourceResolutionError(f"Path does not exist: {path}")
        return ScanTarget(
            source_kind="path",
            source=str(path),
            display_name=path.name or str(path),
            work_path=str(path),
        )

    if spec.kind == "sbom":
        path = Path(spec.value).resolve()
        if not path.exists() or not path.is_file():
            raise SourceResolutionError(f"SBOM file does not exist: {path}")
        return ScanTarget(
            source_kind="sbom",
            source=str(path),
            display_name=path.name,
            sbom_path=str(path),
        )

    if spec.kind == "git_url":
        return _clone_git_target(spec.value, git_timeout=git_timeout)

    raise SourceResolutionError(f"Unsupported source kind: {spec.kind}")


def cleanup_targets(targets: list[ScanTarget]) -> None:
    for target in targets:
        if target.cleanup_path:
            shutil.rmtree(target.cleanup_path, ignore_errors=True)


def _clone_git_target(git_url: str, *, git_timeout: int) -> ScanTarget:
    clone_root = Path(tempfile.mkdtemp(prefix="container-scanner-"))
    destination = clone_root / "repo"
    command = ["git", "clone", "--depth", "1", git_url, str(destination)]
    try:
        subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=git_timeout,
        )
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(clone_root, ignore_errors=True)
        stderr = (exc.stderr or "").strip()
        raise SourceResolutionError(stderr or f"git clone failed for {git_url}") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        shutil.rmtree(clone_root, ignore_errors=True)
        raise SourceResolutionError(f"Unable to execute git clone for {git_url}") from exc

    return ScanTarget(
        source_kind="git_url",
        source=git_url,
        display_name=safe_display_name(git_url),
        work_path=str(destination),
        cleanup_path=str(clone_root),
    )
