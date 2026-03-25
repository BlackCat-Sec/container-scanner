from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "tests" / "fixtures"
PYTHON = sys.executable


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, str(ROOT / "main.py"), *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=True,
    )


def build_local_git_repo() -> Path:
    workspace = Path(tempfile.mkdtemp(prefix="container-scanner-smoke-"))
    repo = workspace / "sample-project"
    shutil.copytree(FIXTURES / "sample_project", repo)
    subprocess.run(["git", "init"], cwd=str(repo), capture_output=True, text=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "smoke@example.com"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Smoke Test"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
    )
    subprocess.run(["git", "add", "."], cwd=str(repo), capture_output=True, text=True, check=True)
    subprocess.run(["git", "commit", "-m", "fixture"], cwd=str(repo), capture_output=True, text=True, check=True)
    return workspace


def main() -> int:
    advisory_db = FIXTURES / "sample_advisories.json"
    project_path = FIXTURES / "sample_project"
    sbom_path = FIXTURES / "sample_sbom_cyclonedx.json"

    local_result = run_cli(
        "--path",
        str(project_path),
        "--offline",
        "--advisory-db",
        str(advisory_db),
    )
    if "score" not in local_result.stdout or "sample_project" not in local_result.stdout:
        raise SystemExit("Local path smoke check failed")

    sbom_result = run_cli(
        "--sbom",
        str(sbom_path),
        "--offline",
        "--advisory-db",
        str(advisory_db),
        "--json",
    )
    sbom_payload = json.loads(sbom_result.stdout)
    if sbom_payload["reports"][0]["dependency_count"] != 2:
        raise SystemExit("SBOM smoke check failed")

    workspace = build_local_git_repo()
    try:
        git_result = run_cli(
            "--git-url",
            str(workspace / "sample-project"),
            "--offline",
            "--advisory-db",
            str(advisory_db),
        )
        if "vulns" not in git_result.stdout:
            raise SystemExit("Git URL smoke check failed")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    print("CLI smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
