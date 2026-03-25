from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import main


FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def test_main_json_output_for_local_path(capsys) -> None:
    exit_code = main.main(
        [
            "--path",
            str(FIXTURE_ROOT / "sample_project"),
            "--offline",
            "--advisory-db",
            str(FIXTURE_ROOT / "sample_advisories.json"),
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["reports"][0]["target"] == "sample_project"
    assert payload["reports"][0]["risk_summary"]["score"] > 0


def test_invalid_advisory_db_is_reported_as_failure(capsys) -> None:
    exit_code = main.main(
        [
            "--path",
            str(FIXTURE_ROOT / "sample_project"),
            "--offline",
            "--advisory-db",
            str(FIXTURE_ROOT / "missing-advisories.json"),
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["reports"] == []
    assert "does not exist" in payload["failures"][0]["error"]


def test_git_url_scan_clones_local_repository(tmp_path: Path) -> None:
    source = FIXTURE_ROOT / "sample_project"
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True, text=True)
    for fixture_path in source.iterdir():
        target = repo / fixture_path.name
        if fixture_path.is_dir():
            shutil.copytree(fixture_path, target)
        else:
            target.write_bytes(fixture_path.read_bytes())
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "tests@example.com"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Tests"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True, text=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "fixture"], check=True, capture_output=True, text=True)

    exit_code = main.main(
        [
            "--git-url",
            str(repo),
            "--offline",
            "--advisory-db",
            str(FIXTURE_ROOT / "sample_advisories.json"),
            "--json",
        ]
    )

    assert exit_code == 0
