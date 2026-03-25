from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}

TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".env",
    ".ini",
    ".js",
    ".json",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
}

IGNORED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "site-packages",
}


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_severity(value: str | None) -> str:
    if not value:
        return "UNKNOWN"
    normalized = value.strip().upper()
    return normalized if normalized in SEVERITY_ORDER else "UNKNOWN"


def severity_rank(value: str | None) -> int:
    return SEVERITY_ORDER.get(normalize_severity(value), 4)


def score_to_level(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    return "LOW"


def safe_display_name(value: str) -> str:
    name = value.rstrip("/\\").split("/")[-1].split("\\")[-1]
    return name[:-4] if name.endswith(".git") else name


def parse_name_and_version(spec: str) -> tuple[str | None, str | None, bool]:
    cleaned = spec.split(";", 1)[0].strip()
    match = re.match(
        r"^(?P<name>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?P<operator>===|==|~=|>=|<=|>|<)?\s*(?P<version>[^,\s]+)?$",
        cleaned,
    )
    if not match:
        return None, None, False
    operator = match.group("operator")
    version = match.group("version")
    pinned = operator in {"==", "==="} and bool(version)
    return match.group("name"), version if pinned else None, pinned


def is_probably_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name.lower() in {".env", "dockerfile"}


def should_skip_path(path: Path) -> bool:
    return any(part in IGNORED_DIRS for part in path.parts)


def read_text_file(path: Path, *, max_size: int = 1_000_000) -> str | None:
    if path.stat().st_size > max_size:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")
