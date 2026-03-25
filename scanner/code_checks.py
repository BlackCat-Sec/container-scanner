from __future__ import annotations

import re
from pathlib import Path

from scanner.models import RiskIssue
from utils.helpers import is_probably_text_file, read_text_file, should_skip_path


PATTERN_RULES = [
    {
        "rule_id": "CS-CODE-001",
        "severity": "HIGH",
        "title": "subprocess with shell=True",
        "message": "Use of shell=True in subprocess calls can introduce command injection risk.",
        "recommendation": "Prefer argument lists and avoid shell=True unless input is fully controlled.",
        "pattern": re.compile(
            r"subprocess\.(?:run|Popen|call|check_call|check_output)\([^)]*shell\s*=\s*True",
            re.DOTALL,
        ),
    },
    {
        "rule_id": "CS-CODE-002",
        "severity": "HIGH",
        "title": "Dynamic code execution",
        "message": "eval/exec usage expands attack surface and should be avoided for untrusted data.",
        "recommendation": "Replace eval/exec with safe parsing or explicit dispatch.",
        "pattern": re.compile(r"\b(?:eval|exec)\s*\("),
    },
    {
        "rule_id": "CS-CODE-003",
        "severity": "MEDIUM",
        "title": "TLS verification disabled",
        "message": "verify=False disables certificate validation.",
        "recommendation": "Enable TLS verification and use a trusted CA bundle.",
        "pattern": re.compile(r"verify\s*=\s*False"),
    },
    {
        "rule_id": "CS-CODE-004",
        "severity": "LOW",
        "title": "Weak hashing algorithm",
        "message": "MD5 and SHA1 are not appropriate for security-sensitive hashing.",
        "recommendation": "Use SHA-256 or stronger hashing algorithms where security matters.",
        "pattern": re.compile(r"\b(?:hashlib\.)?(?:md5|sha1)\s*\("),
    },
    {
        "rule_id": "CS-CODE-005",
        "severity": "HIGH",
        "title": "Possible hardcoded secret",
        "message": "A variable name associated with secrets appears to be assigned a literal value.",
        "recommendation": "Move secrets to environment variables or a secrets manager.",
        "pattern": re.compile(r"(?i)\b(?:password|secret|token|api[_-]?key)\b\s*[:=]\s*['\"][^'\"]{8,}"),
    },
]


def scan_code_risks(root_path: str) -> list[RiskIssue]:
    root = Path(root_path)
    candidates = [root] if root.is_file() else sorted(path for path in root.rglob("*") if path.is_file())
    issues: list[RiskIssue] = []

    for path in candidates:
        if should_skip_path(path) or not is_probably_text_file(path):
            continue
        content = read_text_file(path)
        if content is None:
            continue

        for rule in PATTERN_RULES:
            for match in rule["pattern"].finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                issues.append(
                    RiskIssue(
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        title=rule["title"],
                        message=rule["message"],
                        recommendation=rule["recommendation"],
                        file_path=str(path),
                        line=line,
                    )
                )
    return issues
