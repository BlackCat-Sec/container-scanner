from __future__ import annotations

import py_compile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TEXT_SUFFIXES = {".py", ".sh", ".md", ".yml", ".yaml"}


def iter_files() -> list[Path]:
    targets = [
        ROOT / "main.py",
        ROOT / "install_kali.sh",
        ROOT / "run_kali.sh",
        ROOT / "README.md",
        ROOT / "lint.py",
        ROOT / "smoke_cli.py",
    ]
    targets.extend(sorted((ROOT / "scanner").rglob("*.py")))
    targets.extend(sorted((ROOT / "tests").rglob("*.py")))
    targets.extend(sorted((ROOT / ".github").rglob("*.yml")))
    return [path for path in targets if path.exists()]


def main() -> int:
    failures: list[str] = []

    for path in iter_files():
        if path.suffix == ".py":
            try:
                py_compile.compile(str(path), doraise=True)
            except py_compile.PyCompileError as exc:
                failures.append(f"{path}: {exc.msg}")

        if path.suffix in TEXT_SUFFIXES or path.name == "README.md":
            content = path.read_text(encoding="utf-8")
            if not content.endswith("\n"):
                failures.append(f"{path}: file does not end with a newline")
            for line_number, line in enumerate(content.splitlines(), start=1):
                if "\t" in line:
                    failures.append(f"{path}:{line_number}: tab character found")
                if line.rstrip() != line:
                    failures.append(f"{path}:{line_number}: trailing whitespace")
                if path.suffix == ".py" and len(line) > 120:
                    failures.append(f"{path}:{line_number}: line exceeds 120 characters")

    if failures:
        print("Lint failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("Lint passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
