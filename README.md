# container-scanner

`container-scanner` is a Python CLI for dependency and source-risk scanning. It supports three input modes:

- local paths
- Git repository URLs
- CycloneDX or SPDX JSON SBOM files

The scanner combines dependency extraction, vulnerability correlation, source-code risk checks, weighted risk scoring, JSON output, and a concise CLI summary. It is cross-platform, but the repository is set up to be especially easy to run on Kali Linux.

## Why Use This Tool

Use `container-scanner` when you need a fast security-oriented view of a codebase or software bill of materials without setting up a larger platform first.

- Use `--path` when the code is already on disk and you want the fastest local scan.
- Use `--git-url` when you want the scanner to clone and inspect a repository for you.
- Use `--sbom` when you already have a CycloneDX or SPDX JSON inventory and want dependency-based risk results without scanning source files.

This tool is intended for lightweight dependency and code-risk assessment. It is useful for triage, offline review, lab environments, CI checks, and repeatable Kali workflows.

## How This Helps In Practice

`container-scanner` is most useful when you need a fast decision tool rather than a full security platform rollout.

- For developers, it helps catch risky dependencies and insecure coding patterns before shipping code.
- For security engineers, it helps triage unknown repositories quickly and decide where deeper review is needed.
- For Kali workflows, it gives a simple local command that works well in lab environments, short assessments, and repeatable verification tasks.
- For CI usage, it gives a compact summary for humans and a JSON payload for automation.

In practical terms, the tool helps answer questions like:

- Does this project depend on packages with known vulnerabilities?
- Are there obvious risky coding patterns such as `shell=True`, disabled TLS verification, or weak hashing?
- Is this repository worth escalating for manual review?
- Can I scan this target offline in a controlled environment?

## How It Works

Each scan follows the same high-level flow:

1. Resolve the target from a local path, Git URL, or SBOM file.
2. Extract dependencies from supported manifests or SBOM components.
3. Correlate dependency versions against the official OSV API or a local advisory database.
4. Run source checks for risky code patterns when scanning source trees or Git clones.
5. Build a weighted risk score and produce text and JSON output.

The scanner does not execute the target project. It reads files, parses dependency metadata, and optionally queries vulnerability data.

## What It Checks

- Python dependencies from `requirements.txt` and `pyproject.toml`
- npm dependencies from `package-lock.json` and `package.json`
- CycloneDX and SPDX JSON SBOM components
- Vulnerabilities from the official [OSV API](https://osv.dev/)
- Offline or deterministic lookups from a local advisory database JSON file
- Source risks such as `shell=True`, `eval`/`exec`, disabled TLS verification, weak hashing, and likely hardcoded secrets

## Supported Inputs

### Local path

Use `--path` for a project directory or a single supported manifest file.

Examples:

```bash
container-scanner --path ./some-project
container-scanner --path ./requirements.txt
```

### Git repository URL

Use `--git-url` when you want the tool to clone the repository into a temporary working directory and clean it up after the scan.

Examples:

```bash
container-scanner --git-url https://github.com/pallets/flask.git
container-scanner --git-url file:///home/kali/repos/internal-project
```

### SBOM file

Use `--sbom` for CycloneDX JSON or SPDX JSON when you already have a software inventory and do not need source-code pattern checks.

Examples:

```bash
container-scanner --sbom ./bom.cdx.json
container-scanner --sbom ./bom.spdx.json --json
```

## What Gets Sent Externally

By default, vulnerability correlation uses the official OSV API. When that path is used, the scanner sends only dependency metadata needed for advisory matching:

- package name
- package ecosystem
- package version

It does not upload your source files, full repository contents, or local secrets to OSV.

If you do not want any external lookups, use:

```bash
container-scanner --path ./some-project --offline --advisory-db ./advisories.json
```

That keeps the scan fully local.

## Kali Linux Quick Start

Install the base system packages:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
```

Clone the repository:

```bash
git clone <your-repository-url> container-scanner
cd container-scanner
```

Install the local command:

```bash
bash install_kali.sh
```

That command creates the `container-scanner` launcher in `~/.local/bin` and bootstraps the Python virtual environment on first install.

Run a local source scan:

```bash
container-scanner --path ./some-project
```

Run an offline scan with a local advisory database:

```bash
container-scanner --path ./some-project --offline --advisory-db ./tests/fixtures/sample_advisories.json
```

Scan a Git repository directly:

```bash
container-scanner --git-url https://github.com/pallets/flask.git
```

Scan an SBOM:

```bash
container-scanner --sbom ./bom.cdx.json --json
```

## How the Kali Wrapper Works

- `run_kali.sh` creates `.venv` on first run
- it installs or refreshes Python dependencies when `requirements.txt` changes
- it executes `main.py` from the project root
- `install_kali.sh` creates `~/.local/bin/container-scanner`, so the command works anywhere

If you want to skip the bootstrap verification during install, use:

```bash
bash install_kali.sh --skip-bootstrap
```

If `~/.local/bin` is not on your `PATH`, add this to `~/.bashrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload your shell:

```bash
source ~/.bashrc
```

## Windows Setup

Clone the repository in PowerShell:

```powershell
git clone <your-repository-url> container-scanner
cd container-scanner
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run a scan:

```powershell
python .\main.py --path .\tests\fixtures\sample_project
python .\main.py --sbom .\tests\fixtures\sample_sbom_cyclonedx.json --json
python .\main.py --git-url https://github.com/pallets/flask.git
```

## CLI Usage

```text
python main.py [scan] [--path PATH] [--git-url URL] [--sbom FILE] [--json]
               [--offline] [--advisory-db FILE] [--api-timeout SECONDS]
               [--git-timeout SECONDS] [--max-findings COUNT]
```

## CLI Flags Explained

- `--path`: scan a local directory or supported manifest file.
- `--git-url`: clone and scan a Git repository.
- `--sbom`: scan a CycloneDX or SPDX JSON SBOM.
- `--json`: print structured JSON instead of the default text summary.
- `--offline`: disable OSV API calls.
- `--advisory-db`: use a local advisory database JSON file.
- `--api-timeout`: set the OSV request timeout in seconds.
- `--git-timeout`: set the git clone timeout in seconds.
- `--max-findings`: limit the number of finding rows shown in text output.
- `--log-level`: change logging verbosity.

### Common Examples

Scan a local path:

```bash
python main.py --path ./app
```

Scan multiple targets at once:

```bash
python main.py --path ./app --sbom ./bom.cdx.json
```

Scan a Git repository:

```bash
python main.py --git-url https://github.com/pallets/flask.git
```

Use an offline advisory database:

```bash
python main.py --path ./app --offline --advisory-db ./advisories.json
```

Emit JSON:

```bash
python main.py --path ./app --json
```

## Output Model

The text output starts with a concise per-target summary:

```text
sample_project | score 66 HIGH | deps 2 | vulns 2 | issues 4
```

That summary means:

- `score 66`: the weighted aggregate risk score for the target
- `HIGH`: the risk band derived from the score
- `deps 2`: two dependencies were identified
- `vulns 2`: two dependency vulnerabilities were matched
- `issues 4`: four local risk issues were detected

Text output then shows:

- a vulnerability table with package, version, advisory ID, severity, and fix version when available
- a risk issue table with severity, rule ID, file path, line number, and title
- warning lines when the scan could not complete a non-fatal step

## How To Read The Results

Use the output in this order:

1. Check the top summary line to understand the overall score, severity band, dependency count, vulnerability count, and issue count.
2. Review the vulnerability table to identify packages that need patching or version upgrades.
3. Review the risk issue table to find code patterns that should be fixed or manually reviewed.
4. Review warnings last, because they indicate partial visibility or non-fatal scan problems.

A high score does not always mean the target is immediately exploitable, but it does mean the target deserves faster review and remediation. A low score does not prove the target is safe; it only means this scanner found fewer issues within its coverage.

## How Risk Scoring Works

The score is a bounded `0-100` aggregate built from vulnerability severity and local code-risk severity.

Vulnerability weights:

- `CRITICAL`: `35`
- `HIGH`: `20`
- `MEDIUM`: `10`
- `LOW`: `4`
- `UNKNOWN`: `8`

Code and dependency issue weights:

- `CRITICAL`: `25`
- `HIGH`: `15`
- `MEDIUM`: `8`
- `LOW`: `3`
- `UNKNOWN`: `5`

Score bands:

- `0-14`: `LOW`
- `15-39`: `MEDIUM`
- `40-69`: `HIGH`
- `70-100`: `CRITICAL`

JSON output is always wrapped as:

```json
{
  "reports": [
    {
      "target": "sample_project",
      "source_kind": "path",
      "dependency_count": 2,
      "vulnerabilities": [],
      "risk_issues": [],
      "risk_summary": {
        "score": 0,
        "level": "LOW"
      }
    }
  ],
  "failures": []
}
```

## Local Advisory Database Format

Use this when you need deterministic scans or no outbound network access:

```json
{
  "schema": "container-scanner-advisory-db/v1",
  "advisories": [
    {
      "id": "PYSEC-TEST-0001",
      "package": {
        "ecosystem": "PyPI",
        "name": "requests",
        "version": "2.19.0"
      },
      "severity": "HIGH",
      "summary": "Example advisory",
      "fix_versions": ["2.20.0"],
      "references": ["https://osv.dev/example"]
    }
  ]
}
```

## Limitations

- This tool only analyzes the dependency sources and code patterns it knows how to parse.
- It does not run the target application, build containers, or perform exploit validation.
- Source pattern findings are heuristic and should be reviewed by a human before acting on them.
- SBOM scans do not include source-code pattern checks because no source tree is being inspected.
- Private Git repositories require whatever access your local `git` client already supports.

## Troubleshooting

If `container-scanner` is not found after `bash install_kali.sh`:

```bash
export PATH="$HOME/.local/bin:$PATH"
source ~/.bashrc
container-scanner --help
```

If the Kali bootstrap fails while creating `.venv`:

```bash
sudo apt install -y python3 python3-venv python3-pip
bash run_kali.sh --help
```

If you need a deterministic or air-gapped run:

```bash
container-scanner --path ./some-project --offline --advisory-db ./advisories.json --json
```

If you want more detail while debugging:

```bash
container-scanner --path ./some-project --log-level DEBUG
```

## Development Commands

Run linting:

```bash
python lint.py
```

Run tests:

```bash
python -m pytest -q
```

Run real CLI smoke checks:

```bash
python smoke_cli.py
```

## Test Fixtures

- `tests/fixtures/sample_project` contains a small vulnerable source tree
- `tests/fixtures/sample_sbom_cyclonedx.json` contains a CycloneDX SBOM
- `tests/fixtures/sample_advisories.json` contains a deterministic advisory DB used by tests and smoke checks

## Project Layout

```text
container-scanner/
  main.py
  scanner/
  tests/
  install_kali.sh
  run_kali.sh
  lint.py
  smoke_cli.py
  requirements.txt
  README.md
```
