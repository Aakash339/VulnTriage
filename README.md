# VulnTriage

**Dependency Vulnerability Triage Agent** is a small analysis pipeline and Streamlit interface for reviewing dependency vulnerabilities in Python and npm projects. Upload a ZIP archive to extract dependency records, query OSV.dev, check whether vulnerable packages appear in source imports, and view prioritized remediation guidance with a CSV export.

## Architecture

The orchestrator connects four agents in sequence:

1. **Dependency agent** reads dependency manifests and npm lockfiles.
2. **Vulnerability agent** submits supported, resolved dependency versions to OSV.dev and returns vulnerability records.
3. **Reachability agent** searches supported source files for matching imports. An import match indicates import presence only; it does not establish exploitability. `NOT_FOUND` does not establish that a dependency is unused or safe.
4. **Remediation agent** combines vulnerability and reachability records into prioritized findings and upgrade guidance.

`reports/report_generator.py` exports the findings as CSV. `app.py` provides the ZIP upload, scan, filtering, metrics, and download interface.

## Supported project files

- **Python dependencies:** `requirements.txt`
- **npm dependencies:** `package.json` and `package-lock.json`
- **Reachability source scan:** `.py`, `.js`, `.jsx`, `.ts`, and `.tsx` files

The agents skip common generated or vendor directories such as `.git`, virtual environments, `node_modules`, and Python cache folders. The dependency parser does not currently read `pyproject.toml`, `Pipfile`, Yarn or pnpm lockfiles, or other manifest formats.

## Installation

Python 3.10 or newer is recommended. Create and activate a virtual environment, then install the runtime dependencies:

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# macOS/Linux
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Launch

From the repository root, run:

```bash
streamlit run app.py
```

Upload a ZIP containing a Python or npm project and select **Scan project**. ZIP uploads are limited to 100 MB; extracted archives are limited to 500 MB, 10,000 entries, and 100 MB per file. The app blocks path traversal and symbolic-link entries and removes its temporary extraction directory when the scan finishes.

## Limitations

- Vulnerability results depend on OSV.dev availability and the package/version data returned by its API. A failed or skipped query is not evidence that a dependency is safe.
- Dependency extraction currently supports `requirements.txt`, npm `package.json`, and npm `package-lock.json`; it does not resolve Python dependency trees or all package manager formats.
- Reachability is a basic import-presence check, not call-graph or exploitability analysis. JavaScript and TypeScript import recognition uses pattern matching rather than a full parser.
- Findings and priority levels are triage guidance. Review upstream advisories, affected version ranges, and application behavior before applying changes.
