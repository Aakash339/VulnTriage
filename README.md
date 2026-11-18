# VulnTriage

**Dependency Vulnerability Triage Agent** analyzes Python, npm, and Java projects, looks up supported dependency versions in OSV.dev, checks for static import evidence, prioritizes findings, and exports a CSV report.

## Architecture

The orchestrator connects four agents:

1. **Dependency agent** reads supported manifests and lockfiles without running project or build code.
2. **Vulnerability agent** queries OSV.dev for resolved dependencies in the supported ecosystems: PyPI, npm, and Maven.
3. **Reachability agent** searches Python, JavaScript/TypeScript, and Java source for import evidence. An import does not prove runtime execution or exploitability.
4. **Remediation agent** joins vulnerability and reachability records by ecosystem and package identity, then produces remediation and risk details.

The Streamlit dashboard shows scan coverage, findings, analytics, dependency inventory, and complete-scan CSV reporting.

## Supported project files

- **Python / PyPI:** `requirements.txt`
- **npm:** `package.json` and `package-lock.json`
- **Maven:** `pom.xml` direct dependencies. Simple properties and versions from a declared `dependencyManagement` entry are resolved when available. `dependencyManagement` entries alone are not treated as installed dependencies.
- **Gradle:** literal dependency declarations in `build.gradle` and `build.gradle.kts`; `gradle.lockfile` supplies resolved direct and transitive versions where available.
- **Source reachability:** `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, and `.java` files.

Maven support currently reports dependencies declared directly in each POM; it does not build a complete Maven dependency graph. Gradle scripts are scanned for common literal declarations and are never evaluated. Unresolved properties, variables, and dynamic version selectors are not guessed. Test and provided Maven scopes are included because the dependency scanner does not apply a scope exclusion policy.

Java reachability uses only three curated Maven mappings: `com.google.guava:guava` to `com.google.common`, `org.apache.commons:commons-lang3` to `org.apache.commons.lang3`, and `com.fasterxml.jackson.core:jackson-databind` to `com.fasterxml.jackson.databind`. Other coordinates remain `UNKNOWN`; package names are not inferred from Maven group IDs or artifact IDs.

Generated and vendor directories such as `.git`, `target`, `build`, `dist`, virtual environments, `node_modules`, and Python cache directories are skipped.

## Reachability statuses

- **USED** means a matching static import was detected. It does not prove that code executes or that the vulnerable behavior is exploitable.
- **NOT_FOUND** means no matching import was detected in supported source files. It does not prove that the dependency is unused or safe; dynamic loading, reflection, plugins, indirect use, and unsupported languages may be missed.
- **UNKNOWN** means reachability could not be determined confidently, for example because source files were unavailable, a scan failed, or a Java coordinate had no unique curated mapping.

The dashboard reports partial scan coverage when manifests fail to parse or OSV queries fail. Failed or skipped queries do not create vulnerability findings and must not be interpreted as a clean result. OSV coverage and response quality depend on the service and its available advisories; valid dependencies can have no returned records.

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

From the repository root:

```bash
streamlit run app.py
```

Upload a ZIP containing one or more supported projects and select **Start Security Scan**. ZIP uploads are limited to 100 MB; extraction is limited to 500 MB, 10,000 entries, and 100 MB per file. The app blocks path traversal and symbolic-link entries and removes its temporary extraction directory when the scan finishes.

## Limitations

- Python support currently reads `requirements.txt`; it does not resolve Python dependency trees or other Python lock/manifest formats.
- npm support does not include Yarn, pnpm, or Bun lockfiles.
- Maven dependency collection is direct-declaration focused and does not resolve the full Maven graph. Gradle support intentionally handles only common literal declarations plus lockfile entries.
- Java reachability is limited to the three curated mappings above; Java wildcard and static imports are recognized only when their package prefix maps uniquely.
- Reachability is static import-presence analysis rather than call-graph or exploitability analysis. JavaScript/TypeScript use lightweight lexical recognition rather than a full parser.
- OSV network failures, unsupported or unresolved versions, and absent advisories can limit findings. Review coverage status and upstream advisories before treating a scan as complete.
- Findings, risk scores, and priorities are triage guidance. Validate advisories, version constraints, and application behavior before remediation.
