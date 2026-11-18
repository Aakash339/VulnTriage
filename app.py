"""Streamlit frontend for the VulnTriage dependency analysis pipeline."""

from __future__ import annotations

import io
import os
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

import streamlit as st

from orchestrator import run_vulntriage
from reports.report_generator import generate_csv_report


MAX_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_FILES = 10_000
MAX_SINGLE_FILE_BYTES = 100 * 1024 * 1024
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
PROJECT_MANIFESTS = {"requirements.txt", "package.json", "package-lock.json"}
PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
SORT_OPTIONS = (
    "Priority (Highest first)",
    "Severity (Highest first)",
    "Package name (A–Z)",
    "Reachability (USED first)",
    "Vulnerability ID (A–Z)",
)


class ArchiveValidationError(ValueError):
    """Raised when an uploaded archive is unsafe or exceeds configured limits."""


def _safe_member_target(destination: Path, member_name: str) -> Path:
    """Resolve an archive path under destination, rejecting traversal variants."""
    if not member_name or "\x00" in member_name or "\\" in member_name:
        raise ArchiveValidationError("The ZIP contains an invalid file path.")
    if member_name.startswith("/") or ":" in member_name:
        raise ArchiveValidationError("The ZIP contains an absolute or unsupported file path.")

    parts = member_name.split("/")
    if any(part in {"", ".", ".."} for part in parts[:-1]):
        raise ArchiveValidationError("The ZIP contains a path traversal entry.")
    relative = PurePosixPath(member_name)
    if relative.is_absolute() or any(part == ".." for part in relative.parts):
        raise ArchiveValidationError("The ZIP contains a path traversal entry.")

    target = destination.joinpath(*relative.parts)
    try:
        if os.path.commonpath((str(destination.resolve()), str(target.resolve()))) != str(destination.resolve()):
            raise ArchiveValidationError("The ZIP contains a path outside its extraction folder.")
    except ValueError as error:
        raise ArchiveValidationError("The ZIP contains an invalid file path.") from error
    return target


def _extract_project_zip(archive_bytes: bytes, destination: Path) -> Path:
    """Safely extract a bounded ZIP and return the likely project root."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except (zipfile.BadZipFile, OSError) as error:
        raise ArchiveValidationError("This file is not a readable ZIP archive.") from error

    with archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_FILES:
            raise ArchiveValidationError(f"The ZIP has too many entries (limit: {MAX_ARCHIVE_FILES:,}).")
        declared_total = 0
        for info in members:
            if info.flag_bits & 0x1:
                raise ArchiveValidationError("Password-protected ZIP files are not supported.")
            _safe_member_target(destination, info.filename)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ArchiveValidationError("Symbolic links in ZIP files are not supported.")
            if info.is_dir():
                continue
            if info.file_size > MAX_SINGLE_FILE_BYTES:
                raise ArchiveValidationError("A file in the ZIP exceeds the 100 MB per-file limit.")
            declared_total += info.file_size
            if declared_total > MAX_EXTRACTED_BYTES:
                raise ArchiveValidationError("The ZIP expands beyond the 500 MB extraction limit.")

        actual_total = 0
        for info in members:
            target = _safe_member_target(destination, info.filename)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            actual_file_size = 0
            with archive.open(info, "r") as source, target.open("wb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    actual_total += len(chunk)
                    actual_file_size += len(chunk)
                    if actual_total > MAX_EXTRACTED_BYTES or actual_file_size > MAX_SINGLE_FILE_BYTES:
                        raise ArchiveValidationError("The ZIP expanded beyond the configured extraction limit.")
                    output.write(chunk)

    return _find_project_root(destination)


def _find_project_root(extraction_root: Path) -> Path:
    """Select a single manifest-bearing root, including one nested top folder."""
    candidates: list[Path] = []
    for current, directories, filenames in os.walk(extraction_root):
        directories[:] = [name for name in directories if name not in IGNORED_DIRS]
        if PROJECT_MANIFESTS.intersection(filenames):
            candidates.append(Path(current))
    if len(candidates) == 1:
        return candidates[0]
    return extraction_root


def _finding_columns() -> list[str]:
    return [
        "package",
        "vulnerability_id",
        "severity",
        "reachability",
        "priority",
        "risk_score",
        "risk_level",
        "risk_factors",
        "risk_explanation",
        "installed_version",
        "recommended_version",
        "recommendation",
    ]


def _field_text(finding, field: str, default: str = "UNKNOWN") -> str:
    if not isinstance(finding, dict):
        return default
    value = finding.get(field)
    return value.strip() if isinstance(value, str) and value.strip() else default


def _priority_rank(finding) -> int:
    return PRIORITY_ORDER.get(_field_text(finding, "priority").upper(), PRIORITY_ORDER["UNKNOWN"])


def _severity_rank(finding) -> int:
    return SEVERITY_ORDER.get(_field_text(finding, "severity").upper(), SEVERITY_ORDER["UNKNOWN"])


def _sort_findings(findings: list, sort_option: str = SORT_OPTIONS[0]) -> list:
    """Return a sorted display copy, leaving the source findings untouched."""
    rows = list(findings)

    def package_key(finding):
        return _field_text(finding, "package", "").casefold()

    def priority_key(finding):
        return (_priority_rank(finding), _severity_rank(finding), package_key(finding))

    if sort_option == "Severity (Highest first)":
        key = lambda finding: (_severity_rank(finding), _priority_rank(finding), package_key(finding))
    elif sort_option == "Package name (A–Z)":
        key = lambda finding: (package_key(finding), _priority_rank(finding), _severity_rank(finding))
    elif sort_option == "Reachability (USED first)":
        reach_order = {"USED": 0, "NOT_FOUND": 1, "UNKNOWN": 2}
        key = lambda finding: (
            reach_order.get(_field_text(finding, "reachability").upper(), 3),
            _priority_rank(finding), _severity_rank(finding), package_key(finding),
        )
    elif sort_option == "Vulnerability ID (A–Z)":
        key = lambda finding: (
            _field_text(finding, "vulnerability_id", "").casefold(),
            _priority_rank(finding), _severity_rank(finding), package_key(finding),
        )
    else:
        key = priority_key
    return sorted(rows, key=key)


def _filter_findings(findings: list, severities: set[str], priorities: set[str], reachability: str) -> list:
    """Filter without changing or dropping rows except by selected criteria."""
    filtered = []
    for finding in findings:
        severity = _field_text(finding, "severity").upper()
        priority = _field_text(finding, "priority").upper()
        reach = _field_text(finding, "reachability").upper()
        if severity not in severities or priority not in priorities:
            continue
        if reachability != "All" and reach != reachability:
            continue
        filtered.append(finding)
    return filtered


def _finding_summary(findings: list) -> dict[str, int]:
    packages = {
        package.casefold()
        for finding in findings
        if (package := _field_text(finding, "package", ""))
    }
    return {
        "total": len(findings),
        "unique_packages": len(packages),
        "used": sum(_field_text(finding, "reachability").upper() == "USED" for finding in findings),
        "unknown_reachability": sum(
            _field_text(finding, "reachability").upper() == "UNKNOWN" for finding in findings
        ),
    }


def _table_rows(findings: list) -> list[dict]:
    return [
        {column: (finding.get(column) if isinstance(finding, dict) else None) for column in _finding_columns()}
        for finding in findings
    ]


def _render_findings(findings: list[dict]) -> None:
    priorities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    summary = _finding_summary(findings)
    summary_columns = st.columns(4)
    summary_columns[0].metric("Total findings", summary["total"])
    summary_columns[1].metric("Unique affected packages", summary["unique_packages"])
    summary_columns[2].metric("USED findings", summary["used"])
    summary_columns[3].metric("Findings to investigate", summary["unknown_reachability"])

    priority_columns = st.columns(len(priorities))
    for column, priority in zip(priority_columns, priorities):
        count = sum(_field_text(item, "priority").upper() == priority for item in findings)
        column.metric(f"{priority} priority", count)

    st.subheader("Findings")
    severities = sorted({_field_text(item, "severity").upper() for item in findings})
    finding_priorities = sorted({_field_text(item, "priority").upper() for item in findings})
    filter_columns = st.columns(4)
    sort_option = filter_columns[0].selectbox("Sort findings", SORT_OPTIONS, index=0)
    selected_severities = filter_columns[1].multiselect("Filter by severity", severities, default=severities)
    selected_priorities = filter_columns[2].multiselect("Filter by priority", finding_priorities, default=finding_priorities)
    selected_reachability = filter_columns[3].selectbox(
        "Filter by reachability", ["All", "USED", "NOT_FOUND", "UNKNOWN"], index=0
    )
    filtered = _filter_findings(findings, set(selected_severities), set(selected_priorities), selected_reachability)
    sorted_findings = _sort_findings(filtered, sort_option)
    if filtered:
        st.dataframe(
            _table_rows(sorted_findings),
            use_container_width=True,
            hide_index=True,
            column_order=_finding_columns(),
            column_config={
                "package": st.column_config.TextColumn("package", width="medium"),
                "vulnerability_id": st.column_config.TextColumn("vulnerability_id", width="medium"),
                "severity": st.column_config.TextColumn("severity", width="small"),
                "reachability": st.column_config.TextColumn("reachability", width="small"),
                "priority": st.column_config.TextColumn("priority", width="small"),
                "risk_score": st.column_config.NumberColumn("risk_score", width="small", format="%d/100"),
                "risk_level": st.column_config.TextColumn("risk_level", width="small"),
                "risk_factors": st.column_config.TextColumn("risk_factors", width="large"),
                "risk_explanation": st.column_config.TextColumn(
                    "risk_explanation", width="large", help="Full explanation is also available below."
                ),
                "installed_version": st.column_config.TextColumn("installed_version", width="small"),
                "recommended_version": st.column_config.TextColumn("recommended_version", width="medium"),
                "recommendation": st.column_config.TextColumn(
                    "recommendation", width="large", help="Expand a row below to read the full recommendation."
                ),
            },
            height=560,
        )
        with st.expander("Read full recommendations"):
            for finding in sorted_findings:
                package = _field_text(finding, "package", "(unknown package)")
                vulnerability_id = _field_text(finding, "vulnerability_id", "(unknown vulnerability)")
                recommendation = _field_text(finding, "recommendation", "No recommendation provided.")
                risk_explanation = _field_text(finding, "risk_explanation", "Risk explanation unavailable.")
                risk_score = finding.get("risk_score") if isinstance(finding, dict) else None
                risk_score = risk_score if isinstance(risk_score, (int, float)) else "N/A"
                st.markdown(
                    f"**{package} · {vulnerability_id}**\n\n"
                    f"**Recommendation:** {recommendation}\n\n"
                    f"**Risk:** {risk_score}/100 · "
                    f"{_field_text(finding, 'risk_level', 'UNKNOWN')}\n\n"
                    f"{risk_explanation}"
                )
    else:
        st.info("No findings match the selected filters.")

    st.download_button(
        "Download CSV report",
        data=generate_csv_report(findings),
        file_name="vulntriage-report.csv",
        mime="text/csv",
        use_container_width=False,
    )


def main() -> None:
    st.set_page_config(page_title="VulnTriage", page_icon="🛡️", layout="wide")
    st.title("🛡️ VulnTriage")
    st.subheader("Dependency Vulnerability Triage Agent")
    st.write(
        "Upload a Python or npm project ZIP to identify dependencies, query OSV.dev "
        "for known vulnerability records, check source import reachability, and "
        "review prioritized remediation guidance."
    )

    uploaded = st.file_uploader(
        "Upload a project ZIP",
        type=["zip"],
        help="Supports Python requirements.txt projects and npm package.json/package-lock.json projects.",
    )
    if uploaded is not None:
        upload_size = uploaded.size
        if upload_size > MAX_UPLOAD_BYTES:
            st.error("The ZIP exceeds the 100 MB upload limit. Please upload a smaller archive.")
        else:
            st.caption(f"{uploaded.name} · {upload_size / (1024 * 1024):.1f} MB")

    if st.button("Scan project", type="primary", disabled=(uploaded is None or uploaded.size > MAX_UPLOAD_BYTES)):
        try:
            archive_bytes = uploaded.getvalue()
            with tempfile.TemporaryDirectory(prefix="vulntriage-") as temporary_dir:
                extraction_root = Path(temporary_dir)
                with st.status("Preparing project scan…", expanded=True) as status:
                    st.write("Validating and extracting the project ZIP")
                    project_root = _extract_project_zip(archive_bytes, extraction_root)
                    st.write(f"Scanning project at `{project_root.name or project_root}`")
                    findings = run_vulntriage(str(project_root))
                    status.update(label="Scan complete", state="complete", expanded=False)
            st.session_state["vulntriage_findings"] = findings
            st.session_state["vulntriage_upload"] = (uploaded.name, upload_size)
            st.session_state.pop("vulntriage_error", None)
        except ArchiveValidationError as error:
            st.session_state["vulntriage_error"] = str(error)
            st.session_state.pop("vulntriage_findings", None)
        except Exception as error:  # Keep user-facing failures clear; details stay in server logs.
            st.session_state["vulntriage_error"] = f"The scan could not be completed: {error}"
            st.session_state.pop("vulntriage_findings", None)

    error_message = st.session_state.get("vulntriage_error")
    if error_message:
        st.error(error_message)

    findings = st.session_state.get("vulntriage_findings")
    current_upload = (uploaded.name, uploaded.size) if uploaded is not None else None
    if findings is not None and st.session_state.get("vulntriage_upload") == current_upload:
        if findings:
            _render_findings(findings)
        else:
            st.success("The scan completed and no vulnerability findings were returned by the analysis agents.")

    st.caption(
        "Reachability indicates detected imports only; it does not prove exploitability. "
        "A NOT_FOUND result does not prove a dependency is unused or safe."
    )


if __name__ == "__main__":
    main()
