"""Streamlit frontend for the VulnTriage dependency analysis pipeline."""

from __future__ import annotations

import io
import html
import math
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
    "Risk score (Highest first)",
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

    def score_key(finding):
        score = _risk_score(finding)
        return -(score if score is not None else -1)

    def priority_key(finding):
        return (_priority_rank(finding), _severity_rank(finding), package_key(finding))

    if sort_option == "Risk score (Highest first)":
        key = lambda finding: (
            score_key(finding),
            _priority_rank(finding), _severity_rank(finding), package_key(finding),
        )
    elif sort_option == "Priority (Highest first)":
        key = priority_key
    elif sort_option == "Severity (Highest first)":
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
    """Filter a copy; empty severity or priority selections mean no restriction."""
    selected_severities = {value.strip().upper() for value in (severities or set()) if isinstance(value, str) and value.strip()}
    selected_priorities = {value.strip().upper() for value in (priorities or set()) if isinstance(value, str) and value.strip()}
    selected_reachability = reachability.strip().upper() if isinstance(reachability, str) else "ALL"
    filtered = []
    for finding in findings:
        severity = _normal_severity(finding)
        priority = _field_text(finding, "priority").upper()
        if not priority or priority not in PRIORITY_ORDER:
            priority = "UNKNOWN"
        reach = _field_text(finding, "reachability").upper()
        if reach not in {"USED", "NOT_FOUND", "UNKNOWN"}:
            reach = "UNKNOWN"
        if selected_severities and severity not in selected_severities:
            continue
        if selected_priorities and priority not in selected_priorities:
            continue
        if selected_reachability != "ALL" and reach != selected_reachability:
            continue
        filtered.append(finding)
    return filtered


def _queue_filter_defaults(findings: list) -> dict[str, object]:
    """Build current-scan defaults for Streamlit's persistent filter widgets."""
    return {
        "soc-severity": sorted({_normal_severity(item) for item in findings}),
        "soc-priority": sorted({
            priority if priority in PRIORITY_ORDER else "UNKNOWN"
            for priority in (_field_text(item, "priority").upper() for item in findings)
        }),
        "soc-reachability": "All",
        "soc-sort": SORT_OPTIONS[0],
    }


def _reset_queue_filters() -> None:
    findings = st.session_state.get("vulntriage_findings", [])
    for key, value in _queue_filter_defaults(findings).items():
        st.session_state[key] = value


def _prepare_queue(findings: list, severities: set[str], priorities: set[str], reachability: str, sort_option: str) -> list:
    """Apply filters and sort without mutating or losing any source findings."""
    return _sort_findings(_filter_findings(findings, severities, priorities, reachability), sort_option)


def _reachability_counts(findings: list) -> dict[str, int]:
    counts = {"USED": 0, "NOT_FOUND": 0, "UNKNOWN": 0}
    for finding in findings:
        status = _field_text(finding, "reachability").upper()
        counts[status if status in counts else "UNKNOWN"] += 1
    return counts


def _risk_analysis_summary(findings: list) -> dict[str, object]:
    scores = [score for finding in findings if (score := _risk_score(finding)) is not None]
    reachability = _reachability_counts(findings)
    return {
        "average": sum(scores) / len(scores) if scores else None,
        "highest": max(scores) if scores else None,
        "unknown_severity": sum(_normal_severity(finding) == "UNKNOWN" for finding in findings),
        "reachability": reachability,
    }


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


_PIPELINE_STAGES = (
    ("extraction", "Project Extraction"),
    ("dependencies", "Dependency Detection"),
    ("osv", "OSV Vulnerability Intelligence"),
    ("reachability", "Reachability Analysis"),
    ("risk", "Risk Prioritisation"),
)


def _normal_severity(finding) -> str:
    severity = _field_text(finding, "severity").upper()
    return severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "UNKNOWN"


def _render_theme() -> None:
    st.markdown("""
    <style>
    :root { --bg:#07111d; --panel:#0d1b2a; --panel2:#102235; --line:#263e51;
            --text:#edf4fa; --muted:#b0bfcd; --cyan:#54ddeb; --green:#52e6a0;
            --critical:#ff5265; --high:#ff9a45; --medium:#f4d35e; --low:#45d483; --unknown:#8b98a7; }
    html, body, [class*="st-"], [data-testid="stAppViewContainer"] { font-size:17px; }
    .stApp { background:radial-gradient(ellipse at 18% -15%, #10283c 0, transparent 42%), var(--bg); color:var(--text); }
    [data-testid="stSidebar"] { background:#091522; border-right:1px solid var(--line); min-width:250px; }
    [data-testid="stSidebar"] section { padding:1.25rem .9rem; }
    .block-container { max-width:1600px; padding:1.1rem clamp(1rem,2.3vw,2.5rem) 2.5rem; }
    h1,h2,h3 { color:#f2f7fb; letter-spacing:-.025em; }
    h1 { font-size:2rem !important; } h2 { font-size:1.55rem !important; } h3 { font-size:1.18rem !important; }
    p, li, label, [data-testid="stCaptionContainer"] { color:#d1dce6; }
    [data-testid="stCaptionContainer"] { font-size:.9rem; }
    .soc-brand { color:#f3f8fc; font-size:1.35rem; font-weight:760; letter-spacing:.02em; }
    .soc-subbrand { color:#a9bac9; font-size:.82rem; letter-spacing:.1em; text-transform:uppercase; margin-top:.25rem; }
    .soc-nav-link { display:flex; align-items:center; gap:.7rem; margin:.28rem 0; padding:.68rem .7rem;
       color:#c6d3de !important; text-decoration:none !important; font-size:.98rem; font-weight:560;
       border:1px solid transparent; border-radius:8px; transition:background-color .12s ease; }
    .soc-nav-icon { color:#77a0b7; width:1.25rem; text-align:center; font-size:1.05rem; }
    .soc-nav-link:hover, .soc-nav-link:focus-visible { background:#13283a; border-color:#29465c; color:#f2f7fb !important; }
    body:has(#security-overview:target) a[href="#security-overview"],
    body:has(#vulnerability-findings:target) a[href="#vulnerability-findings"],
    body:has(#dependency-inventory:target) a[href="#dependency-inventory"],
    body:has(#risk-analysis:target) a[href="#risk-analysis"],
    body:has(#scan-reports:target) a[href="#scan-reports"] { background:#142b3d; border-color:#2a4a60; color:#f4f9fc !important; }
    .soc-topbar { display:flex; align-items:center; justify-content:space-between; gap:1rem; padding:.9rem 1.1rem;
       border:1px solid var(--line); border-radius:12px; background:linear-gradient(110deg,#0d1b2a,#0b1926); margin:.5rem 0 1.1rem; }
    .soc-system { font-weight:700; color:#eaf4fb; letter-spacing:.02em; }
    .soc-meta { color:#b4c3d0; font-size:.92rem; }
    .soc-status { color:var(--green); font-weight:750; letter-spacing:.06em; white-space:nowrap; font-size:.9rem; }
    .soc-dot { display:inline-block; width:.55rem; height:.55rem; border-radius:50%; background:var(--green); margin-right:.45rem;
       box-shadow:0 0 10px #45e39a88; }
    .soc-stage { position:relative; display:grid; grid-template-columns:25px 1fr auto; align-items:center; gap:.6rem;
       padding:.64rem .2rem; color:var(--text); min-height:42px; }
    .soc-stage:not(:last-child)::after { content:""; position:absolute; left:12px; top:31px; height:23px; width:1px; background:#385064; }
    .soc-stage-label { font-size:.96rem; }
    .soc-stage-marker { display:grid; place-items:center; width:21px; height:21px; border-radius:50%;
       border:1px solid #52687a; color:#b0bfcd; background:#0d1b2a; font-size:.73rem; z-index:1; }
    .marker-completed { color:#081a12; background:var(--green); border-color:var(--green); }
    .marker-running { color:#071820; background:var(--cyan); border-color:var(--cyan); }
    .marker-failed { color:#fff; background:var(--critical); border-color:var(--critical); }
    .soc-stage-state { color:#b0bfcd; font-size:.82rem; text-transform:uppercase; letter-spacing:.06em; }
    .state-completed { color:var(--green); } .state-running { color:var(--cyan); } .state-failed { color:#ff7584; }
    .soc-card-grid { display:grid; grid-template-columns:repeat(6,minmax(110px,1fr)); gap:.7rem; margin:.8rem 0 1rem; }
    .soc-card { background:linear-gradient(145deg,#112538,#0b1926); border:1px solid #2a4154; border-top:3px solid var(--accent);
       border-radius:10px; padding:.95rem 1rem; min-height:102px; box-shadow:0 4px 14px #00000018; }
    .soc-card-label { font-size:.82rem; line-height:1.3; text-transform:uppercase; color:#c2cfda; letter-spacing:.075em; font-weight:650; }
    .soc-card-value { color:#f2f7fb; font-size:2.15rem; line-height:1.15; font-weight:790; margin-top:.38rem; font-variant-numeric:tabular-nums; }
    .soc-section-kicker { color:#66ddea; font-size:.78rem; font-weight:720; text-transform:uppercase; letter-spacing:.13em; margin-bottom:.35rem; }
    .soc-panel { border:1px solid var(--line); background:#0b1926; border-radius:12px; padding:1rem 1.1rem; }
    .soc-bar-row { display:grid; grid-template-columns:100px 1fr 45px; gap:.7rem; align-items:center; margin:.72rem 0; color:#c6d2dd; font-size:.92rem; }
    .soc-bar-track { height:10px; background:#1b3041; border-radius:8px; overflow:hidden; }
    .soc-bar-fill { height:100%; border-radius:8px; }
    .soc-scroll { overflow-x:auto; border:1px solid var(--line); border-radius:10px; background:#0b1926; }
    table.soc-queue { border-collapse:collapse; width:100%; min-width:800px; font-size:.98rem; }
    table.soc-queue th { position:sticky; top:0; z-index:1; text-align:left; color:#c2cfda; background:#102235;
       font-size:.8rem; letter-spacing:.065em; text-transform:uppercase; padding:.78rem .85rem; border-bottom:1px solid var(--line); }
    table.soc-queue td { padding:.78rem .85rem; border-bottom:1px solid #1b3041; color:#e1eaf1; }
    table.soc-queue tr:last-child td { border-bottom:0; }
    .tag { display:inline-block; border-radius:5px; padding:.22rem .48rem; font-weight:760; font-size:.83rem; white-space:nowrap; }
    .tag-CRITICAL { color:#ff6979; background:#ff52651c; border:1px solid #ff52654d; }
    .tag-HIGH { color:#ffab62; background:#ff9a4518; border:1px solid #ff9a4540; }
    .tag-MEDIUM { color:#f4d35e; background:#f4d35e18; border:1px solid #f4d35e40; }
    .tag-LOW { color:#55df93; background:#45d48318; border:1px solid #45d48340; }
    .tag-UNKNOWN { color:#a3afbd; background:#8b98a718; border:1px solid #8b98a740; }
    .risk-number { font-variant-numeric:tabular-nums; font-weight:820; font-size:1.08rem; color:#f1f6fa; }
    a { color:var(--cyan) !important; }
    [data-testid="stFileUploader"] section { background:#0d1b2a; border:1px dashed #38566d; border-radius:10px; }
    [data-testid="stFileUploader"] small, [data-testid="stFileUploader"] label { color:#d2dce5 !important; font-size:.92rem !important; }
    [data-testid="stFileUploaderDropzone"] { background:#0d1b2a; }
    [data-testid="stBaseButton-primary"] { min-height:2.8rem; padding:.55rem 1.1rem; font-weight:720; border:1px solid #28bfcf; background:#087c89; color:#f5fcff; }
    [data-testid="stBaseButton-primary"]:hover { background:#0a8d99; border-color:#61e0e9; }
    [data-baseweb="select"] > div, [data-baseweb="tag"] { background:#102235; border-color:#355066; }
    [data-testid="stVerticalBlockBorderWrapper"] { border-color:#263e51; background:#0b1926; }
    @media(max-width:1100px) { .soc-card-grid { grid-template-columns:repeat(3,minmax(100px,1fr)); }
       .soc-topbar { align-items:flex-start; flex-wrap:wrap; } }
    @media(max-width:720px) { .soc-card-grid { grid-template-columns:repeat(2,minmax(100px,1fr)); }
       .soc-topbar { flex-direction:column; } }
    </style>
    """, unsafe_allow_html=True)


def _render_sidebar() -> None:
    with st.sidebar:
        st.markdown('<div class="soc-brand">🛡️ VulnTriage</div><div class="soc-subbrand">Security Operations</div>', unsafe_allow_html=True)
        st.markdown("---")
        st.caption("NAVIGATION")
        for icon, label, anchor in (
            ("⌂", "Security Overview", "security-overview"),
            ("⚠", "Vulnerability Findings", "vulnerability-findings"),
            ("▤", "Dependency Inventory", "dependency-inventory"),
            ("◉", "Risk Analysis", "risk-analysis"),
            ("⇩", "Scan Reports", "scan-reports"),
        ):
            st.markdown(
                f'<a class="soc-nav-link" href="#{anchor}"><span class="soc-nav-icon">{icon}</span>{label}</a>',
                unsafe_allow_html=True,
            )
        st.markdown("---")
        st.caption("LOCAL ANALYSIS · OSV INTELLIGENCE")


def _render_topbar(scan_status: str, project_name: str, total: int | None, container=None) -> None:
    total_label = str(total) if total is not None else "—"
    safe_project = html.escape(project_name or "No project uploaded")
    safe_status = html.escape(scan_status.upper())
    markup = (
        '<div class="soc-topbar">'
        '<div><div class="soc-system">VulnTriage Security Operations</div>'
        f'<div class="soc-meta">Project · {safe_project}</div></div>'
        f'<div class="soc-meta">Scan status · <b>{safe_status}</b></div>'
        f'<div class="soc-meta">Vulnerabilities · <b>{total_label}</b></div>'
        '<div class="soc-status"><span class="soc-dot"></span>ENGINE READY</div>'
        '</div>'
    )
    target = container if container is not None else st
    target.markdown(markup, unsafe_allow_html=True)


def _render_pipeline(statuses: dict[str, str]) -> None:
    for stage, label in _PIPELINE_STAGES:
        state = statuses.get(stage, "pending")
        symbol = {"completed": "✓", "running": "●", "failed": "×", "pending": "○"}.get(state, "○")
        st.markdown(
            f'<div class="soc-stage"><span class="soc-stage-marker marker-{state}">{symbol}</span>'
            f'<span class="soc-stage-label">{html.escape(label)}</span>'
            f'<span class="soc-stage-state state-{state}">{html.escape(state)}</span></div>',
            unsafe_allow_html=True,
        )


def _risk_score(finding) -> float | None:
    if not isinstance(finding, dict):
        return None
    score = finding.get("risk_score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    try:
        return float(score) if math.isfinite(score) else None
    except (OverflowError, ValueError):
        return None


def _render_severity_chart(findings: list[dict]) -> None:
    colors = {
        "CRITICAL": "#ff5265", "HIGH": "#ff9a45", "MEDIUM": "#f4d35e",
        "LOW": "#45d483", "UNKNOWN": "#8b98a7",
    }
    counts = {severity: 0 for severity in colors}
    for finding in findings:
        counts[_normal_severity(finding)] += 1
    peak = max(counts.values(), default=0) or 1
    for severity, color in colors.items():
        count = counts[severity]
        width = round(100 * count / peak) if count else 0
        st.markdown(
            f'<div class="soc-bar-row"><span>{severity}</span><div class="soc-bar-track">'
            f'<div class="soc-bar-fill" style="width:{width}%;background:{color}"></div></div>'
            f'<b>{count}</b></div>', unsafe_allow_html=True,
        )


def _render_queue(findings: list[dict], vulnerability_records: list[dict], reachability_records: list[dict], scan_completed: bool) -> None:
    st.markdown('<div id="vulnerability-findings"></div><div class="soc-section-kicker">05 / Investigation queue</div>', unsafe_allow_html=True)
    st.header("Priority Investigation Queue")
    st.caption("Risk score is a deterministic triage heuristic. Filtered rows affect the queue and details; the report retains every finding.")
    severities = sorted({_normal_severity(item) for item in findings})
    finding_priorities = sorted({_field_text(item, "priority").upper() for item in findings})
    controls = st.columns([1.25, 1, 1, 1])
    sort_option = controls[0].selectbox("Sort queue", SORT_OPTIONS, index=0, key="soc-sort")
    selected_severities = controls[1].multiselect("Severity", severities, default=severities, key="soc-severity")
    selected_priorities = controls[2].multiselect("Priority", finding_priorities, default=finding_priorities, key="soc-priority")
    selected_reach = controls[3].selectbox("Reachability", ["All", "USED", "NOT_FOUND", "UNKNOWN"], key="soc-reachability")
    st.button("Reset filters", key="soc-reset-filters", on_click=_reset_queue_filters, help="Restore the full finding set.")
    sorted_findings = _prepare_queue(
        findings, set(selected_severities), set(selected_priorities), selected_reach, sort_option
    )

    if not scan_completed:
        st.info("Run a project scan to populate the investigation queue.")
        return
    if not findings:
        st.success("No vulnerability findings were returned by the analysis agents for this scan.")
        return
    if not sorted_findings:
        st.info("No findings match the selected filters.")
        return
    st.caption(f"Showing {len(sorted_findings)} of {len(findings)} findings · sorted by {sort_option}.")

    columns = ("package", "vulnerability_id", "installed_version", "severity", "risk_score", "reachability", "priority")
    labels = ("PACKAGE", "CVE / OSV ID", "INSTALLED", "SEVERITY", "RISK", "REACHABILITY", "PRIORITY")
    body = []
    for finding in sorted_findings:
        cells = []
        for field in columns:
            if field == "severity":
                severity = _normal_severity(finding)
                value = f'<span class="tag tag-{severity}">{severity}</span>'
            elif field == "risk_score":
                score = _risk_score(finding)
                value = f'<span class="risk-number">{score:.0f}</span>' if score is not None else "—"
            else:
                value = html.escape(_field_text(finding, field, "—"))
            cells.append(f"<td>{value}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    header = "".join(f"<th>{label}</th>" for label in labels)
    st.markdown(
        '<div class="soc-scroll"><table class="soc-queue"><thead><tr>' + header +
        "</tr></thead><tbody>" + "".join(body) + "</tbody></table></div>",
        unsafe_allow_html=True,
    )

    st.markdown('<div class="soc-section-kicker" style="margin-top:1.4rem">06 / Finding details</div>', unsafe_allow_html=True)
    st.subheader("Vulnerability Investigation")
    vuln_by_key = {
        (_field_text(record, "package", "").casefold(), _field_text(record, "vulnerability_id", "").casefold()): record
        for record in vulnerability_records if isinstance(record, dict)
    }
    reach_by_package = {}
    for record in reachability_records:
        if isinstance(record, dict):
            reach_by_package.setdefault(_field_text(record, "package", "").casefold(), []).append(record)

    for finding in sorted_findings:
        package = _field_text(finding, "package", "Unknown package")
        vuln_id = _field_text(finding, "vulnerability_id", "Unknown ID")
        severity = _normal_severity(finding)
        score = _risk_score(finding)
        score_label = f"{score:.0f}" if score is not None else "—"
        with st.expander(f"{severity}  ·  {package}  ·  {vuln_id}  ·  Risk {score_label}", expanded=False):
            vulnerability = vuln_by_key.get((package.casefold(), vuln_id.casefold()), {})
            left, right = st.columns(2)
            left.markdown("**Vulnerability summary**")
            left.write(_field_text(vulnerability, "summary", "Summary was not included in the OSV result."))
            left.markdown("**Risk explanation**")
            left.write(_field_text(finding, "risk_explanation", "Risk explanation unavailable."))
            left.markdown("**Risk factors**")
            factors = finding.get("risk_factors", []) if isinstance(finding, dict) else []
            if isinstance(factors, list) and factors:
                for factor in factors:
                    left.markdown(f"- {factor}")
            else:
                st.write("No risk factor details were provided.")
            right.markdown("**Versions and remediation**")
            right.write(f"Installed: {_field_text(finding, 'installed_version', 'Not provided')}")
            right.write(f"OSV fixed version: {_field_text(finding, 'recommended_version', 'Not provided')}")
            right.write(_field_text(finding, "recommendation", "No remediation instruction was provided."))
            right.markdown("**Reachability evidence**")
            records = reach_by_package.get(package.casefold(), [])
            evidence = []
            for record in records:
                items = record.get("evidence")
                if isinstance(items, list):
                    evidence.extend(item for item in items if isinstance(item, str) and item not in evidence)
            if evidence:
                for item in evidence:
                    right.code(item, language=None)
            else:
                right.write("No import evidence was provided for this finding.")
            references = vulnerability.get("references", []) if isinstance(vulnerability, dict) else []
            if isinstance(references, list) and references:
                right.markdown("**OSV references**")
                for reference in references:
                    if isinstance(reference, str) and reference.startswith(("https://", "http://")):
                        right.write(reference)


def _render_metrics(findings: list[dict], scan_completed: bool) -> None:
    severities = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    colors = {"CRITICAL": "#ff5265", "HIGH": "#ff9a45", "MEDIUM": "#f4d35e", "LOW": "#45d483", "UNKNOWN": "#8b98a7"}
    counts = {severity: sum(_normal_severity(item) == severity for item in findings) for severity in severities}
    cards = []
    for severity in ("TOTAL",) + severities:
        count = (len(findings) if severity == "TOTAL" else counts[severity]) if scan_completed else "—"
        color = "#48d8e8" if severity == "TOTAL" else colors[severity]
        label = "TOTAL VULNERABILITIES" if severity == "TOTAL" else severity
        cards.append(
            f'<div class="soc-card" style="--accent:{color}"><div class="soc-card-label">{label}</div>'
            f'<div class="soc-card-value">{count}</div></div>'
        )
    st.markdown('<div class="soc-card-grid">' + "".join(cards) + "</div>", unsafe_allow_html=True)


def _render_overview(
    findings: list[dict], statuses: dict[str, str], scan_completed: bool,
    live_pipeline_displayed: bool,
) -> None:
    st.markdown('<div id="security-overview"></div><div class="soc-section-kicker">01 / Security overview</div>', unsafe_allow_html=True)
    st.header("Threat Overview")
    _render_metrics(findings, scan_completed)
    if live_pipeline_displayed:
        with st.container(border=True):
            st.markdown('<div class="soc-section-kicker">03 / Threat intelligence</div>', unsafe_allow_html=True)
            st.subheader("Severity Distribution")
            if scan_completed:
                _render_severity_chart(findings)
            else:
                st.info("Distribution is available after the first completed scan.")
    else:
        left, right = st.columns([1.05, 1])
        with left:
            with st.container(border=True):
                st.markdown('<div class="soc-section-kicker">02 / Scan activity</div>', unsafe_allow_html=True)
                st.subheader("Investigation Pipeline")
                _render_pipeline(statuses)
        with right:
            with st.container(border=True):
                st.markdown('<div class="soc-section-kicker">03 / Threat intelligence</div>', unsafe_allow_html=True)
                st.subheader("Severity Distribution")
                if scan_completed:
                    _render_severity_chart(findings)
                else:
                    st.info("Distribution is available after the first completed scan.")
    risk_scores = [score for item in findings if (score := _risk_score(item)) is not None]
    used = sum(_field_text(item, "reachability").upper() == "USED" for item in findings)
    unknown = sum(_field_text(item, "reachability").upper() == "UNKNOWN" for item in findings)
    risk_columns = st.columns(4)
    unique_packages = len({_field_text(item, "package", "").casefold() for item in findings if _field_text(item, "package", "")})
    risk_columns[0].metric("Affected packages", unique_packages if scan_completed else "—")
    risk_columns[1].metric("Mean risk score", f"{sum(risk_scores) / len(risk_scores):.1f}" if risk_scores else "—")
    risk_columns[2].metric("Imports detected", used if scan_completed else "—")
    risk_columns[3].metric("Reachability unknown", unknown if scan_completed else "—")


def _render_inventory(dependencies: list[dict], scan_completed: bool) -> None:
    st.markdown('<div id="dependency-inventory"></div><div class="soc-section-kicker">04 / Dependency inventory</div>', unsafe_allow_html=True)
    st.header("Dependency Inventory")
    if not scan_completed:
        st.info("Dependency inventory will appear after scanning a project.")
        return
    if not dependencies:
        st.info("No dependencies were returned by the supported manifest scanners for this project.")
        return
    st.caption(f"{len(dependencies)} dependency records extracted from supported manifests and lockfiles.")
    rows = []
    for dependency in dependencies:
        if isinstance(dependency, dict):
            rows.append({key: dependency.get(key, "") for key in ("name", "version", "ecosystem", "source_file")})
    st.dataframe(rows, hide_index=True, use_container_width=True, height=min(440, 45 + 35 * len(rows)))


def _render_reports(findings: list[dict], scan_completed: bool) -> None:
    st.markdown('<div id="scan-reports"></div><div class="soc-section-kicker">07 / Reporting</div>', unsafe_allow_html=True)
    st.header("Scan Reports")
    st.caption("CSV contains all findings from this scan, regardless of queue filters or sort order.")
    if scan_completed:
        st.download_button(
            "⬇  Export complete CSV report",
            data=generate_csv_report(findings),
            file_name="vulntriage-report.csv",
            mime="text/csv",
            type="primary",
            use_container_width=False,
        )
    else:
        st.info("A complete CSV report will be available after a scan finishes.")


def _scan_with_progress(uploaded, upload_identity) -> None:
    statuses = {stage: "pending" for stage, _ in _PIPELINE_STAGES}
    data = {"dependencies": [], "vulnerabilities": [], "reachability": [], "findings": []}
    current_stage = "extraction"
    st.session_state["soc_scan_status"] = "scanning"
    st.session_state["soc_scan_project"] = uploaded.name
    st.session_state["soc_scan_upload"] = upload_identity
    with st.container(border=True):
        st.markdown('<div class="soc-section-kicker">LIVE / Scan activity</div>', unsafe_allow_html=True)
        st.subheader("Investigation Pipeline")
        progress_bar = st.progress(0, text="Project extraction pending")
        pipeline_slot = st.empty()

        def redraw():
            with pipeline_slot.container():
                _render_pipeline(statuses)

        redraw()
        try:
            archive_bytes = uploaded.getvalue()
            with tempfile.TemporaryDirectory(prefix="vulntriage-") as temporary_dir:
                current_stage = "extraction"
                statuses[current_stage] = "running"
                redraw()
                project_root = _extract_project_zip(archive_bytes, Path(temporary_dir))
                statuses[current_stage] = "completed"
                progress_bar.progress(20, text="Project extraction complete")
                redraw()

                stage_progress = {"dependencies": 40, "osv": 60, "reachability": 80, "risk": 100}
                stage_names = dict(_PIPELINE_STAGES)

                def on_progress(event: dict) -> None:
                    nonlocal current_stage
                    stage = event.get("stage")
                    state = event.get("status")
                    if stage not in stage_progress or state not in {"started", "completed"}:
                        return
                    current_stage = stage
                    if state == "started":
                        statuses[stage] = "running"
                        progress_bar.progress((stage_progress[stage] - 20), text=f"{stage_names[stage]} in progress")
                    else:
                        statuses[stage] = "completed"
                        data_key = {"dependencies": "dependencies", "osv": "vulnerabilities",
                                    "reachability": "reachability", "risk": "findings"}[stage]
                        data[data_key] = event.get("data", [])
                        progress_bar.progress(stage_progress[stage], text=f"{stage_names[stage]} complete")
                    redraw()

                findings = run_vulntriage(str(project_root), progress_callback=on_progress)
            st.session_state["vulntriage_findings"] = findings
            st.session_state["vulntriage_upload"] = upload_identity
            st.session_state["soc_scan_data"] = data
            st.session_state["soc_pipeline_statuses"] = statuses
            st.session_state["soc_scan_status"] = "completed"
            for key, value in _queue_filter_defaults(findings).items():
                st.session_state[key] = value
            st.session_state.pop("vulntriage_error", None)
            progress_bar.progress(100, text="All analysis stages complete")
        except Exception as error:
            statuses[current_stage] = "failed"
            st.session_state["soc_pipeline_statuses"] = statuses
            st.session_state["soc_scan_status"] = "failed"
            st.session_state["vulntriage_error"] = f"The scan could not be completed: {error}"
            st.session_state.pop("vulntriage_findings", None)
            progress_bar.progress(0, text=f"{dict(_PIPELINE_STAGES)[current_stage]} failed")
            redraw()


def main() -> None:
    st.set_page_config(page_title="VulnTriage SOC", page_icon="🛡️", layout="wide")
    _render_theme()
    _render_sidebar()

    st.markdown('<div class="soc-brand">VulnTriage</div><div class="soc-subbrand">Dependency Vulnerability Triage Agent</div>', unsafe_allow_html=True)
    st.write("Security operations console for dependency exposure, reachability signals, and remediation triage.")
    topbar_slot = st.empty()
    uploaded = st.file_uploader(
        "Load Python or npm project archive",
        type=["zip"],
        help="Supports requirements.txt and npm package.json/package-lock.json projects.",
        label_visibility="collapsed",
    )
    upload_identity = (uploaded.name, uploaded.size) if uploaded is not None else None
    if uploaded is not None and uploaded.size > MAX_UPLOAD_BYTES:
        st.error("The ZIP exceeds the 100 MB upload limit. Please provide a smaller archive.")
    scan_button = st.button(
        "▶  Start Security Scan", type="primary",
        disabled=(uploaded is None or uploaded.size > MAX_UPLOAD_BYTES),
        use_container_width=False,
    )
    if scan_button and uploaded is not None:
        st.session_state["soc_scan_status"] = "scanning"
        st.session_state["soc_scan_project"] = uploaded.name
        st.session_state["soc_scan_upload"] = upload_identity
        _render_topbar("scanning", uploaded.name, None, topbar_slot)
    if scan_button and uploaded is not None:
        _scan_with_progress(uploaded, upload_identity)

    matching_scan = (
        upload_identity is not None
        and st.session_state.get("vulntriage_upload") == upload_identity
        and "vulntriage_findings" in st.session_state
    )
    findings = st.session_state.get("vulntriage_findings", []) if matching_scan else []
    scan_status = st.session_state.get("soc_scan_status", "ready" if uploaded else "idle")
    if uploaded is not None and not matching_scan and st.session_state.get("soc_scan_upload") != upload_identity:
        scan_status = "ready"
    total = len(findings) if matching_scan else None
    _render_topbar(
        scan_status,
        uploaded.name if uploaded else st.session_state.get("soc_scan_project", ""),
        total,
        topbar_slot,
    )
    if st.session_state.get("vulntriage_error") and scan_status == "failed":
        st.error(st.session_state["vulntriage_error"])

    statuses = st.session_state.get("soc_pipeline_statuses", {stage: "pending" for stage, _ in _PIPELINE_STAGES})
    if not matching_scan and scan_status not in {"scanning", "failed"}:
        statuses = {stage: "pending" for stage, _ in _PIPELINE_STAGES}
    data = st.session_state.get("soc_scan_data", {}) if matching_scan else {}
    dependencies = data.get("dependencies", []) if isinstance(data, dict) else []
    vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    reachability = data.get("reachability", []) if isinstance(data, dict) else []

    _render_overview(findings, statuses, matching_scan, scan_button)
    if scan_status == "idle" and not matching_scan:
        st.info("Upload a project ZIP and start a scan to populate the investigation console.")
    _render_queue(findings, vulnerabilities, reachability, matching_scan)
    _render_inventory(dependencies, matching_scan)
    st.markdown('<div id="risk-analysis"></div><div class="soc-section-kicker">08 / Risk analysis</div>', unsafe_allow_html=True)
    st.header("Risk Analysis")
    if matching_scan and findings:
        risk_summary = _risk_analysis_summary(findings)
        analysis_columns = st.columns(5)
        average = risk_summary["average"]
        highest = risk_summary["highest"]
        analysis_columns[0].metric("Average risk score", f"{average:.1f}" if average is not None else "—")
        analysis_columns[1].metric("Highest risk score", f"{highest:.0f}" if highest is not None else "—")
        analysis_columns[2].metric("Unknown Severity", risk_summary["unknown_severity"])
        analysis_columns[3].metric("Unknown Reachability", risk_summary["reachability"]["UNKNOWN"])
        analysis_columns[4].metric("Total findings", len(findings))
        st.caption(
            "Unknown Severity: OSV did not provide a recognized severity label. "
            "Unknown Reachability: source analysis could not determine whether the package is imported. "
            "Review these findings using the advisory and source evidence."
        )
        st.markdown("**Reachability breakdown**")
        breakdown = risk_summary["reachability"]
        reach_columns = st.columns(3)
        reach_columns[0].metric("USED", breakdown["USED"])
        reach_columns[1].metric("NOT_FOUND", breakdown["NOT_FOUND"])
        reach_columns[2].metric("UNKNOWN", breakdown["UNKNOWN"])
        st.caption("Scores are triage heuristics, not probabilities of exploitation. Review the factor-by-factor explanation for each finding.")
    elif matching_scan:
        st.info("The completed scan returned no vulnerability findings to score.")
    else:
        st.info("Risk statistics will appear after a completed scan returns findings.")
    _render_reports(findings if matching_scan else [], matching_scan)
    st.caption("Import detection does not prove exploitability. NOT_FOUND does not establish that a dependency is unused or safe.")


if __name__ == "__main__":
    main()
