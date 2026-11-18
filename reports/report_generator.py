"""CSV export helpers for VulnTriage reports."""

import csv
import io
import re
from collections.abc import Mapping


_COLUMNS = (
    ("Package", "package"),
    ("Vulnerability ID", "vulnerability_id"),
    ("Severity", "severity"),
    ("Reachability", "reachability"),
    ("Priority", "priority"),
    ("Risk Score", "risk_score"),
    ("Risk Level", "risk_level"),
    ("Risk Factors", "risk_factors"),
    ("Risk Explanation", "risk_explanation"),
    ("Installed Version", "installed_version"),
    ("Recommended Version", "recommended_version"),
    ("Recommendation", "recommendation"),
    ("Reachability Evidence", "reachability_evidence"),
    ("Reachability Interpretation", "reachability_interpretation"),
    ("Ecosystem", "ecosystem"),
)
_REACHABILITY_STATUSES = {"USED", "NOT_FOUND", "UNKNOWN"}
_REACHABILITY_INTERPRETATIONS = {
    "USED": "Static import evidence was detected. This does not prove runtime execution or exploitability.",
    "NOT_FOUND": "No matching import was detected in supported files. This does not prove the dependency is unused or safe.",
    "UNKNOWN": "Reachability could not be determined confidently.",
}
_PACKAGE_SEPARATORS = re.compile(r"[-_.]+")


def generate_csv_report(findings: list, reachability: list | None = None) -> bytes:
    """Return findings as UTF-8 CSV bytes, optionally enriched with raw reachability evidence.

    The optional argument preserves compatibility with existing one-argument
    callers. Findings are never filtered or reordered by this report helper.
    """
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow([label for label, _ in _COLUMNS])
    reachability_by_package = _reachability_by_package(reachability)
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, Mapping):
                continue
            record = reachability_by_package.get(_record_key(finding), {})
            status = _status(finding.get("reachability"), record.get("status"))
            evidence = record.get("evidence", [])
            evidence_value = "\n".join(evidence) if evidence else "No static import evidence available"
            row = [_csv_value(finding.get(key)) for _, key in _COLUMNS
                   if key not in {"reachability_evidence", "reachability_interpretation", "ecosystem"}]
            row.extend((evidence_value, _REACHABILITY_INTERPRETATIONS[status], _csv_value(finding.get("ecosystem"))))
            writer.writerow(row)
    return output.getvalue().encode("utf-8")


def _package_key(value, ecosystem=None) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    ecosystem = ecosystem.strip().casefold() if isinstance(ecosystem, str) else ""
    if ecosystem == "maven":
        # Maven groupId:artifactId coordinates are exact identifiers.
        return value.strip()
    if ecosystem == "npm":
        return value.strip().casefold()
    return _PACKAGE_SEPARATORS.sub("-", value.strip()).casefold()


def _record_key(record):
    ecosystem = record.get("ecosystem") if isinstance(record, Mapping) else None
    normalized_ecosystem = ecosystem.strip().casefold() if isinstance(ecosystem, str) and ecosystem.strip() else None
    canonical = {"pypi": "PyPI", "npm": "npm", "maven": "Maven"}.get(normalized_ecosystem, normalized_ecosystem)
    return canonical, _package_key(record.get("package"), canonical)


def _status(value, fallback="UNKNOWN") -> str:
    candidate = value.strip().upper() if isinstance(value, str) else ""
    if candidate not in _REACHABILITY_STATUSES:
        candidate = fallback.strip().upper() if isinstance(fallback, str) else "UNKNOWN"
    return candidate if candidate in _REACHABILITY_STATUSES else "UNKNOWN"


def _reachability_by_package(records) -> dict[tuple[str | None, str], dict[str, object]]:
    """Collect and deduplicate evidence from raw reachability records."""
    result: dict[tuple[str | None, str], dict[str, object]] = {}
    if not isinstance(records, (list, tuple)):
        return result
    for record in records:
        if not isinstance(record, Mapping):
            continue
        key = _record_key(record)
        if not key[1]:
            continue
        status = _status(record.get("status"))
        evidence_value = record.get("evidence")
        evidence = [item.strip() for item in evidence_value if isinstance(item, str) and item.strip()] \
            if isinstance(evidence_value, (list, tuple)) else []
        existing = result.get(key)
        if existing is None:
            result[key] = {"status": status, "evidence": list(dict.fromkeys(evidence))}
            continue
        if existing["status"] != status:
            existing["status"] = "UNKNOWN"
        existing["evidence"] = list(dict.fromkeys([*existing["evidence"], *evidence]))
    return result


def _csv_value(value) -> str:
    if isinstance(value, (list, tuple)):
        return "; ".join(str(item) for item in value)
    return value if isinstance(value, str) else ("" if value is None else str(value))
