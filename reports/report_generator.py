"""CSV export helpers for VulnTriage reports."""

import csv
import io
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
)


def generate_csv_report(findings: list) -> bytes:
    """Return findings as UTF-8 CSV bytes, including a header for no findings."""
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow([label for label, _ in _COLUMNS])
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, Mapping):
                continue
            writer.writerow([_csv_value(finding.get(key)) for _, key in _COLUMNS])
    return output.getvalue().encode("utf-8")


def _csv_value(value) -> str:
    if isinstance(value, (list, tuple)):
        return "; ".join(str(item) for item in value)
    return value if isinstance(value, str) else ("" if value is None else str(value))
