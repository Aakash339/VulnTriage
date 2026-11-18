"""Build deterministic, evidence-aware remediation findings."""

from __future__ import annotations

from typing import Any

from utils.risk_engine import calculate_risk


_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_PRIORITY_DOWNGRADE = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "INFO"}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _package_key(record: dict) -> str:
    return _text(record.get("package")).casefold()


def _fixed_versions(record: dict) -> list[str]:
    versions = record.get("fixed_versions", [])
    if not isinstance(versions, (list, tuple)):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for value in versions:
        version = _text(value)
        key = version.casefold()
        if version and key not in seen:
            seen.add(key)
            result.append(version)
    return result


def _priority(severity: str, reachability: str) -> str:
    if severity not in _SEVERITIES or reachability == "UNKNOWN":
        return "UNKNOWN"
    if reachability == "NOT_FOUND":
        return _PRIORITY_DOWNGRADE[severity]
    return severity


def _recommendation(package: str, versions: list[str]) -> tuple[str, str]:
    if not versions:
        return (
            "No fixed version identified by OSV",
            "No fixed version identified by OSV. Review the advisory and package "
            "maintainer guidance for mitigation; do not assume the installed version is safe.",
        )
    if len(versions) == 1:
        version = versions[0]
        return (
            version,
            f"Upgrade {package} to the OSV-reported fixed version {version}, then "
            "test the application and dependency compatibility before deployment.",
        )
    joined = ", ".join(versions)
    return (
        f"Multiple fixed versions available: {joined}",
        f"OSV reports these fixed versions for {package}: {joined}. Select a version "
        "after checking the advisory's affected ranges and testing application compatibility.",
    )


def generate_remediation(vulnerabilities: list, reachability: list) -> list:
    """Combine vulnerability and reachability records into RemediationFinding dicts.

    Missing or conflicting reachability data remains UNKNOWN. NOT_FOUND indicates
    no source use was found; it is not treated as proof that a dependency is safe.
    """
    vuln_records = [r for r in vulnerabilities if isinstance(r, dict)] if isinstance(vulnerabilities, list) else []
    reach_records = [r for r in reachability if isinstance(r, dict)] if isinstance(reachability, list) else []

    statuses: dict[str, set[str]] = {}
    reach_records_by_package: dict[str, list[dict]] = {}
    for record in reach_records:
        package = _package_key(record)
        status = _text(record.get("status")).upper()
        if package:
            statuses.setdefault(package, set()).add(status if status in {"USED", "NOT_FOUND", "UNKNOWN"} else "UNKNOWN")
            reach_records_by_package.setdefault(package, []).append(record)

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for vulnerability in vuln_records:
        package = _text(vulnerability.get("package"))
        vuln_id = _text(vulnerability.get("vulnerability_id"))
        if not package or not vuln_id:
            continue
        dedupe_key = (package.casefold(), vuln_id.casefold(), _text(vulnerability.get("installed_version")).casefold())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        raw_severity = _text(vulnerability.get("severity")).upper()
        severity = raw_severity if raw_severity in _SEVERITIES else "UNKNOWN"
        matches = statuses.get(package.casefold(), set())
        reach = next(iter(matches)) if len(matches) == 1 else "UNKNOWN"
        recommended, recommendation = _recommendation(package, _fixed_versions(vulnerability))
        evidence = []
        for record in reach_records_by_package.get(package.casefold(), []):
            values = record.get("evidence")
            if isinstance(values, (list, tuple)):
                for value in values:
                    if isinstance(value, str) and value.strip() and value not in evidence:
                        evidence.append(value)
        risk = calculate_risk(vulnerability, {"package": package, "status": reach, "evidence": evidence})
        findings.append({
            "package": package,
            "vulnerability_id": vuln_id,
            "severity": severity,
            "reachability": reach,
            "priority": _priority(severity, reach),
            "installed_version": _text(vulnerability.get("installed_version")),
            "recommended_version": recommended,
            "recommendation": recommendation,
            **risk,
        })
    return findings
