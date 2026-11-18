"""Deterministic, conservative upgrade compatibility assessments.

This module does not install packages, inspect or change uploaded source code,
query external services, or claim that an upgrade is compatible. OSV fixed
versions are treated only as candidate versions that require developer review.
"""

from __future__ import annotations

import re
from typing import Any


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _ecosystem(record: dict[str, Any]) -> str | None:
    value = _text(record.get("ecosystem"))
    if not value:
        return None
    return {"pypi": "PyPI", "npm": "npm", "maven": "Maven"}.get(value.casefold(), value)


def _package_identity(ecosystem: str, package: str) -> str:
    if ecosystem == "Maven":
        # Maven coordinates are exact identifiers. Do not normalize punctuation
        # or case, either of which could join distinct coordinates.
        return package.strip()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", package).casefold()
    if ecosystem == "npm":
        return package.casefold()
    return package.casefold()


def _identity(record: dict[str, Any], package_field: str) -> tuple[str, str] | None:
    ecosystem = _ecosystem(record)
    package = _text(record.get(package_field))
    if ecosystem is None or not package:
        return None
    return ecosystem, _package_identity(ecosystem, package)


def _resolved_literal_version(value: Any) -> str | None:
    """Accept only a conservative literal version, preserving it verbatim."""
    version = _text(value)
    if not version or any(character.isspace() for character in version):
        return None
    if any(token in version for token in ("$", "${", "}", "<", ">", "=", "!", "~", "^", "*", ",", "|")):
        return None
    if version.startswith(("[", "(", "-e ")) or "://" in version:
        return None
    if version.endswith("+") or ".+" in version:
        return None
    if version.casefold() in {"latest", "latest.release", "latest.integration"}:
        return None
    # Common npm wildcard selectors are not exact resolved versions.
    if re.search(r"(?:^|\.)x(?:$|\.)", version, re.IGNORECASE):
        return None
    return version


def _records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [record for record in value if isinstance(record, dict)]


def analyze_compatibility(
    dependencies: list,
    vulnerabilities: list,
    reachability: list,
) -> list[dict[str, Any]]:
    """Assess whether OSV fixes have enough context for compatibility review.

    Returns one assessment per ecosystem-qualified vulnerable package. A
    ``REVIEW_REQUIRED`` result means a matching OSV fix and a consistent,
    literal installed version were found; compatibility itself remains
    unverified. All other cases return ``NOT_ASSESSED``.
    """
    dependencies_by_identity: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for dependency in _records(dependencies):
        identity = _identity(dependency, "name")
        if identity is not None:
            dependencies_by_identity.setdefault(identity, []).append(dependency)

    vulnerabilities_by_identity: dict[tuple[str, str], list[dict[str, Any]]] = {}
    package_names: dict[tuple[str, str], str] = {}
    for vulnerability in _records(vulnerabilities):
        identity = _identity(vulnerability, "package")
        if identity is None:
            continue
        vulnerabilities_by_identity.setdefault(identity, []).append(vulnerability)
        package_names.setdefault(identity, _text(vulnerability.get("package")))

    reachability_by_identity: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in _records(reachability):
        identity = _identity(record, "package")
        if identity is not None:
            reachability_by_identity.setdefault(identity, []).append(record)

    assessments: list[dict[str, Any]] = []
    for identity, vuln_records in vulnerabilities_by_identity.items():
        ecosystem, _normalized_package = identity
        package = package_names[identity]
        dependency_records = dependencies_by_identity.get(identity, [])
        matching_reachability = reachability_by_identity.get(identity, [])

        candidate_versions: list[str] = []
        evidence_used: list[str] = []
        explanations: list[str] = []
        installed_versions: set[str] = set()
        version_data_incomplete = False

        for dependency in dependency_records:
            raw_version = dependency.get("version")
            version = _resolved_literal_version(raw_version)
            if version is None:
                version_data_incomplete = True
                if _text(raw_version):
                    explanations.append("A dependency version is a range, unresolved value, or otherwise not an exact version.")
            else:
                installed_versions.add(version)
                source_file = _text(dependency.get("source_file"))
                detail = f"Dependency version {version}"
                if source_file:
                    detail += f" from {source_file}"
                if detail not in evidence_used:
                    evidence_used.append(detail)

        for vulnerability in vuln_records:
            installed = _resolved_literal_version(vulnerability.get("installed_version"))
            if installed is None:
                version_data_incomplete = True
                explanations.append("An OSV finding is missing a usable exact installed version.")
            else:
                installed_versions.add(installed)

            vuln_id = _text(vulnerability.get("vulnerability_id")) or "OSV finding"
            raw_fixed = vulnerability.get("fixed_versions")
            if isinstance(raw_fixed, (list, tuple)):
                for raw_candidate in raw_fixed:
                    candidate = _text(raw_candidate)
                    # Candidate provenance remains the supplied OSV record. Do
                    # not derive or transform any version strings here.
                    if candidate and _resolved_literal_version(candidate) is None:
                        explanations.append("An OSV fixed-version value is unresolved or not a single literal version.")
                    elif candidate and candidate not in candidate_versions:
                        candidate_versions.append(candidate)
                        evidence_used.append(f"{vuln_id} lists OSV fixed version {candidate}")

        if len(installed_versions) > 1:
            explanations.append("Dependency and OSV records contain conflicting installed versions.")
        if not dependency_records:
            explanations.append("No dependency record matched this vulnerability by ecosystem and package identity.")
        if not candidate_versions:
            explanations.append("No fixed-version candidate was supplied by a matching OSV finding.")
        if not matching_reachability:
            explanations.append("No reachability record matched this ecosystem and package; source usage context is unavailable.")
        else:
            for record in matching_reachability:
                status = _text(record.get("status")).upper()
                if status:
                    evidence_used.append(f"Reachability status: {status}")
                values = record.get("evidence")
                if isinstance(values, (list, tuple)):
                    evidence_used.extend(
                        item for item in values
                        if isinstance(item, str) and item.strip() and item not in evidence_used
                    )

        installed_version = next(iter(installed_versions)) if len(installed_versions) == 1 else ""
        version_consistent = (
            bool(dependency_records)
            and not version_data_incomplete
            and len(installed_versions) == 1
        )
        status = (
            "REVIEW_REQUIRED"
            if candidate_versions and version_consistent
            else "NOT_ASSESSED"
        )
        if status == "REVIEW_REQUIRED":
            explanations.append(
                "A matching OSV fixed-version candidate and a consistent installed version are available, "
                "but API compatibility and application behavior have not been verified. Test the upgrade before deployment."
            )
        else:
            explanations.append(
                "Compatibility was not assessed because the required package, version, or OSV fix information is missing or ambiguous."
            )

        assessments.append({
            "package": package,
            "ecosystem": ecosystem,
            "installed_version": installed_version,
            "candidate_fixed_versions": candidate_versions,
            "assessment_status": status,
            "evidence_used": evidence_used,
            "explanation": " ".join(dict.fromkeys(explanations)),
        })

    return assessments


# A descriptive alias for callers that prefer a verb phrase.
assess_compatibility = analyze_compatibility
