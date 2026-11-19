"""Conservative, evidence-grounded source change suggestions.

The current VulnTriage compatibility and API-impact records do not contain
verified replacement APIs or code examples. Therefore this MVP reports the
observed code and gives explicitly illustrative review guidance, but never
fabricates a replacement snippet or claims an upgrade is safe.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


_ILLUSTRATIVE_GUIDANCE = (
    "Illustrative guidance only: review the package maintainer's upgrade notes and tests, "
    "then update the application only when a documented replacement is identified."
)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _ecosystem(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    return {"pypi": "PyPI", "npm": "npm", "maven": "Maven"}.get(value.casefold(), value)


def _identity(record: dict[str, Any], package_field: str) -> tuple[str, str] | None:
    ecosystem = _ecosystem(record.get("ecosystem"))
    package = _text(record.get(package_field))
    if not ecosystem or not package:
        return None
    if ecosystem == "Maven":
        normalized = package
    elif ecosystem == "PyPI":
        normalized = re.sub(r"[-_.]+", "-", package).casefold()
    else:
        normalized = package.casefold()
    return ecosystem, normalized


def _records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [record for record in value if isinstance(record, dict)]


def _candidate_values(record: dict[str, Any]) -> list[str]:
    values = record.get("candidate_fixed_versions")
    if not isinstance(values, (list, tuple)):
        return []
    return list(dict.fromkeys(item.strip() for item in values if isinstance(item, str) and item.strip()))


def _safe_source_path(project_path: str, source_file: str) -> Path | None:
    """Resolve an API-impact path only when it stays inside the project root."""
    if not source_file:
        return None
    try:
        relative = Path(source_file)
        if relative.is_absolute():
            return None
        root = Path(project_path).resolve()
        resolved = (root / relative).resolve()
        if not resolved.is_relative_to(root):
            return None
        return resolved
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


def _current_line(path: Path | None, line_number: int) -> str | None:
    if path is None or line_number < 1:
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return None
    if line_number > len(lines):
        return None
    return lines[line_number - 1].strip() or None


def generate_code_suggestions(
    project_path: str,
    api_impact_results: list,
    compatibility_assessments: list,
) -> list[dict[str, Any]]:
    """Build one conservative suggestion record per identifiable API usage.

    A source usage is emitted only when its ecosystem-qualified package exists
    in the dependency inventory. A proposed code snippet is populated only if
    the supplied evidence record explicitly contains a documented safe
    alternative and its supporting source; current VulnTriage contracts do not
    provide those fields, so the result is ``NO_SAFE_SUGGESTION`` by default.
    """
    compatibility: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in _records(compatibility_assessments):
        identity = _identity(record, "package")
        if identity is not None:
            compatibility.setdefault(identity, []).append(record)

    suggestions: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, int, str]] = set()
    for impact in _records(api_impact_results):
        identity = _identity(impact, "package")
        if identity is None:
            continue
        ecosystem, package_key = identity
        package = _text(impact.get("package"))
        related_assessments = compatibility.get(identity, [])

        # No code finding means there is no source-specific suggestion to make.
        usages = impact.get("usages")
        if not isinstance(usages, (list, tuple)):
            continue
        for usage in usages:
            if not isinstance(usage, dict):
                continue
            source_file = _text(usage.get("source_file"))
            reference = _text(usage.get("reference"))
            raw_line = usage.get("line_number")
            line_number = raw_line if isinstance(raw_line, int) and not isinstance(raw_line, bool) else 0
            if not source_file or not reference or line_number < 1:
                continue
            suffix = Path(source_file).suffix.casefold()
            language_supported = (
                ecosystem == "PyPI" and suffix == ".py"
            ) or (
                ecosystem == "npm" and suffix in {".js", ".jsx", ".ts", ".tsx"}
            )

            unique = (ecosystem, package_key, source_file, line_number, reference)
            if unique in seen:
                continue
            seen.add(unique)

            source_path = _safe_source_path(project_path, source_file) if language_supported else None
            current_snippet = _current_line(source_path, line_number)
            snapshot_statement = _text(usage.get("statement"))
            snippet_source = "current file"
            explanation_parts: list[str] = []
            if current_snippet is None and snapshot_statement:
                # Retain scan-time evidence if the source file was removed or
                # unreadable, while clearly distinguishing it from live content.
                current_snippet = snapshot_statement
                snippet_source = "scan-time evidence"
                explanation_parts.append(
                    "The source file is missing, unreadable, or no longer has this line; the snippet is retained from scan-time evidence."
                )
            elif current_snippet is None:
                explanation_parts.append("The source file or referenced line is unavailable, so current code could not be confirmed.")

            if not related_assessments:
                explanation_parts.append("No compatibility assessment matched this ecosystem and package identity.")
            elif len(related_assessments) > 1:
                assessment_versions = {
                    _text(record.get("installed_version")) for record in related_assessments
                }
                assessment_candidates = {
                    tuple(_candidate_values(record)) for record in related_assessments
                }
                assessment_statuses = {
                    _text(record.get("assessment_status")).upper() for record in related_assessments
                }
                if (len(assessment_versions) > 1 or len(assessment_candidates) > 1
                        or len(assessment_statuses) > 1):
                    explanation_parts.append("Matching compatibility records conflict; candidate provenance is ambiguous.")

            impact_version = _text(impact.get("installed_version"))
            compatibility_versions = {
                _text(record.get("installed_version"))
                for record in related_assessments if _text(record.get("installed_version"))
            }
            versions_conflict = bool(
                impact_version and compatibility_versions
                and compatibility_versions != {impact_version}
            )
            if versions_conflict:
                explanation_parts.append(
                    "API-impact and compatibility records disagree on the installed version; candidate association is not reliable."
                )

            if not language_supported:
                explanation_parts.append("This source language is not supported for code suggestions.")

            impact_candidates = _candidate_values(impact)
            compatibility_candidate_sets = {
                tuple(_candidate_values(record)) for record in related_assessments
            }
            candidate_conflict = bool(
                impact_candidates
                and compatibility_candidate_sets
                and any(set(values) != set(impact_candidates) for values in compatibility_candidate_sets)
            )
            if candidate_conflict:
                explanation_parts.append(
                    "API-impact and compatibility records disagree on fixed-version candidates; candidate provenance is not reliable."
                )
            candidates = [] if versions_conflict or candidate_conflict else list(impact_candidates)
            if len(related_assessments) == 1 and not versions_conflict:
                assessment = related_assessments[0]
                if not candidate_conflict:
                    for candidate in _candidate_values(assessment):
                        if candidate not in candidates:
                            candidates.append(candidate)
            elif len(related_assessments) > 1 and not versions_conflict and not candidate_conflict:
                version_signatures = {
                    (
                        _text(record.get("installed_version")),
                        tuple(_candidate_values(record)),
                    )
                    for record in related_assessments
                }
                if len(version_signatures) == 1:
                    for candidate in _candidate_values(related_assessments[0]):
                        if candidate not in candidates:
                            candidates.append(candidate)
                else:
                    candidates = []

            # No current input contract contains a documented replacement API
            # plus its source. Do not transform the observed snippet into code.
            proposed_snippet = None
            status = "NO_SAFE_SUGGESTION"
            explanation_parts.append(
                "Static source evidence identifies this import/API reference, but no verified replacement API or code example is available."
            )
            explanation_parts.append(
                "No code change is proposed. This analysis does not establish that an upgrade is compatible or that a change fixes the vulnerability."
            )
            if candidates:
                explanation_parts.append(
                    "The listed version is an OSV-derived candidate from the matching compatibility record, not a verified compatible upgrade."
                )
            explanation_parts.append(_ILLUSTRATIVE_GUIDANCE)

            evidence: list[str] = []
            if snapshot_statement:
                evidence.append(f"API impact {source_file}:{line_number}: {snapshot_statement}")
            evidence.append(f"Detected {usage.get('kind', 'source')} reference: {reference}")
            if snippet_source == "current file":
                evidence.append(f"Read current source line {source_file}:{line_number}")
            if candidates:
                for candidate in candidates:
                    origin = "API impact record" if candidate in impact_candidates else "matching compatibility assessment"
                    evidence.append(f"{origin} lists OSV fixed-version candidate: {candidate}")

            suggestions.append({
                "package": package,
                "ecosystem": ecosystem,
                "source_file": source_file,
                "line_number": line_number,
                "detected_reference": reference,
                "current_code_snippet": current_snippet,
                "proposed_code_snippet": proposed_snippet,
                "guidance": _ILLUSTRATIVE_GUIDANCE,
                "guidance_type": "ILLUSTRATIVE",
                "candidate_fixed_versions": candidates,
                "evidence": evidence,
                "explanation": " ".join(dict.fromkeys(explanation_parts)),
                "confidence": "LOW",
                "review_status": status,
            })

    return suggestions


suggest_code_changes = generate_code_suggestions
