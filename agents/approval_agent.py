"""Prepare developer review records and record one explicit decision per proposal.

This module is an in-memory review helper only. It never edits project files,
applies upgrades, executes code, or assigns a reviewer identity. Callers must
persist the returned proposal list if they need decisions to survive a process
restart.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any


_REVIEW_DECISIONS = {"PENDING", "APPROVED", "REJECTED"}
_CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}
_TEST_STATUSES = {"PASSED", "FAILED", "NOT_RUN"}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _ecosystem(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    return {"pypi": "PyPI", "npm": "npm", "maven": "Maven"}.get(value.casefold(), value)


def _identity(record: dict[str, Any], package_field: str = "package") -> tuple[str, str] | None:
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


def _strings(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return list(dict.fromkeys(item.strip() for item in value if isinstance(item, str) and item.strip()))


def _source_evidence(api_impacts: list[dict[str, Any]], code_suggestions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()

    for impact in api_impacts:
        usages = impact.get("usages")
        if not isinstance(usages, (list, tuple)):
            continue
        for usage in usages:
            if not isinstance(usage, dict):
                continue
            path = _text(usage.get("source_file"))
            line = usage.get("line_number")
            reference = _text(usage.get("reference"))
            if not path or not isinstance(line, int) or isinstance(line, bool) or line < 1:
                continue
            key = (path, line, reference)
            if key in seen:
                continue
            seen.add(key)
            result.append({
                "source_file": path,
                "line_number": line,
                "reference": reference,
                "current_code_snippet": _text(usage.get("statement")) or None,
                "evidence": _text(usage.get("statement")) or reference,
            })

    for suggestion in code_suggestions:
        path = _text(suggestion.get("source_file"))
        line = suggestion.get("line_number")
        reference = _text(suggestion.get("detected_reference"))
        if not path or not isinstance(line, int) or isinstance(line, bool) or line < 1:
            continue
        key = (path, line, reference)
        if key in seen:
            continue
        seen.add(key)
        result.append({
            "source_file": path,
            "line_number": line,
            "reference": reference,
            "current_code_snippet": _text(suggestion.get("current_code_snippet")) or None,
            "evidence": _text(suggestion.get("current_code_snippet")) or reference,
        })
    return result


def _explicit_change(suggestion: dict[str, Any], candidates: set[str], installed: str) -> tuple[str, str | None]:
    if _text(suggestion.get("review_status")).upper() != "REVIEW_REQUIRED":
        return "", None
    change = suggestion.get("proposed_dependency_change")
    if not isinstance(change, dict):
        return "", None
    current = _text(change.get("from_version"))
    proposed = _text(change.get("to_version"))
    if not current or not proposed or current != installed or proposed not in candidates:
        return "", None
    return proposed, _text(change.get("manifest_file")) or None


def _test_matches_change(record: dict[str, Any], identity: tuple[str, str], installed: str,
                         proposed: str) -> bool:
    if not proposed:
        return False
    changes = record.get("tested_dependency_changes")
    if not isinstance(changes, (list, tuple)):
        return False
    return any(
        isinstance(change, dict)
        and _identity(change) == identity
        and _text(change.get("from_version")) == installed
        and _text(change.get("to_version")) == proposed
        for change in changes
    )


def _stable_proposal_id(identity: tuple[str, str], installed: str, proposed: str,
                        evidence: list[dict[str, Any]], conflicts: list[str]) -> str:
    identity_data = {
        "ecosystem": identity[0],
        "package_identity": identity[1],
        "installed_version": installed,
        "proposed_version": proposed,
        "source_evidence": sorted(
            (item["source_file"], item["line_number"], item["reference"])
            for item in evidence
        ),
        "conflicting_versions": sorted(conflicts),
    }
    encoded = json.dumps(identity_data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "vt-proposal-" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]


def prepare_review_proposals(
    compatibility_assessments: list,
    api_impact_results: list,
    code_suggestions: list,
    compatibility_test_results: list,
) -> list[dict[str, Any]]:
    """Create stable, initially pending proposals from existing agent records.

    Proposed versions are included only when an explicit code-suggestion
    dependency change matches the installed version and a fixed candidate from
    a matching compatibility assessment. Code snippets are included only when
    the suggestion explicitly labels them ``EVIDENCE_BACKED`` and provides
    evidence; current code-suggestion outputs are illustrative and therefore
    do not satisfy this gate.
    """
    assessments_by_id: dict[tuple[str, str], list[dict[str, Any]]] = {}
    impacts_by_id: dict[tuple[str, str], list[dict[str, Any]]] = {}
    suggestions_by_id: dict[tuple[str, str], list[dict[str, Any]]] = {}
    tests_by_id: dict[tuple[str, str], list[dict[str, Any]]] = {}

    for bucket, records, field in (
        (assessments_by_id, _records(compatibility_assessments), "package"),
        (impacts_by_id, _records(api_impact_results), "package"),
        (suggestions_by_id, _records(code_suggestions), "package"),
        (tests_by_id, _records(compatibility_test_results), "package"),
    ):
        for record in records:
            identity = _identity(record, field)
            if identity is not None:
                bucket.setdefault(identity, []).append(record)

    identities = set(assessments_by_id) | set(impacts_by_id) | set(suggestions_by_id)
    proposals: list[dict[str, Any]] = []
    for identity in sorted(identities):
        ecosystem, _normalized_package = identity
        assessment_records = assessments_by_id.get(identity, [])
        impact_records = impacts_by_id.get(identity, [])
        suggestion_records = suggestions_by_id.get(identity, [])
        test_records = tests_by_id.get(identity, [])
        package = next((
            _text(record.get("package"))
            for records in (assessment_records, impact_records, suggestion_records, test_records)
            for record in records if _text(record.get("package"))
        ), "")
        if not package:
            continue

        evidence = _source_evidence(impact_records, suggestion_records)
        installed_versions = {
            _text(record.get("installed_version"))
            for record in assessment_records + impact_records + suggestion_records
            if _text(record.get("installed_version"))
        }
        installed_conflict = len(installed_versions) > 1
        installed_version = next(iter(installed_versions)) if len(installed_versions) == 1 else ""

        candidate_versions: set[str] = set()
        for record in assessment_records:
            candidate_versions.update(_strings(record.get("candidate_fixed_versions")))
        candidate_signatures = {
            tuple(_strings(record.get("candidate_fixed_versions"))) for record in assessment_records
        }
        candidate_conflict = len(candidate_signatures) > 1
        assessment_statuses = {
            _text(record.get("assessment_status")).upper() for record in assessment_records
        }
        assessment_conflict = len(assessment_statuses) > 1
        assessment_is_reviewable = (
            bool(assessment_records)
            and assessment_statuses == {"REVIEW_REQUIRED"}
            and not installed_conflict
            and not candidate_conflict
            and not assessment_conflict
        )
        candidates_for_selection = candidate_versions if assessment_is_reviewable else set()
        proposals_for_identity = {
            version for suggestion in suggestion_records
            for version, _manifest in [_explicit_change(suggestion, candidates_for_selection, installed_version)]
            if version
        }
        proposed_conflict = len(proposals_for_identity) > 1
        proposed_version = next(iter(proposals_for_identity)) if len(proposals_for_identity) == 1 and not installed_conflict else ""

        code_snippets: set[str] = set()
        for suggestion in suggestion_records:
            snippet = _text(suggestion.get("proposed_code_snippet"))
            if (
                snippet
                and _text(suggestion.get("guidance_type")).upper() == "EVIDENCE_BACKED"
                and _text(suggestion.get("review_status")).upper() == "REVIEW_REQUIRED"
                and _text(suggestion.get("confidence")).upper() == "HIGH"
                and _strings(suggestion.get("proposed_code_evidence"))
            ):
                code_snippets.add(snippet)
        code_conflict = len(code_snippets) > 1
        proposed_code = next(iter(code_snippets)) if len(code_snippets) == 1 and not code_conflict else None

        explanations: list[str] = []
        if not assessment_records:
            explanations.append("No compatibility assessment matched this ecosystem and package identity.")
        if not evidence:
            explanations.append("No source file/line evidence is available; review the dependency and advisory records manually.")
        if installed_conflict:
            explanations.append("Agent records disagree on the installed version; no single installed version is asserted.")
        if candidate_conflict:
            explanations.append("Compatibility assessments list conflicting fixed-version candidates; none is selected.")
        if assessment_conflict:
            explanations.append("Compatibility assessment statuses conflict; candidate versions are not selected.")
        elif assessment_records and not assessment_is_reviewable:
            explanations.append("Compatibility assessment is not REVIEW_REQUIRED; no candidate is selected for proposal.")
        if proposed_conflict:
            explanations.append("Multiple explicit proposed versions conflict; no proposed version is selected.")
        elif not proposed_version:
            explanations.append("No explicit proposed version matched both the installed version and an OSV fixed candidate.")
        if code_conflict:
            explanations.append("Evidence-backed code suggestions conflict; no code snippet is proposed.")
        if not proposed_code:
            explanations.append("No evidence-backed replacement code is available; illustrative snippets are not treated as approved changes.")

        matching_test_records = [
            record for record in test_records
            if _test_matches_change(record, identity, installed_version, proposed_version)
        ]
        raw_test_statuses = [
            _text(record.get("status")).upper() for record in matching_test_records
        ]
        statuses = {
            _text(record.get("status")).upper()
            for record in matching_test_records
            if _text(record.get("status")).upper() in _TEST_STATUSES
        }
        valid_test_status = (
            bool(raw_test_statuses)
            and all(status in _TEST_STATUSES for status in raw_test_statuses)
            and len(statuses) == 1
        )
        test_status = next(iter(statuses)) if valid_test_status else "NOT_RUN"
        if not test_records:
            test_summary = "No compatibility test result was supplied."
        elif not matching_test_records:
            test_summary = "No compatibility test result matched the proposed dependency change."
        elif not valid_test_status:
            test_summary = "Matching compatibility test results are missing, malformed, or conflicting."
        else:
            matching_summaries = list(dict.fromkeys(
                _text(record.get("reason")) for record in matching_test_records if _text(record.get("reason"))
            ))
            test_summary = " ".join(matching_summaries) or "Compatibility test result supplied; output is not proof of full compatibility."

        confidence_values = {
            _text(record.get("confidence")).upper()
            for record in suggestion_records
            if _text(record.get("confidence")).upper() in _CONFIDENCE_LEVELS
        }
        confidence = next(iter(confidence_values)) if proposed_code and len(confidence_values) == 1 and not code_conflict else "LOW"
        explanations.append("Approval records a human review decision only; it does not apply changes or establish security/compatibility.")

        conflicts = sorted(installed_versions) if installed_conflict else []
        proposal_id = _stable_proposal_id(identity, installed_version, proposed_version, evidence, conflicts)
        # Include only candidate target metadata that was explicitly selected
        # by a matching code-suggestion proposal.
        manifest_files = {
            manifest for suggestion in suggestion_records
            for version, manifest in [_explicit_change(suggestion, candidates_for_selection, installed_version)]
            if version == proposed_version and manifest
        }
        if len(manifest_files) > 1:
            explanations.append("Matching explicit proposals name different manifests; verify the intended dependency file.")

        proposals.append({
            "proposal_id": proposal_id,
            "package": package,
            "package_identity": identity[1],
            "ecosystem": ecosystem,
            "installed_version": installed_version or None,
            "proposed_version": proposed_version or None,
            "candidate_fixed_versions": sorted(candidate_versions),
            "manifest_file": next(iter(manifest_files)) if len(manifest_files) == 1 else None,
            "source_evidence": evidence,
            "proposed_code_snippet": proposed_code,
            "explanation": " ".join(dict.fromkeys(explanations)),
            "confidence": confidence,
            "compatibility_test_status": test_status,
            "compatibility_test_summary": test_summary,
            "decision": "PENDING",
            "review_status": "PENDING",
            "reviewer_identity": None,
            "decision_timestamp": None,
            "review_comment": None,
        })

    # Defensive deduplication: stable IDs identify identical proposal payloads.
    unique: dict[str, dict[str, Any]] = {}
    for proposal in proposals:
        unique.setdefault(proposal["proposal_id"], proposal)
    return list(unique.values())


def submit_review_decision(
    proposals: list,
    proposal_id: str,
    decision: str,
    reviewer_identity: str | None,
    comment: str | None = None,
) -> list[dict[str, Any]]:
    """Return a copied proposal list with one non-overwritable human decision.

    ``PENDING`` is the initial state; submitting it is an idempotent no-op.
    Final decisions require an explicit reviewer identity and cannot be
    replaced. There is intentionally no revision/appeal workflow in this MVP.
    """
    if not isinstance(proposals, list):
        raise ValueError("Proposals must be a list.")
    if not isinstance(proposal_id, str) or not proposal_id.strip():
        raise KeyError("Unknown proposal ID.")
    if not isinstance(decision, str) or decision.strip().upper() not in _REVIEW_DECISIONS:
        raise ValueError("Decision must be PENDING, APPROVED, or REJECTED.")
    normalized_decision = decision.strip().upper()
    if comment is not None and not isinstance(comment, str):
        raise ValueError("Review comment must be text or None.")

    matches = [index for index, proposal in enumerate(proposals)
               if isinstance(proposal, dict) and proposal.get("proposal_id") == proposal_id]
    if not matches:
        raise KeyError("Unknown proposal ID.")
    if len(matches) != 1:
        raise ValueError("Proposal ID is ambiguous; duplicate IDs cannot be reviewed.")

    current = proposals[matches[0]]
    current_status = _text(current.get("review_status") or current.get("decision")).upper() or "PENDING"
    recorded_decision = _text(current.get("decision")).upper() or current_status
    if recorded_decision != current_status:
        raise ValueError("Proposal decision fields are inconsistent.")
    if current_status not in _REVIEW_DECISIONS:
        raise ValueError("Existing proposal review status is invalid.")
    if current_status != "PENDING":
        raise ValueError("A final decision already exists and cannot be overwritten.")
    if normalized_decision == "PENDING":
        return copy.deepcopy(proposals)

    reviewer = _text(reviewer_identity)
    if not reviewer:
        raise ValueError("An explicit reviewer identity is required for approval or rejection.")

    updated = copy.deepcopy(proposals)
    record = updated[matches[0]]
    record["decision"] = normalized_decision
    record["review_status"] = normalized_decision
    record["reviewer_identity"] = reviewer
    record["decision_timestamp"] = datetime.now(timezone.utc).isoformat()
    record["review_comment"] = comment.strip() if isinstance(comment, str) and comment.strip() else None
    return updated


prepare_proposals = prepare_review_proposals
record_review_decision = submit_review_decision
