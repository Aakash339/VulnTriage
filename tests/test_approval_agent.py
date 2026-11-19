from datetime import datetime

import pytest

from agents.approval_agent import prepare_review_proposals, submit_review_decision


def compatibility(package="requests", ecosystem="PyPI", installed="2.30.0", candidates=None):
    return {
        "package": package,
        "ecosystem": ecosystem,
        "installed_version": installed,
        "candidate_fixed_versions": ["2.31.0"] if candidates is None else candidates,
        "assessment_status": "REVIEW_REQUIRED",
        "evidence_used": ["OSV-1 lists fixed version"],
        "explanation": "Candidate requires manual review.",
    }


def impact(package="requests", ecosystem="PyPI", usages=None, candidates=None):
    return {
        "package": package,
        "ecosystem": ecosystem,
        "installed_version": "2.30.0",
        "candidate_fixed_versions": ["2.31.0"] if candidates is None else candidates,
        "status": "POTENTIAL_IMPACT",
        "usages": [{
            "source_file": "src/app.py",
            "line_number": 8,
            "reference": "requests.get",
            "statement": "requests.get('/health')",
            "kind": "API_CALL",
        }] if usages is None else usages,
    }


def suggestion(package="requests", ecosystem="PyPI", target=None, snippet=None, **overrides):
    result = {
        "package": package,
        "ecosystem": ecosystem,
        "installed_version": "2.30.0",
        "source_file": "src/app.py",
        "line_number": 8,
        "detected_reference": "requests.get",
        "current_code_snippet": "requests.get('/health')",
        "proposed_code_snippet": snippet,
        "guidance_type": "ILLUSTRATIVE",
        "confidence": "LOW",
        "review_status": "NO_SAFE_SUGGESTION",
    }
    if target:
        result["review_status"] = "REVIEW_REQUIRED"
        result["proposed_dependency_change"] = {
            "package": package,
            "ecosystem": ecosystem,
            "from_version": "2.30.0",
            "to_version": target,
            "manifest_file": "requirements.txt",
        }
    result.update(overrides)
    return result


def test_proposal_creation_includes_identity_evidence_and_test_summary():
    tests = [{
        "package": "requests", "ecosystem": "PyPI", "status": "PASSED",
        "tested_dependency_changes": [{
            "package": "requests", "ecosystem": "PyPI", "from_version": "2.30.0",
            "to_version": "2.31.0", "manifest_file": "requirements.txt",
        }],
        "reason": "Static syntax check passed.",
    }]
    proposals = prepare_review_proposals(
        [compatibility()], [impact()], [suggestion(target="2.31.0")], tests,
    )

    assert len(proposals) == 1
    proposal = proposals[0]
    assert proposal["proposal_id"].startswith("vt-proposal-")
    assert proposal["package_identity"] == "requests"
    assert proposal["ecosystem"] == "PyPI"
    assert proposal["installed_version"] == "2.30.0"
    assert proposal["proposed_version"] == "2.31.0"
    assert proposal["source_evidence"][0]["source_file"] == "src/app.py"
    assert proposal["source_evidence"][0]["line_number"] == 8
    assert proposal["proposed_code_snippet"] is None
    assert proposal["compatibility_test_status"] == "PASSED"
    assert "Static syntax check passed" in proposal["compatibility_test_summary"]
    assert proposal["review_status"] == "PENDING"


def test_proposal_id_is_stable_and_duplicate_evidence_is_deduplicated():
    first = prepare_review_proposals([compatibility()], [impact(), impact()], [suggestion()], [])[0]
    second = prepare_review_proposals([compatibility()], [impact()], [suggestion()], [])[0]

    assert first["proposal_id"] == second["proposal_id"]
    assert len(first["source_evidence"]) == 1


def test_candidate_is_not_selected_without_explicit_proposed_change():
    proposal = prepare_review_proposals([compatibility(candidates=["2.31.0"])], [impact()], [suggestion()], [])[0]

    assert proposal["candidate_fixed_versions"] == ["2.31.0"]
    assert proposal["proposed_version"] is None
    assert "No explicit proposed version" in proposal["explanation"]


def test_not_assessed_compatibility_cannot_authorize_candidate_selection():
    record = compatibility()
    record["assessment_status"] = "NOT_ASSESSED"
    proposal = prepare_review_proposals([record], [impact()], [suggestion(target="2.31.0")], [])[0]

    assert proposal["candidate_fixed_versions"] == ["2.31.0"]
    assert proposal["proposed_version"] is None
    assert "not REVIEW_REQUIRED" in proposal["explanation"]


def test_code_snippet_requires_explicit_evidence_backed_provenance():
    unsupported = suggestion(snippet="requests.fetch('/health')", guidance_type="ILLUSTRATIVE")
    supported = suggestion(
        snippet="client.get('/health')",
        guidance_type="EVIDENCE_BACKED",
        review_status="REVIEW_REQUIRED",
        confidence="HIGH",
        proposed_code_evidence=["vendor migration guide section 2"],
    )

    assert prepare_review_proposals([compatibility()], [impact()], [unsupported], [])[0]["proposed_code_snippet"] is None
    assert prepare_review_proposals([compatibility()], [impact()], [supported], [])[0]["proposed_code_snippet"] == "client.get('/health')"


def test_missing_evidence_is_pending_but_explicitly_flagged():
    proposal = prepare_review_proposals([compatibility()], [], [], [])[0]

    assert proposal["source_evidence"] == []
    assert proposal["confidence"] == "LOW"
    assert "No source file/line evidence" in proposal["explanation"]
    assert proposal["review_status"] == "PENDING"


def test_conflicting_installed_versions_are_not_asserted():
    records = [compatibility(installed="2.30.0"), compatibility(installed="2.29.0")]
    proposal = prepare_review_proposals(records, [impact()], [suggestion(target="2.31.0")], [])[0]

    assert proposal["installed_version"] is None
    assert proposal["proposed_version"] is None
    assert "disagree on the installed version" in proposal["explanation"]


def test_ecosystem_collisions_and_exact_maven_identity_remain_separate():
    records = [compatibility("common", "PyPI"), compatibility("common", "npm")]
    proposals = prepare_review_proposals(records, [impact("common", "PyPI"), impact("common", "npm")], [], [])
    assert {(item["ecosystem"], item["package"]) for item in proposals} == {("PyPI", "common"), ("npm", "common")}

    maven = prepare_review_proposals(
        [compatibility("org.example:foo-bar", "Maven"), compatibility("org.example:foo_bar", "Maven")],
        [], [], [],
    )
    assert {item["package_identity"] for item in maven} == {"org.example:foo-bar", "org.example:foo_bar"}


def test_conflicting_proposed_targets_are_not_selected():
    suggestions = [suggestion(target="2.31.0"), suggestion(target="2.32.0")]
    proposal = prepare_review_proposals([compatibility(candidates=["2.31.0", "2.32.0"])], [impact()], suggestions, [])[0]

    assert proposal["proposed_version"] is None
    assert "Multiple explicit proposed versions conflict" in proposal["explanation"]


def test_test_result_must_match_exact_proposed_dependency_change():
    wrong_result = {
        "package": "requests", "ecosystem": "PyPI", "status": "PASSED",
        "tested_dependency_changes": [{
            "package": "requests", "ecosystem": "PyPI", "from_version": "2.30.0",
            "to_version": "2.32.0",
        }],
    }
    proposal = prepare_review_proposals(
        [compatibility()], [impact()], [suggestion(target="2.31.0")], [wrong_result],
    )[0]
    assert proposal["compatibility_test_status"] == "NOT_RUN"
    assert "No compatibility test result matched" in proposal["compatibility_test_summary"]


def test_malformed_matching_test_status_does_not_preserve_passed_status():
    change = {"package": "requests", "ecosystem": "PyPI", "from_version": "2.30.0", "to_version": "2.31.0"}
    tests = [
        {"package": "requests", "ecosystem": "PyPI", "status": "PASSED", "tested_dependency_changes": [change]},
        {"package": "requests", "ecosystem": "PyPI", "status": "unknown", "tested_dependency_changes": [change]},
    ]
    proposal = prepare_review_proposals(
        [compatibility()], [impact()], [suggestion(target="2.31.0")], tests,
    )[0]
    assert proposal["compatibility_test_status"] == "NOT_RUN"


def test_approval_records_explicit_reviewer_time_and_optional_comment():
    pending = prepare_review_proposals([compatibility()], [impact()], [suggestion()], [])[0]
    original = [pending]
    approved = submit_review_decision(original, pending["proposal_id"], "APPROVED", "analyst@example.test", "Reviewed manually.")

    assert original[0]["review_status"] == "PENDING"
    record = approved[0]
    assert record["review_status"] == "APPROVED"
    assert record["decision"] == "APPROVED"
    assert record["reviewer_identity"] == "analyst@example.test"
    assert record["review_comment"] == "Reviewed manually."
    assert datetime.fromisoformat(record["decision_timestamp"]).tzinfo is not None


def test_rejection_allows_no_comment_and_records_explicit_identity():
    pending = prepare_review_proposals([compatibility()], [], [], [])[0]
    rejected = submit_review_decision([pending], pending["proposal_id"], "REJECTED", "reviewer-7")

    assert rejected[0]["review_status"] == "REJECTED"
    assert rejected[0]["decision"] == "REJECTED"
    assert rejected[0]["reviewer_identity"] == "reviewer-7"
    assert rejected[0]["review_comment"] is None


def test_final_decision_cannot_be_overwritten():
    pending = prepare_review_proposals([compatibility()], [], [], [])[0]
    approved = submit_review_decision([pending], pending["proposal_id"], "APPROVED", "reviewer")

    with pytest.raises(ValueError, match="cannot be overwritten"):
        submit_review_decision(approved, pending["proposal_id"], "REJECTED", "another reviewer")


@pytest.mark.parametrize("proposal_id", ["missing", ""])
def test_unknown_proposal_ids_are_rejected(proposal_id):
    pending = prepare_review_proposals([compatibility()], [], [], [])
    with pytest.raises(KeyError):
        submit_review_decision(pending, proposal_id, "APPROVED", "reviewer")


def test_invalid_decisions_and_missing_reviewer_are_rejected():
    pending = prepare_review_proposals([compatibility()], [], [], [])
    proposal_id = pending[0]["proposal_id"]
    with pytest.raises(ValueError, match="Decision must"):
        submit_review_decision(pending, proposal_id, "MAYBE", "reviewer")
    with pytest.raises(ValueError, match="reviewer identity"):
        submit_review_decision(pending, proposal_id, "APPROVED", " ")


def test_pending_decision_is_noop_and_malformed_records_are_safe():
    pending = prepare_review_proposals([None, {}, compatibility()], [None], [None], [None])
    assert len(pending) == 1
    unchanged = submit_review_decision(pending, pending[0]["proposal_id"], "PENDING", None)
    assert unchanged[0]["review_status"] == "PENDING"
    assert prepare_review_proposals(None, None, None, None) == []

