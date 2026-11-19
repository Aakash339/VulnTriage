import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app
from agents.approval_agent import prepare_review_proposals


class RemediationDashboardTests(unittest.TestCase):
    def setUp(self):
        self.calls = {"text": [], "code": [], "info": [], "warning": [], "error": [], "success": [], "expander": []}
        self.state = {}
        self.button_results = {}
        self.text_values = {}

        def capture(name):
            def method(*args, **kwargs):
                self.calls[name].append((args, kwargs))
                if name == "text":
                    return None
            return method

        def capture_expander(label, **_kwargs):
            self.calls["expander"].append(label)
            return nullcontext()

        fake_st = SimpleNamespace(
            markdown=Mock(), title=Mock(), caption=capture("text"), subheader=Mock(), write=capture("text"),
            info=capture("info"), warning=capture("warning"), error=capture("error"),
            success=capture("success"), code=capture("code"),
            expander=capture_expander,
            columns=lambda count: [nullcontext() for _ in range(count)],
            selectbox=lambda _label, options, **_kwargs: None,
            text_input=lambda label, key: self.text_values.get(key, ""),
            button=lambda label, key, **_kwargs: self.button_results.get(key, False),
            session_state=self.state,
        )
        self.patch = patch.object(app, "st", fake_st)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def fixture(self):
        return {
            "analysis_status": {
                "compatibility": {"status": "completed"},
                "api_impact": {"status": "completed"},
                "code_suggestions": {"status": "completed"},
                "compatibility_tests": {"status": "completed"},
                "approvals": {"status": "completed"},
            },
            "compatibility_assessments": [{
                "package": "requests", "ecosystem": "PyPI", "installed_version": "2.31.0",
                "candidate_fixed_versions": ["2.32.0"], "assessment_status": "REVIEW_REQUIRED",
                "evidence_used": ["OSV advisory lists 2.32.0"], "explanation": "Compatibility remains unverified.",
            }],
            "api_impact_results": [{
                "package": "requests", "ecosystem": "PyPI", "status": "POTENTIAL_IMPACT",
                "usages": [{
                    "source_file": "src/client.py", "line_number": 4,
                    "reference": "requests.get", "statement": "import requests; requests.get(url)", "kind": "API call",
                }],
                "evidence": ["Static usage detected at src/client.py:4"],
                "explanation": "Upgrade impact is unverified.",
            }],
            "code_suggestions": [{
                "package": "requests", "ecosystem": "PyPI", "source_file": "src/client.py", "line_number": 4,
                "detected_reference": "requests.get", "current_code_snippet": "requests.get(url)",
                "proposed_code_snippet": None, "guidance": "Review release notes.",
                "confidence": "LOW", "review_status": "NO_SAFE_SUGGESTION",
            }],
            "compatibility_test_results": [{
                "package": "requests", "ecosystem": "PyPI", "status": "NOT_RUN", "test_command": None,
                "tested_dependency_changes": [], "stdout": "", "stderr": "",
                "reason": "No explicit change was supplied.",
                "limitations": ["Syntax checks do not verify behavior."],
            }],
            "review_proposals": [],
        }

    def proposal(self):
        return prepare_review_proposals(
            self.fixture()["compatibility_assessments"], self.fixture()["api_impact_results"],
            self.fixture()["code_suggestions"], self.fixture()["compatibility_test_results"],
        )[0]

    def test_empty_and_older_scan_states_render_safely(self):
        app._render_remediation_compatibility({})
        self.assertTrue(any("after a scan" in str(args) for args, _kwargs in self.calls["info"]))
        self.calls["info"].clear()
        app._render_remediation_compatibility({"compatibility_assessments": None})
        self.assertTrue(any("older saved session" in str(args) for args, _kwargs in self.calls["info"]))

    def test_compatibility_api_suggestion_and_test_details_render(self):
        data = self.fixture()
        app._render_remediation_compatibility(data)
        rendered_text = "\n".join(str(args) for args, _kwargs in self.calls["text"])
        rendered_code = "\n".join(str(args) for args, _kwargs in self.calls["code"])
        self.assertIn("OSV fixed-version candidates: 2.32.0", rendered_text)
        self.assertIn("src/client.py:4", rendered_text)
        self.assertIn("Upgrade impact is unverified", "\n".join(str(call) for call in self.calls["text"]))
        self.assertIn("requests.get(url)", rendered_code)
        self.assertIn("No safe evidence-backed replacement", "\n".join(str(call) for call in self.calls["info"]))
        self.assertTrue(any("NOT_RUN" in label for label in self.calls["expander"]))
        self.assertIn("Syntax checks do not verify behavior", "\n".join(str(call) for call in self.calls["text"]))

    def test_agent_error_state_is_displayed(self):
        data = {"analysis_status": {"api_impact": {"status": "failed", "error": "RuntimeError: analyzer failed"}}}
        app._render_remediation_compatibility(data)
        self.assertTrue(any("analyzer failed" in str(args) for args, _kwargs in self.calls["warning"]))

    def test_only_evidence_backed_proposed_snippets_are_shown(self):
        data = self.fixture()
        suggestion = data["code_suggestions"][0]
        suggestion.update({
            "proposed_code_snippet": "replacement()", "guidance_type": "ILLUSTRATIVE",
            "proposed_code_evidence": [],
        })
        app._render_remediation_compatibility(data)
        rendered_code = "\n".join(str(args) for args, _kwargs in self.calls["code"])
        self.assertNotIn("replacement()", rendered_code)

    def test_approval_and_rejection_require_reviewer_and_persist_updated_proposals(self):
        for decision in ("APPROVED", "REJECTED"):
            with self.subTest(decision=decision):
                data = self.fixture()
                proposal = self.proposal()
                data["review_proposals"] = [proposal]
                reviewer_key = f"reviewer-{proposal['proposal_id']}"
                self.text_values[reviewer_key] = "security-reviewer"
                self.text_values[f"review-comment-{proposal['proposal_id']}"] = "Checked evidence"
                button_key = (f"approve-{proposal['proposal_id']}" if decision == "APPROVED"
                              else f"reject-{proposal['proposal_id']}")
                self.button_results[button_key] = True
                self.state["soc_scan_data"] = data
                app._render_remediation_compatibility(data)
                stored = self.state["soc_scan_data"]["review_proposals"][0]
                self.assertEqual(stored["decision"], decision)
                self.assertEqual(stored["review_status"], decision)
                self.assertEqual(stored["reviewer_identity"], "security-reviewer")
                self.assertIsNotNone(stored["decision_timestamp"])
                self.assertEqual(stored["review_comment"], "Checked evidence")
                self.button_results.clear()
                self.calls["error"].clear()
                app._render_remediation_compatibility(self.state["soc_scan_data"])
                self.assertFalse(any("required" in str(args).casefold() for args, _kwargs in self.calls["error"]))

    def test_invalid_reviewer_and_repeated_decision_are_rejected(self):
        data = self.fixture()
        proposal = self.proposal()
        data["review_proposals"] = [proposal]
        self.state["soc_scan_data"] = data
        self.button_results[f"approve-{proposal['proposal_id']}"] = True
        app._render_remediation_compatibility(data)
        self.assertEqual(self.state["soc_scan_data"]["review_proposals"][0]["decision"], "PENDING")
        self.assertTrue(any("reviewer identity" in str(args).casefold() for args, _kwargs in self.calls["error"]))

        self.calls["error"].clear()
        self.text_values[f"reviewer-{proposal['proposal_id']}"] = "reviewer-1"
        app._render_remediation_compatibility(data)
        approved_data = self.state["soc_scan_data"]
        self.button_results.clear()
        with self.assertRaises(ValueError):
            updated = app._record_review_decision(
                approved_data, proposal["proposal_id"], "REJECTED", "reviewer-2", "overwrite attempt",
            )
            self.state["soc_scan_data"] = updated

    def test_session_state_decision_survives_render_rerun(self):
        data = self.fixture()
        proposal = self.proposal()
        data["review_proposals"] = [proposal]
        self.state["soc_scan_data"] = data
        self.button_results[f"reject-{proposal['proposal_id']}"] = True
        self.text_values[f"reviewer-{proposal['proposal_id']}"] = "analyst"
        app._render_remediation_compatibility(data)
        self.assertEqual(self.state["soc_scan_data"]["review_proposals"][0]["decision"], "REJECTED")

        self.button_results.clear()
        self.calls["text"].clear()
        app._render_remediation_compatibility(self.state["soc_scan_data"])
        self.assertTrue(any("REJECTED" in label for label in self.calls["expander"]))
        self.assertFalse(any(key.startswith("approve-") for key in self.button_results))


if __name__ == "__main__":
    unittest.main()
