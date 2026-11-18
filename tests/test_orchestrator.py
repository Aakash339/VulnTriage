import unittest
from unittest.mock import patch

import orchestrator


class OrchestratorProgressTests(unittest.TestCase):
    def test_callback_reports_actual_stage_outputs_and_return_is_unchanged(self):
        dependencies = [{"name": "pkg", "version": "1.0"}]
        vulnerabilities = [{"package": "pkg", "vulnerability_id": "OSV-1"}]
        reachability = [{"package": "pkg", "status": "USED", "evidence": ["app.py:1"]}]
        findings = [{"package": "pkg", "risk_score": 82}]
        events = []

        with (
            patch.object(orchestrator, "parse_dependencies", return_value=dependencies),
            patch.object(orchestrator, "scan_vulnerabilities", return_value=vulnerabilities),
            patch.object(orchestrator, "check_reachability", return_value=reachability),
            patch.object(orchestrator, "generate_remediation", return_value=findings),
        ):
            result = orchestrator.run_vulntriage("project", progress_callback=events.append)

        self.assertIs(result, findings)
        self.assertEqual(
            [(event["stage"], event["status"]) for event in events],
            [(stage, state) for stage in ("dependencies", "osv", "reachability", "risk")
             for state in ("started", "completed")],
        )
        completed = [event for event in events if event["status"] == "completed"]
        self.assertEqual([event["data"] for event in completed], [dependencies, vulnerabilities, reachability, findings])

    def test_original_call_without_callback_still_returns_findings(self):
        findings = [{"package": "pkg"}]
        with (
            patch.object(orchestrator, "parse_dependencies", return_value=[]),
            patch.object(orchestrator, "scan_vulnerabilities", return_value=[]),
            patch.object(orchestrator, "check_reachability", return_value=[]),
            patch.object(orchestrator, "generate_remediation", return_value=findings),
        ):
            self.assertIs(orchestrator.run_vulntriage("project"), findings)


if __name__ == "__main__":
    unittest.main()
