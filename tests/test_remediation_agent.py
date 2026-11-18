import unittest

from agents.remediation_agent import generate_remediation


def vuln(**overrides):
    record = {
        "package": "flask", "vulnerability_id": "CVE-2025-1234",
        "severity": "HIGH", "installed_version": "1.0",
        "fixed_versions": ["2.0"],
    }
    record.update(overrides)
    return record


class RemediationAgentTests(unittest.TestCase):
    def test_used_priorities_by_severity(self):
        records = [vuln(severity=s, vulnerability_id=s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
        findings = generate_remediation(records, [{"package": "flask", "status": "USED"}])
        self.assertEqual([f["priority"] for f in findings], ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_not_found_is_downgraded_and_not_safe(self):
        finding = generate_remediation([vuln()], [{"package": "flask", "status": "NOT_FOUND"}])[0]
        self.assertEqual((finding["reachability"], finding["priority"]), ("NOT_FOUND", "MEDIUM"))

    def test_unknown_reachability_and_severity_preserve_uncertainty(self):
        for reach in ([], [{"package": "flask", "status": "UNKNOWN"}]):
            finding = generate_remediation([vuln()], reach)[0]
            self.assertEqual((finding["reachability"], finding["priority"]), ("UNKNOWN", "UNKNOWN"))
        finding = generate_remediation([vuln(severity="unspecified")], [{"package": "flask", "status": "USED"}])[0]
        self.assertEqual((finding["severity"], finding["priority"]), ("UNKNOWN", "UNKNOWN"))

    def test_fixed_version_selection(self):
        one = generate_remediation([vuln(fixed_versions=["2.3"])], [])[0]
        self.assertEqual(one["recommended_version"], "2.3")
        self.assertIn("test", one["recommendation"])
        missing = generate_remediation([vuln(fixed_versions=[])], [])[0]
        self.assertEqual(missing["recommended_version"], "No fixed version identified by OSV")
        self.assertIn("No fixed version identified by OSV", missing["recommendation"])
        multi = generate_remediation([vuln(fixed_versions=["3.0", "2.1", "3.0"])], [])[0]
        self.assertIn("3.0, 2.1", multi["recommended_version"])
        self.assertIn("after checking", multi["recommendation"])

    def test_multiple_vulnerabilities_and_deduplication(self):
        first = vuln()
        second = vuln(vulnerability_id="CVE-2025-9999")
        results = generate_remediation([first, first.copy(), second], [{"package": "flask", "status": "USED"}])
        self.assertEqual(len(results), 2)
        self.assertEqual({f["vulnerability_id"] for f in results}, {"CVE-2025-1234", "CVE-2025-9999"})

    def test_malformed_records_are_skipped_and_bad_fields_are_safe(self):
        result = generate_remediation([None, {}, vuln(installed_version=None, fixed_versions="2")], [None, {}])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["installed_version"], "")
        self.assertEqual(result[0]["reachability"], "UNKNOWN")

    def test_conflicting_reachability_is_unknown(self):
        result = generate_remediation([vuln()], [
            {"package": "flask", "status": "USED"}, {"package": "FLASK", "status": "NOT_FOUND"}
        ])[0]
        self.assertEqual(result["reachability"], "UNKNOWN")

    def test_empty_inputs_and_contract_fields(self):
        self.assertEqual(generate_remediation([], []), [])
        self.assertEqual(generate_remediation([vuln()], [] )[0].keys(), {
            "package", "vulnerability_id", "severity", "reachability", "priority",
            "installed_version", "recommended_version", "recommendation",
            "risk_score", "risk_level", "risk_factors", "risk_explanation",
        })


if __name__ == "__main__":
    unittest.main()
