import unittest

from app import _filter_findings, _prepare_queue, _security_analytics, SORT_OPTIONS
from test_app_findings import make_reported_sample


class SecurityAnalyticsTests(unittest.TestCase):
    def test_36_finding_sample_analytics_and_queue_filter_independence(self):
        findings = make_reported_sample()
        # Aggregate repeated packages while retaining the existing 36-row severity fixture.
        for index, finding in enumerate(findings):
            finding["package"] = f"shared-package-{index % 6}"
            finding["risk_level"] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")[index % 4]
        vulnerabilities = [
            {"package": row["package"], "ecosystem": "PyPI" if index % 2 == 0 else "npm",
             "fixed_versions": ["2.0.0"] if index % 3 == 0 else []}
            for index, row in enumerate(findings)
        ]
        analytics = _security_analytics(findings, vulnerabilities)

        self.assertEqual(analytics["total_findings"], 36)
        self.assertEqual(analytics["severity_distribution"], {
            "CRITICAL": 0, "HIGH": 10, "MEDIUM": 18, "LOW": 0, "UNKNOWN": 8,
        })
        self.assertEqual(analytics["risk_level_distribution"], {
            "CRITICAL": 9, "HIGH": 9, "MEDIUM": 9, "LOW": 9, "UNKNOWN": 0,
        })
        self.assertEqual(analytics["average_risk_score"], 72.5)
        self.assertEqual(analytics["maximum_risk_score"], 90)
        self.assertEqual(analytics["minimum_risk_score"], 55)
        self.assertEqual(analytics["reachability_breakdown"], {"USED": 12, "NOT_FOUND": 12, "UNKNOWN": 12})
        self.assertEqual(analytics["ecosystem_distribution"], {"npm": 18, "PyPI": 18})
        self.assertEqual(analytics["findings_with_fixed_versions"], 12)
        self.assertEqual(analytics["package_ranking"][0]["vulnerability_count"], 6)
        self.assertEqual(len(analytics["highest_priority_targets"]), 5)

        _filter_findings(findings, {"HIGH"}, set(), "All")
        _prepare_queue(findings, {"UNKNOWN"}, set(), "UNKNOWN", SORT_OPTIONS[0])
        self.assertEqual(_security_analytics(findings, vulnerabilities), analytics)

    def test_top_five_dependency_ranking_uses_count_score_severity_and_priority(self):
        findings = []
        for package, count, score, severity, priority in (
            ("alpha", 3, 70, "HIGH", "HIGH"),
            ("beta", 3, 95, "CRITICAL", "CRITICAL"),
            ("gamma", 2, 80, "CRITICAL", "HIGH"),
            ("delta", 1, 99, "MEDIUM", "MEDIUM"),
            ("epsilon", 1, 60, "LOW", "LOW"),
            ("zeta", 1, 50, "UNKNOWN", "UNKNOWN"),
        ):
            for _ in range(count):
                findings.append({"package": package, "risk_score": score, "severity": severity, "priority": priority})
        ranking = _security_analytics(findings, [])['package_ranking']
        self.assertEqual([row["package"] for row in ranking], ["beta", "alpha", "gamma", "delta", "epsilon"])
        beta = ranking[0]
        self.assertEqual((beta["vulnerability_count"], beta["highest_risk_score"], beta["highest_severity"], beta["remediation_priority"]),
                         (3, 95, "CRITICAL", "CRITICAL"))

    def test_missing_malformed_and_empty_inputs_are_safe(self):
        analytics = _security_analytics([None, {}, {"package": "x", "risk_score": "bad"}], [None, {}])
        self.assertEqual(analytics["total_findings"], 2)
        self.assertIsNone(analytics["average_risk_score"])
        self.assertEqual(analytics["severity_distribution"]["UNKNOWN"], 2)
        self.assertEqual(analytics["reachability_breakdown"]["UNKNOWN"], 2)
        self.assertEqual(analytics["ecosystem_distribution"], {"UNKNOWN": 1})
        self.assertEqual(analytics["findings_with_fixed_versions"], 0)
        empty = _security_analytics([], [])
        self.assertEqual(empty["total_findings"], 0)
        self.assertIsNone(empty["maximum_risk_score"])
        self.assertEqual(empty["observations"], ["No vulnerability findings were returned in this scan."])

    def test_observations_are_based_on_actual_scan_values(self):
        findings = [{"package": "real-package", "severity": "HIGH", "reachability": "UNKNOWN", "risk_score": 88}]
        observations = _security_analytics(findings, [])["observations"]
        combined = " ".join(observations)
        self.assertIn("High", combined)
        self.assertIn("88/100", combined)
        self.assertIn("real-package", combined)
        self.assertIn("unknown reachability", combined)
        self.assertNotIn("invented-package", combined)


if __name__ == "__main__":
    unittest.main()
