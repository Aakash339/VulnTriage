import unittest

from agents.remediation_agent import generate_remediation
from utils.risk_engine import calculate_risk


class RiskEngineTests(unittest.TestCase):
    def calculate(self, severity="HIGH", fixed_versions=None, status="USED", evidence=None):
        vulnerability = {"severity": severity}
        if fixed_versions is not None:
            vulnerability["fixed_versions"] = fixed_versions
        reachability = {"status": status, "evidence": evidence or []}
        return calculate_risk(vulnerability, reachability)

    def test_critical_scores_higher_than_low(self):
        critical = self.calculate("CRITICAL", ["2.0"], "USED", ["src.py:1: import pkg"])
        low = self.calculate("LOW", ["2.0"], "USED", ["src.py:1: import pkg"])
        self.assertGreater(critical["risk_score"], low["risk_score"])

    def test_used_scores_higher_than_not_found(self):
        used = self.calculate("HIGH", ["2.0"], "USED", ["src.py:1: import pkg"])
        absent = self.calculate("HIGH", ["2.0"], "NOT_FOUND")
        self.assertGreater(used["risk_score"], absent["risk_score"])
        self.assertGreater(absent["risk_score"], 0)
        self.assertIn("not proof of safety", absent["risk_explanation"])

    def test_unknown_reachability_preserves_uncertainty(self):
        result = self.calculate("HIGH", ["2.0"], "UNKNOWN")
        self.assertEqual(result["risk_factors"][1], "Reachability UNKNOWN: 25/30 points.")
        self.assertIn("unknown or incomplete", result["risk_explanation"])

    def test_actual_fixed_versions_reduce_unresolved_fix_points(self):
        fixed = self.calculate("CRITICAL", ["2.0"], "USED", ["src.py:1: import pkg"])
        no_fix = self.calculate("CRITICAL", [], "USED", ["src.py:1: import pkg"])
        self.assertEqual(no_fix["risk_score"] - fixed["risk_score"], 10)
        self.assertIn("2.0", " ".join(fixed["risk_factors"]))
        self.assertIn("OSV reports no fixed version", " ".join(no_fix["risk_factors"]))

    def test_missing_severity_is_uncertain_not_zero(self):
        result = calculate_risk({"fixed_versions": ["1.1"]}, {"status": "USED", "evidence": ["x.py:1 import x"]})
        self.assertEqual(result["risk_factors"][0], "Severity UNKNOWN: 25/50 points.")
        self.assertGreater(result["risk_score"], 0)

    def test_missing_reachability_is_unknown(self):
        result = calculate_risk({"severity": "MEDIUM", "fixed_versions": []}, None)
        self.assertEqual(result["risk_factors"][1], "Reachability UNKNOWN: 25/30 points.")
        self.assertIn("Reachability is unknown", result["risk_explanation"])

    def test_malformed_inputs_are_safe_and_bounded(self):
        result = calculate_risk(None, ["bad record"])
        self.assertEqual(set(result), {"risk_score", "risk_level", "risk_factors", "risk_explanation"})
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)

    def test_score_is_deterministic_and_explanation_matches_factors(self):
        vulnerability = {"severity": "MEDIUM", "fixed_versions": ["3.1"]}
        reachability = {"status": "USED", "evidence": ["src/app.py:4: import example"]}
        first = calculate_risk(vulnerability, reachability)
        second = calculate_risk(vulnerability, reachability)
        self.assertEqual(first, second)
        self.assertIn(f"Risk score {first['risk_score']}/100 ({first['risk_level']})", first["risk_explanation"])
        for factor in first["risk_factors"]:
            self.assertTrue(factor)

    def test_remediation_contract_and_existing_priority_are_preserved(self):
        vulnerability = {
            "package": "flask", "vulnerability_id": "CVE-1", "severity": "HIGH",
            "installed_version": "1.0", "fixed_versions": ["2.0"],
        }
        finding = generate_remediation([vulnerability], [
            {"package": "flask", "status": "NOT_FOUND", "evidence": []},
        ])[0]
        self.assertEqual(finding["priority"], "MEDIUM")
        self.assertEqual(finding["recommended_version"], "2.0")
        self.assertEqual(finding["risk_score"], 66)
        self.assertEqual(set(finding), {
            "package", "vulnerability_id", "severity", "reachability", "priority",
            "installed_version", "recommended_version", "recommendation",
            "risk_score", "risk_level", "risk_factors", "risk_explanation",
        })


if __name__ == "__main__":
    unittest.main()
