import unittest

from app import (
    SORT_OPTIONS,
    _filter_findings,
    _finding_summary,
    _sort_findings,
)


class DashboardFindingTests(unittest.TestCase):
    def setUp(self):
        self.findings = [
            {"package": "zeta", "priority": "LOW", "severity": "CRITICAL", "reachability": "USED", "vulnerability_id": "Z-1"},
            {"package": "Beta", "priority": "CRITICAL", "severity": "HIGH", "reachability": "UNKNOWN", "vulnerability_id": "B-2"},
            {"package": "alpha", "priority": "CRITICAL", "severity": "CRITICAL", "reachability": "USED", "vulnerability_id": "A-1"},
            {"package": "alpha", "priority": "UNKNOWN", "severity": "UNKNOWN", "reachability": "NOT_FOUND", "vulnerability_id": "C-1"},
            {"package": "gamma", "priority": "MEDIUM", "severity": "MEDIUM", "reachability": "NOT_FOUND", "vulnerability_id": "D-1"},
        ]

    def test_default_priority_then_severity_then_package(self):
        original = list(self.findings)
        sorted_rows = _sort_findings(self.findings)
        self.assertEqual(
            [row["package"] for row in sorted_rows],
            ["alpha", "Beta", "gamma", "zeta", "alpha"],
        )
        self.assertEqual(self.findings, original)

    def test_sort_options(self):
        expected = {
            "Priority (Highest first)": ["alpha", "Beta", "gamma", "zeta", "alpha"],
            "Severity (Highest first)": ["alpha", "zeta", "Beta", "gamma", "alpha"],
            "Package name (A–Z)": ["alpha", "alpha", "Beta", "gamma", "zeta"],
            "Reachability (USED first)": ["alpha", "zeta", "gamma", "alpha", "Beta"],
            "Vulnerability ID (A–Z)": ["alpha", "Beta", "alpha", "gamma", "zeta"],
        }
        self.assertEqual(tuple(expected), SORT_OPTIONS)
        for option, packages in expected.items():
            with self.subTest(option=option):
                self.assertEqual([row["package"] for row in _sort_findings(self.findings, option)], packages)

    def test_missing_and_unexpected_values_sort_safely(self):
        rows = [{"package": "valid", "priority": "HIGH", "severity": "HIGH"}, {}, None]
        self.assertEqual(len(_sort_findings(rows)), 3)
        self.assertEqual(_sort_findings(rows)[-1], None)

    def test_filters_combine_and_preserve_original_rows(self):
        selected = _filter_findings(self.findings, {"CRITICAL", "HIGH"}, {"CRITICAL"}, "USED")
        self.assertEqual([row["package"] for row in selected], ["alpha"])
        all_reachability = _filter_findings(self.findings, {"CRITICAL", "HIGH", "MEDIUM", "UNKNOWN"},
                                            {"CRITICAL", "LOW", "MEDIUM", "UNKNOWN"}, "All")
        self.assertEqual(len(all_reachability), len(self.findings))
        self.assertEqual(len(self.findings), 5)

    def test_summary_uses_findings(self):
        self.assertEqual(_finding_summary(self.findings), {
            "total": 5,
            "unique_packages": 4,
            "used": 2,
            "unknown_reachability": 1,
        })


if __name__ == "__main__":
    unittest.main()
