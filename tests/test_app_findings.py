import unittest
import csv
import io
from types import SimpleNamespace
from unittest.mock import Mock, patch
from collections import Counter

from app import (
    NAVIGATION_ITEMS,
    SORT_OPTIONS,
    _filter_findings,
    _finding_summary,
    _security_analytics,
    _prepare_queue,
    _queue_filter_defaults,
    _risk_analysis_summary,
    _sort_findings,
    _navigation_section,
    _reachability_explanation,
    _reachability_limitations,
)
from reports.report_generator import generate_csv_report
import app


class DashboardFindingTests(unittest.TestCase):
    def setUp(self):
        self.findings = [
            {"package": "zeta", "priority": "LOW", "severity": "CRITICAL", "reachability": "USED", "vulnerability_id": "Z-1", "risk_score": 40},
            {"package": "Beta", "priority": "CRITICAL", "severity": "HIGH", "reachability": "UNKNOWN", "vulnerability_id": "B-2", "risk_score": 90},
            {"package": "alpha", "priority": "CRITICAL", "severity": "CRITICAL", "reachability": "USED", "vulnerability_id": "A-1", "risk_score": 90},
            {"package": "alpha", "priority": "UNKNOWN", "severity": "UNKNOWN", "reachability": "NOT_FOUND", "vulnerability_id": "C-1", "risk_score": 10},
            {"package": "gamma", "priority": "MEDIUM", "severity": "MEDIUM", "reachability": "NOT_FOUND", "vulnerability_id": "D-1", "risk_score": 70},
        ]

    def test_default_risk_sort_then_priority_and_severity_tiebreakers(self):
        original = list(self.findings)
        sorted_rows = _sort_findings(self.findings)
        self.assertEqual(
            [row["package"] for row in sorted_rows],
            ["alpha", "Beta", "gamma", "zeta", "alpha"],
        )
        self.assertEqual(self.findings, original)

    def test_sort_options(self):
        expected = {
            "Risk score (Highest first)": ["alpha", "Beta", "gamma", "zeta", "alpha"],
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

    def test_search_filters_by_package_or_vulnerability_id(self):
        self.assertEqual(
            [row["vulnerability_id"] for row in _filter_findings(self.findings, set(), set(), "All", "B-2")],
            ["B-2"],
        )
        self.assertEqual(
            [row["package"] for row in _filter_findings(self.findings, set(), set(), "All", "ALPHA")],
            ["alpha", "alpha"],
        )
        combined = _filter_findings(self.findings, {"HIGH"}, set(), "All", "B-2")
        self.assertEqual([row["vulnerability_id"] for row in combined], ["B-2"])

    def test_navigation_has_four_main_workspaces_and_safe_fallback(self):
        self.assertEqual([key for key, _ in NAVIGATION_ITEMS], ["overview", "investigation", "intelligence", "reports"])
        self.assertEqual(_navigation_section("intelligence"), "intelligence")
        self.assertEqual(_navigation_section("unknown"), "overview")

    def test_reachability_copy_does_not_overclaim_not_found(self):
        explanation = _reachability_explanation("NOT_FOUND")
        self.assertIn("not prove", explanation)
        self.assertIn("safe", explanation)
        limitations = _reachability_limitations().casefold()
        for limitation in ("dynamic loading", "reflection", "plugins", "transitive", "curated", "ambiguous", "unknown"):
            self.assertIn(limitation, limitations)

    def test_summary_uses_findings(self):
        self.assertEqual(_finding_summary(self.findings), {
            "total": 5,
            "unique_packages": 4,
            "used": 2,
            "unknown_reachability": 1,
        })

    def test_package_metrics_keep_same_name_separate_across_ecosystems(self):
        findings = [
            {"package": "shared", "ecosystem": "PyPI", "severity": "HIGH", "priority": "HIGH", "reachability": "USED", "risk_score": 80},
            {"package": "shared", "ecosystem": "npm", "severity": "LOW", "priority": "LOW", "reachability": "NOT_FOUND", "risk_score": 30},
        ]
        self.assertEqual(_finding_summary(findings)["unique_packages"], 2)
        analytics = _security_analytics(findings, [])
        self.assertEqual(len(analytics["package_ranking"]), 2)
        self.assertEqual({row["ecosystem"] for row in analytics["package_ranking"]}, {"PyPI", "npm"})

    def test_36_findings_default_queue_and_empty_filters_show_everything(self):
        findings = make_reported_sample()
        queued = _prepare_queue(findings, set(), set(), "All", SORT_OPTIONS[0])
        self.assertEqual(len(queued), 36)
        self.assertEqual(Counter(row["severity"] for row in queued), {
            "HIGH": 10, "MEDIUM": 18, "UNKNOWN": 8,
        })

    def test_36_finding_filters_apply_independently_and_all_reachability(self):
        findings = make_reported_sample()
        high_only = _prepare_queue(findings, {"HIGH"}, set(), "All", SORT_OPTIONS[0])
        medium_priority_only = _prepare_queue(findings, set(), {"MEDIUM"}, "All", SORT_OPTIONS[0])
        used_only = _prepare_queue(findings, set(), set(), "USED", SORT_OPTIONS[0])
        unknown_severity = _prepare_queue(findings, {"UNKNOWN"}, {"UNKNOWN"}, "All", SORT_OPTIONS[0])
        self.assertEqual(len(high_only), 10)
        self.assertEqual(len(medium_priority_only), 18)
        self.assertEqual(len(used_only), 12)
        self.assertEqual(len(unknown_severity), 8)
        self.assertEqual(len(_prepare_queue(findings, set(), set(), "All", SORT_OPTIONS[0])), 36)

    def test_reset_defaults_restore_all_36_and_csv_ignores_filters(self):
        findings = make_reported_sample()
        defaults = _queue_filter_defaults(findings)
        restored = _prepare_queue(
            findings, set(defaults["soc-severity"]), set(defaults["soc-priority"]),
            defaults["soc-reachability"], defaults["soc-sort"],
        )
        filtered = _prepare_queue(findings, {"HIGH"}, set(), "All", SORT_OPTIONS[0])
        reachability = [
            {"package": finding["package"], "status": finding["reachability"], "evidence": []}
            for finding in findings
        ]
        csv_rows = list(csv.reader(io.StringIO(generate_csv_report(findings, reachability).decode("utf-8"))))
        self.assertEqual(len(restored), 36)
        self.assertEqual(len(filtered), 10)
        self.assertEqual(len(csv_rows) - 1, 36)

    def test_reports_download_receives_all_findings_after_queue_filtering(self):
        findings = make_reported_sample()
        filtered_queue = _prepare_queue(findings, {"HIGH"}, set(), "All", SORT_OPTIONS[0])
        self.assertEqual(len(filtered_queue), 10)
        fake_st = SimpleNamespace(markdown=Mock(), title=Mock(), caption=Mock(), download_button=Mock())
        with patch.object(app, "st", fake_st):
            app._render_reports(findings, True, [])
        downloaded = fake_st.download_button.call_args.kwargs["data"]
        exported = list(csv.reader(io.StringIO(downloaded.decode("utf-8"))))
        self.assertEqual(len(exported) - 1, 36)

    def test_36_finding_risk_analysis_uses_actual_scores_and_reachability(self):
        summary = _risk_analysis_summary(make_reported_sample())
        self.assertEqual(summary["average"], 72.5)
        self.assertEqual(summary["highest"], 90)
        self.assertEqual(summary["unknown_severity"], 8)
        self.assertEqual(summary["reachability"], {"USED": 12, "NOT_FOUND": 12, "UNKNOWN": 12})


def make_reported_sample():
    findings = []
    distribution = [("HIGH", 10), ("MEDIUM", 18), ("UNKNOWN", 8)]
    index = 0
    for severity, count in distribution:
        for _ in range(count):
            findings.append({
                "package": f"sample-package-{index:02d}",
                "vulnerability_id": f"OSV-2026-{index:04d}",
                "installed_version": "1.0.0",
                "severity": severity,
                "priority": severity,
                "reachability": ("USED", "NOT_FOUND", "UNKNOWN")[index % 3],
                "risk_score": 90 - index,
            })
            index += 1
    return findings


if __name__ == "__main__":
    unittest.main()
