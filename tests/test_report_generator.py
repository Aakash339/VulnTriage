import csv
import io
import unittest

from reports.report_generator import generate_csv_report


HEADER = [
    "Package", "Vulnerability ID", "Severity", "Reachability", "Priority",
    "Risk Score", "Risk Level", "Risk Factors", "Risk Explanation",
    "Installed Version", "Recommended Version", "Recommendation",
]


class ReportGeneratorTests(unittest.TestCase):
    def rows(self, data):
        return list(csv.reader(io.StringIO(data.decode("utf-8"), newline="")))

    def test_empty_report_has_header(self):
        self.assertEqual(self.rows(generate_csv_report([])), [HEADER])

    def test_one_and_multiple_findings(self):
        one = {"package": "pkg", "vulnerability_id": "CVE-1", "severity": "HIGH"}
        two = {"package": "pkg2", "vulnerability_id": "CVE-2"}
        rows = self.rows(generate_csv_report([one, two]))
        self.assertEqual(rows[0], HEADER)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[1][:3], ["pkg", "CVE-1", "HIGH"])
        self.assertEqual(rows[2][:2], ["pkg2", "CVE-2"])
        self.assertEqual(rows[2][2:], [""] * 10)

    def test_csv_escapes_commas_quotes_and_newlines(self):
        recommendation = 'Upgrade carefully, then review "compatibility".\nRetest.'
        rows = self.rows(generate_csv_report([{"recommendation": recommendation}]))
        self.assertEqual(rows[1][-1], recommendation)

    def test_utf8_and_bytes(self):
        result = generate_csv_report([{"package": "café"}])
        self.assertIsInstance(result, bytes)
        self.assertIn("café".encode("utf-8"), result)

    def test_column_order_and_missing_values(self):
        rows = self.rows(generate_csv_report([{"recommendation": "Fix"}]))
        self.assertEqual(rows[0], HEADER)
        self.assertEqual(rows[1], ["", "", "", "", "", "", "", "", "", "", "", "Fix"])

    def test_risk_fields_are_exported(self):
        row = {
            "risk_score": 87,
            "risk_level": "CRITICAL",
            "risk_factors": ["Severity: 50/50", "Reachability: 30/30"],
            "risk_explanation": "The score reflects severity and import evidence.",
        }
        rows = self.rows(generate_csv_report([row]))
        self.assertEqual(rows[0], HEADER)
        self.assertEqual(rows[1][5:9], [
            "87", "CRITICAL", "Severity: 50/50; Reachability: 30/30",
            "The score reflects severity and import evidence.",
        ])

    def test_36_finding_export_has_exact_columns_and_preserves_risk_and_remediation(self):
        findings = [
            {
                "package": f"package-{index:02d}",
                "vulnerability_id": f"OSV-2026-{index:04d}",
                "severity": "UNKNOWN" if index >= 28 else ("HIGH" if index < 10 else "MEDIUM"),
                "reachability": "USED",
                "priority": "UNKNOWN" if index >= 28 else ("HIGH" if index < 10 else "MEDIUM"),
                "risk_score": 80 - index,
                "risk_level": "HIGH",
                "risk_factors": ["Severity contribution", "Reachability contribution"],
                "risk_explanation": f"Risk explanation for finding {index}.",
                "installed_version": "1.0.0",
                "recommended_version": "2.0.0",
                "recommendation": f"Upgrade package-{index:02d} and validate compatibility.",
            }
            for index in range(36)
        ]

        rows = self.rows(generate_csv_report(findings))
        self.assertEqual(rows[0], HEADER)
        self.assertEqual(len(HEADER), 12)
        self.assertEqual(len(rows), 37)
        self.assertTrue(all(len(row) == 12 for row in rows))
        self.assertTrue(all(row[-1] for row in rows[1:]), "unexpected empty trailing column or recommendation")
        self.assertEqual(rows[1][7], "Severity contribution; Reachability contribution")
        self.assertEqual(rows[1][8], "Risk explanation for finding 0.")
        self.assertEqual(rows[-1][11], "Upgrade package-35 and validate compatibility.")

    def test_non_mapping_rows_are_skipped(self):
        self.assertEqual(self.rows(generate_csv_report([None, "bad"])), [HEADER])


if __name__ == "__main__":
    unittest.main()
