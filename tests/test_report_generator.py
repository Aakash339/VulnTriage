import csv
import io
import unittest

from reports.report_generator import generate_csv_report


HEADER = [
    "Package", "Vulnerability ID", "Severity", "Reachability", "Priority",
    "Risk Score", "Risk Level", "Risk Factors", "Risk Explanation",
    "Installed Version", "Recommended Version", "Recommendation",
    "Reachability Evidence", "Reachability Interpretation",
]
INTERPRETATIONS = {
    "USED": "Static import evidence was detected. This does not prove runtime execution or exploitability.",
    "NOT_FOUND": "No matching import was detected in supported files. This does not prove the dependency is unused or safe.",
    "UNKNOWN": "Reachability could not be determined confidently.",
}


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
        self.assertEqual(rows[2][2:12], [""] * 10)
        self.assertEqual(rows[2][12:], ["No static import evidence available", INTERPRETATIONS["UNKNOWN"]])

    def test_csv_escapes_commas_quotes_and_newlines(self):
        recommendation = 'Upgrade carefully, then review "compatibility".\nRetest.'
        rows = self.rows(generate_csv_report([{"recommendation": recommendation}]))
        self.assertEqual(rows[1][11], recommendation)

    def test_utf8_and_bytes(self):
        result = generate_csv_report([{"package": "café"}])
        self.assertIsInstance(result, bytes)
        self.assertIn("café".encode("utf-8"), result)

    def test_column_order_and_missing_values(self):
        rows = self.rows(generate_csv_report([{"recommendation": "Fix"}]))
        self.assertEqual(rows[0], HEADER)
        self.assertEqual(rows[1], ["", "", "", "", "", "", "", "", "", "", "", "Fix",
                                   "No static import evidence available", INTERPRETATIONS["UNKNOWN"]])

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

        reachability = [
            {"package": finding["package"], "status": "USED", "evidence": [f"src/{index}.py:1: import {finding['package']}"]}
            for index, finding in enumerate(findings)
        ]
        rows = self.rows(generate_csv_report(findings, reachability))
        self.assertEqual(rows[0], HEADER)
        self.assertEqual(len(HEADER), 14)
        self.assertEqual(len(rows), 37)
        self.assertTrue(all(len(row) == 14 for row in rows))
        self.assertTrue(all(row[-1] for row in rows[1:]), "unexpected empty trailing column or recommendation")
        self.assertEqual(rows[1][7], "Severity contribution; Reachability contribution")
        self.assertEqual(rows[1][8], "Risk explanation for finding 0.")
        self.assertEqual(rows[-1][11], "Upgrade package-35 and validate compatibility.")
        self.assertEqual(rows[1][12], "src/0.py:1: import package-00")
        self.assertEqual(rows[1][13], INTERPRETATIONS["USED"])

    def test_reachability_status_interpretations_and_normalized_package_matching(self):
        findings = [
            {"package": "Some_Pkg", "reachability": "USED"},
            {"package": "absent", "reachability": "NOT_FOUND"},
            {"package": "uncertain", "reachability": "UNKNOWN"},
        ]
        reachability = [
            {"package": "some.pkg", "status": "USED", "evidence": ["app.py:3: import some_pkg"]},
            {"package": "ABSENT", "status": "NOT_FOUND", "evidence": []},
            {"package": "uncertain", "status": "UNKNOWN", "evidence": []},
        ]
        rows = self.rows(generate_csv_report(findings, reachability))[1:]
        self.assertEqual(rows[0][12], "app.py:3: import some_pkg")
        self.assertEqual([row[13] for row in rows], [
            INTERPRETATIONS["USED"], INTERPRETATIONS["NOT_FOUND"], INTERPRETATIONS["UNKNOWN"],
        ])
        self.assertEqual(rows[1][12], "No static import evidence available")
        self.assertEqual(rows[2][12], "No static import evidence available")

    def test_multiple_evidence_entries_and_csv_special_characters(self):
        evidence = [
            'src/app.py:2: import pkg, alias="one"',
            'src/other.py:8: import pkg\n# retained source context',
        ]
        rows = self.rows(generate_csv_report(
            [{"package": "pkg", "reachability": "USED"}],
            [{"package": "PKG", "status": "USED", "evidence": evidence}],
        ))
        self.assertEqual(rows[1][12], "\n".join(evidence))
        self.assertEqual(rows[1][13], INTERPRETATIONS["USED"])

    def test_optional_argument_and_missing_evidence_are_backward_compatible(self):
        rows = self.rows(generate_csv_report([{"package": "pkg", "reachability": "NOT_FOUND"}]))
        self.assertEqual(rows[1][12], "No static import evidence available")
        self.assertEqual(rows[1][13], INTERPRETATIONS["NOT_FOUND"])

    def test_non_mapping_rows_are_skipped(self):
        self.assertEqual(self.rows(generate_csv_report([None, "bad"])), [HEADER])


if __name__ == "__main__":
    unittest.main()
