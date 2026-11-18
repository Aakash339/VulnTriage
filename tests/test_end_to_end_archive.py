import csv
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import orchestrator
from app import _extract_project_zip
from reports.report_generator import generate_csv_report


class ArchiveToReportIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def archive(files):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as zipped:
            for path, content in files.items():
                zipped.writestr(path, content)
        return output.getvalue()

    @staticmethod
    def project_files(ecosystems):
        files = {}
        if "PyPI" in ecosystems:
            files["python/requirements.txt"] = "requests==2.31.0\n"
            files["python/src/main.py"] = "import requests\n"
        if "npm" in ecosystems:
            files["web/package.json"] = json.dumps({"dependencies": {"lodash": "4.17.21"}})
            files["web/src/index.js"] = "import lodash from 'lodash';\n"
        if "Maven" in ecosystems:
            files["java/pom.xml"] = (
                "<project><dependencies><dependency><groupId>com.google.guava</groupId>"
                "<artifactId>guava</artifactId><version>32.1.3-jre</version>"
                "</dependency></dependencies></project>"
            )
            files["java/src/main/java/App.java"] = (
                "import com.google.common.collect.ImmutableList;\nclass App {}\n"
            )
        return files

    @staticmethod
    def osv_response(name, version, ecosystem):
        safe_name = name.replace(":", "-").replace("/", "-")
        return {"vulns": [{
            "id": f"OSV-{ecosystem}-{safe_name}",
            "summary": f"Test advisory for {name}",
            "severity": "HIGH",
            "affected": [{
                "package": {"name": name, "ecosystem": ecosystem},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "99.0.0"}]}],
            }],
        }]}

    def test_each_ecosystem_archive_runs_through_pipeline_and_csv(self):
        scenarios = (
            ("Python-only", {"PyPI"}, {"requests"}),
            ("npm-only", {"npm"}, {"lodash"}),
            ("Java-only", {"Maven"}, {"com.google.guava:guava"}),
            ("mixed", {"PyPI", "npm", "Maven"}, {"requests", "lodash", "com.google.guava:guava"}),
        )
        for label, ecosystems, expected_packages in scenarios:
            with self.subTest(project=label):
                archive = self.archive(self.project_files(ecosystems))
                extracted_root = self.root / label
                extracted_root.mkdir()
                project_root = _extract_project_zip(archive, extracted_root)
                coverage = {}
                events = []

                def query(name, version, ecosystem):
                    self.assertIn(ecosystem, ecosystems)
                    return self.osv_response(name, version, ecosystem)

                with patch("agents.vulnerability_agent._query", side_effect=query) as mocked_query:
                    findings = orchestrator.run_vulntriage(
                        str(project_root), progress_callback=events.append, coverage=coverage,
                    )

                dependencies = next(event["data"] for event in events
                                    if event["stage"] == "dependencies" and event["status"] == "completed")
                reaches = next(event["data"] for event in events
                               if event["stage"] == "reachability" and event["status"] == "completed")
                self.assertEqual({item["ecosystem"] for item in dependencies}, ecosystems)
                self.assertEqual({item["name"] for item in dependencies}, expected_packages)
                self.assertEqual(mocked_query.call_count, len(expected_packages))
                self.assertEqual({item["package"] for item in findings}, expected_packages)
                self.assertEqual({item["ecosystem"] for item in findings}, ecosystems)
                self.assertEqual(coverage["status"], "COMPLETE")

                for finding in findings:
                    self.assertTrue(finding["vulnerability_id"].startswith("OSV-"))
                    self.assertEqual(finding["severity"], "HIGH")
                    self.assertEqual(finding["reachability"], "USED")
                    self.assertEqual(finding["priority"], "HIGH")
                    self.assertGreaterEqual(finding["risk_score"], 0)
                    self.assertLessEqual(finding["risk_score"], 100)
                    self.assertTrue(finding["risk_level"])
                    self.assertTrue(finding["risk_factors"])
                    self.assertTrue(finding["risk_explanation"])
                    self.assertEqual(finding["recommended_version"], "99.0.0")
                    self.assertIn("Upgrade", finding["recommendation"])

                report = list(csv.DictReader(io.StringIO(
                    generate_csv_report(findings, reaches).decode("utf-8"),
                )))
                self.assertEqual(len(report), len(expected_packages))
                self.assertEqual({row["Package"] for row in report}, expected_packages)
                self.assertEqual({row["Ecosystem"] for row in report}, ecosystems)
                for row in report:
                    self.assertIn("Static import evidence was detected", row["Reachability Interpretation"])
                    expected_import = {
                        "PyPI": "import requests",
                        "npm": "'lodash'",
                        "Maven": "com.google.common.collect.ImmutableList",
                    }[row["Ecosystem"]]
                    self.assertIn(expected_import, row["Reachability Evidence"])


if __name__ == "__main__":
    unittest.main()
