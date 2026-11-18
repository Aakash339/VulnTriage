import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import orchestrator


class ScanCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def run_scan(self, query_results):
        coverage = {}
        with patch("agents.vulnerability_agent._query", side_effect=query_results) as query:
            findings = orchestrator.run_vulntriage(str(self.root), coverage=coverage)
        return findings, coverage, query

    def test_successful_zero_vulnerability_scan_is_complete(self):
        self.write("requirements.txt", "requests==2.31.0\n")
        findings, coverage, query = self.run_scan([{"vulns": []}])
        self.assertEqual(findings, [])
        self.assertEqual(query.call_count, 1)
        self.assertEqual(coverage["status"], "COMPLETE")
        self.assertEqual(coverage["dependencies_detected"], 1)
        self.assertEqual(coverage["successfully_queried_dependencies"], 1)
        self.assertEqual(coverage["failed_queries"], 0)

    def test_partial_dependency_parsing_failure_is_reported(self):
        self.write("requirements.txt", "requests==2.31.0\n")
        self.write("pom.xml", "<project><dependencies>")
        _findings, coverage, query = self.run_scan([{"vulns": []}])
        self.assertEqual(query.call_count, 1)
        self.assertEqual(coverage["dependencies_detected"], 1)
        self.assertEqual(coverage["parsing_failures"], 1)
        self.assertEqual(coverage["successfully_queried_dependencies"], 1)
        self.assertEqual(coverage["status"], "PARTIAL")

    def test_partial_osv_query_failure_is_reported(self):
        self.write("requirements.txt", "alpha==1.0\nbeta==1.0\n")
        _findings, coverage, query = self.run_scan([{"vulns": []}, None])
        self.assertEqual(query.call_count, 2)
        self.assertEqual(coverage["successfully_queried_dependencies"], 1)
        self.assertEqual(coverage["failed_queries"], 1)
        self.assertEqual(coverage["status"], "PARTIAL")

    def test_all_osv_queries_failing_get_distinct_status(self):
        self.write("requirements.txt", "requests==2.31.0\n")
        _findings, coverage, query = self.run_scan([None])
        self.assertEqual(query.call_count, 1)
        self.assertEqual(coverage["failed_queries"], 1)
        self.assertEqual(coverage["successfully_queried_dependencies"], 0)
        self.assertEqual(coverage["status"], "ALL_OSV_QUERIES_FAILED")

    def test_no_supported_dependencies_is_not_marked_complete(self):
        self.write("README.md", "No dependency manifests here.\n")
        _findings, coverage, query = self.run_scan([])
        self.assertEqual(query.call_count, 0)
        self.assertEqual(coverage["dependencies_detected"], 0)
        self.assertEqual(coverage["status"], "NO_SUPPORTED_DEPENDENCIES")

    def test_unsupported_manifest_prevents_a_false_complete_scan(self):
        self.write("requirements.txt", "requests==2.31.0\n")
        self.write("pyproject.toml", "[project]\ndependencies = ['urllib3']\n")
        _findings, coverage, query = self.run_scan([{"vulns": []}])
        self.assertEqual(query.call_count, 1)
        self.assertEqual(coverage["unsupported_manifests"], 1)
        self.assertEqual(coverage["status"], "PARTIAL")


if __name__ == "__main__":
    unittest.main()
