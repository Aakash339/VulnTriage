import csv
import io
import tempfile
import unittest
import zipfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app
from reports.report_generator import generate_csv_report


def make_archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return output.getvalue()


class FakeUpload:
    name = "sample.zip"

    def __init__(self, content):
        self.content = content

    def getvalue(self):
        return self.content


class FakeProgress:
    def __init__(self):
        self.messages = []

    def progress(self, value, text=None):
        self.messages.append((value, text))


class FakePipelineSlot:
    def container(self):
        return nullcontext()


class AppMilestone7IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def run_app_scan(self, archive, pipeline, agents):
        state = {}
        progress = FakeProgress()
        fake_streamlit = SimpleNamespace(
            session_state=state,
            container=lambda **_kwargs: nullcontext(),
            markdown=Mock(),
            subheader=Mock(),
            progress=Mock(return_value=progress),
            empty=Mock(return_value=FakePipelineSlot()),
        )
        paths_seen = []

        def track_path(function):
            def wrapped(*args):
                for argument in args:
                    if isinstance(argument, str):
                        path = Path(argument)
                        if path.is_dir() and path.name.startswith("project"):
                            paths_seen.append(path)
                            self.assertTrue(path.exists(), "agent must run before extracted files are cleaned")
                return function(*args)
            return wrapped

        original_tempdir = tempfile.TemporaryDirectory

        def create_tempdir(**kwargs):
            return original_tempdir(dir=self.root, **kwargs)

        with patch.object(app, "st", fake_streamlit), patch.object(app, "run_vulntriage", side_effect=pipeline), \
             patch.object(app, "_render_pipeline"), \
             patch.object(app.tempfile, "TemporaryDirectory", side_effect=create_tempdir):
            patches = [patch.object(app, name, track_path(function)) for name, function in agents.items()]
            entered = []
            for item in patches:
                item.start()
                entered.append(item)
            try:
                app._scan_with_progress(FakeUpload(archive), "sha256-test")
            finally:
                for item in reversed(entered):
                    item.stop()

        return state, paths_seen, progress

    @staticmethod
    def scan_records(callback):
        dependencies = [{
            "name": "requests", "version": "2.31.0", "ecosystem": "PyPI",
            "source_file": "requirements.txt",
        }]
        vulnerabilities = [{
            "package": "requests", "ecosystem": "PyPI", "installed_version": "2.31.0",
            "vulnerability_id": "GHSA-test", "summary": "test advisory", "severity": "HIGH",
            "fixed_versions": ["2.32.0"], "references": [],
        }]
        reachability = [{
            "package": "requests", "ecosystem": "PyPI", "status": "USED",
            "evidence": ["main.py:1: import requests"],
        }]
        for stage, result in (
            ("dependencies", dependencies), ("osv", vulnerabilities),
            ("reachability", reachability),
        ):
            callback({"stage": stage, "status": "completed", "data": result})
        return [
            {"package": "requests", "ecosystem": "PyPI", "vulnerability_id": "GHSA-test",
             "severity": "HIGH", "priority": "HIGH", "reachability": "USED",
             "installed_version": "2.31.0", "recommended_version": "2.32.0",
             "recommendation": "Upgrade requests.", "risk_score": 75},
        ]

    def test_agents_run_in_order_inside_temp_root_and_store_separate_outputs(self):
        archive = make_archive({
            "project/requirements.txt": "requests==2.31.0\n",
            "project/main.py": "import requests\n",
        })
        expected = {
            "compatibility_assessments": [{"stage": "compatibility"}],
            "api_impact_results": [{"stage": "api_impact"}],
            "code_suggestions": [{"stage": "code_suggestions"}],
            "compatibility_test_results": [{"stage": "compatibility_tests"}],
            "review_proposals": [{"stage": "approvals"}],
        }
        order = []
        agent_names = (
            "analyze_compatibility", "analyze_api_impact", "generate_code_suggestions",
            "run_compatibility_tests", "prepare_review_proposals",
        )
        stubs = {}
        for name, key in zip(agent_names, expected):
            def build_stub(stage, data_key):
                def stub(*args):
                    order.append(stage)
                    if stage == "compatibility":
                        self.assertEqual(len(args), 3)
                        self.assertEqual(args[0][0]["name"], "requests")
                        self.assertEqual(args[1][0]["package"], "requests")
                        self.assertEqual(args[2][0]["status"], "USED")
                    elif stage == "api_impact":
                        self.assertEqual(args[2], [{"stage": "compatibility"}])
                    elif stage == "code_suggestions":
                        self.assertEqual(args[1], [{"stage": "api_impact"}])
                    elif stage == "compatibility_tests":
                        self.assertEqual(args[2], [{"stage": "code_suggestions"}])
                    elif stage == "approvals":
                        self.assertEqual(args[1], [{"stage": "api_impact"}])
                        self.assertEqual(args[3], [{"stage": "compatibility_tests"}])
                    return expected[data_key]
                return stub
            stage = {
                "analyze_compatibility": "compatibility", "analyze_api_impact": "api_impact",
                "generate_code_suggestions": "code_suggestions", "run_compatibility_tests": "compatibility_tests",
                "prepare_review_proposals": "approvals",
            }[name]
            stubs[name] = build_stub(stage, key)

        def pipeline(project_path, progress_callback, coverage):
            self.assertTrue(Path(project_path).exists())
            findings = self.scan_records(progress_callback)
            coverage.update({"status": "COMPLETE"})
            progress_callback({"stage": "risk", "status": "completed", "data": findings})
            return findings

        state, paths_seen, progress = self.run_app_scan(archive, pipeline, stubs)
        self.assertEqual(state["soc_scan_status"], "completed", state.get("vulntriage_error"))
        self.assertEqual(order, ["compatibility", "api_impact", "code_suggestions", "compatibility_tests", "approvals"])
        data = state["soc_scan_data"]
        self.assertEqual(data["analysis_status"], {stage: {"status": "completed"} for stage in (
            "compatibility", "api_impact", "code_suggestions", "compatibility_tests", "approvals",
        )}, msg=str(data["analysis_status"]))
        for key, value in expected.items():
            self.assertEqual(data[key], value)
        self.assertEqual({row["status"] for row in data["analysis_status"].values()}, {"completed"})
        self.assertEqual(state["vulntriage_findings"][0]["package"], "requests")
        self.assertEqual(state["soc_scan_status"], "completed")
        self.assertTrue(paths_seen)
        self.assertTrue(all(not path.exists() for path in paths_seen))
        self.assertTrue(all(str(path) not in repr(state) for path in paths_seen))
        self.assertIn("Review Proposals complete", [message for _value, message in progress.messages])

    def test_optional_agent_failure_preserves_findings_and_runs_later_stages(self):
        archive = make_archive({"project/requirements.txt": "requests==2.31.0\n"})
        order = []

        def fail(*_args):
            order.append("compatibility")
            raise RuntimeError("optional analyzer unavailable")

        def later(*args):
            order.append("api_impact")
            self.assertEqual(args[2], [])
            return [{"status": "NOT_ASSESSED"}]

        stubs = {
            "analyze_compatibility": fail,
            "analyze_api_impact": later,
            "generate_code_suggestions": lambda *_args: [],
            "run_compatibility_tests": lambda *_args: [{"status": "NOT_RUN"}],
            "prepare_review_proposals": lambda *_args: [],
        }

        def pipeline(project_path, progress_callback, coverage):
            findings = self.scan_records(progress_callback)
            coverage.update({"status": "COMPLETE"})
            progress_callback({"stage": "risk", "status": "completed", "data": findings})
            return findings

        state, _paths, progress = self.run_app_scan(archive, pipeline, stubs)
        self.assertEqual(state["soc_scan_status"], "completed", state.get("vulntriage_error"))
        self.assertEqual(state["soc_scan_status"], "completed")
        self.assertEqual(len(state["vulntriage_findings"]), 1)
        self.assertEqual(state["soc_scan_data"]["analysis_status"]["compatibility"]["status"], "failed")
        self.assertIn("optional analyzer unavailable", state["soc_scan_data"]["analysis_status"]["compatibility"]["error"])
        self.assertEqual(state["soc_scan_data"]["api_impact_results"], [{"status": "NOT_ASSESSED"}])
        self.assertEqual(order, ["compatibility", "api_impact"])
        self.assertEqual(progress.messages[-1][1], "Vulnerability scan complete; optional analysis had errors")

    def test_real_agents_keep_conservative_outputs_and_existing_csv_behavior(self):
        archive = make_archive({
            "project/requirements.txt": "requests==2.31.0\n",
            "project/main.py": "import requests\n",
        })

        def pipeline(_project_path, progress_callback, coverage):
            findings = self.scan_records(progress_callback)
            coverage.update({"status": "COMPLETE"})
            progress_callback({"stage": "risk", "status": "completed", "data": findings})
            return findings

        state, _paths, _progress = self.run_app_scan(archive, pipeline, {})
        self.assertEqual(state["soc_scan_status"], "completed", state.get("vulntriage_error"))
        data = state["soc_scan_data"]
        self.assertTrue(data["api_impact_results"])
        self.assertEqual(data["code_suggestions"][0]["review_status"], "NO_SAFE_SUGGESTION")
        self.assertEqual(data["compatibility_test_results"][0]["status"], "NOT_RUN")
        self.assertTrue(data["review_proposals"])
        csv_rows = list(csv.DictReader(io.StringIO(generate_csv_report(
            state["vulntriage_findings"], data["reachability"],
        ).decode("utf-8"))))
        self.assertEqual(len(csv_rows), 1)
        self.assertEqual(csv_rows[0]["Package"], "requests")
        self.assertEqual(csv_rows[0]["Ecosystem"], "PyPI")
        self.assertIn("Static import evidence", csv_rows[0]["Reachability Interpretation"])


if __name__ == "__main__":
    unittest.main()
