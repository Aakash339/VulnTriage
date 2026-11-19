import hashlib
import io
import tempfile
import unittest
import zipfile
from contextlib import nullcontext
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app
from agents.compatibility_test_agent import run_compatibility_tests


def make_zip(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, contents in files.items():
            archive.writestr(name, contents)
    return output.getvalue()


class FakeUpload:
    name = "project.zip"

    def __init__(self, contents):
        self._contents = contents

    def getvalue(self):
        return self._contents


class CompatibilitySelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def data(self, package="requests", ecosystem="PyPI", candidates=None):
        candidates = candidates or ["2.32.0", "2.33.0"]
        return {
            "compatibility_assessments": [{
                "package": package, "ecosystem": ecosystem, "installed_version": "2.31.0",
                "candidate_fixed_versions": candidates, "assessment_status": "REVIEW_REQUIRED",
            }],
            "dependencies": [{
                "name": package, "ecosystem": ecosystem, "version": "2.31.0",
                "source_file": "requirements.txt" if ecosystem == "PyPI" else "pom.xml",
            }],
            "code_suggestions": [{
                "package": package, "ecosystem": ecosystem,
                "source_file": "src/client.py" if ecosystem == "PyPI" else "src/Main.java",
                "line_number": 3, "detected_reference": "requests.get",
            }],
            "api_impact_results": [],
            "compatibility_test_results": [{
                "package": package, "ecosystem": ecosystem, "status": "NOT_RUN",
                "reason": "Initial scan has no explicit selected version.",
            }],
            "review_proposals": [{
                "proposal_id": "review-1", "package": package, "ecosystem": ecosystem,
                "decision": "PENDING", "review_status": "PENDING",
            }],
        }

    def test_only_explicit_valid_osv_candidate_builds_test_change(self):
        data = self.data()
        suggestion = app._selected_compatibility_test_input(data, "requests", "PyPI", "2.32.0")
        self.assertEqual(suggestion["proposed_dependency_change"], {
            "package": "requests", "ecosystem": "PyPI", "from_version": "2.31.0",
            "to_version": "2.32.0", "manifest_file": "requirements.txt",
        })
        self.assertEqual(suggestion["source_file"], "src/client.py")
        self.assertEqual(suggestion["line_number"], 3)
        self.assertEqual(suggestion["review_status"], "REVIEW_REQUIRED")

    def test_rejects_version_outside_validated_candidate_list(self):
        with self.assertRaisesRegex(ValueError, "fixed-version candidate"):
            app._selected_compatibility_test_input(self.data(), "requests", "PyPI", "9.9.9")

    def test_selected_version_reaches_existing_testing_agent_and_stores_result(self):
        data = self.data()
        archive = make_zip({
            "project/requirements.txt": "requests==2.31.0\n",
            "project/src/client.py": "import requests\nrequests.get('https://example.test')\n",
        })
        upload = FakeUpload(archive)
        session = {"vulntriage_upload": hashlib.sha256(archive).hexdigest()}
        expected_result = {
            "package": "requests", "ecosystem": "PyPI", "status": "PASSED",
            "test_command": ["python", "-m", "py_compile", "src/client.py"],
            "tested_dependency_changes": [{"package": "requests", "ecosystem": "PyPI",
                "from_version": "2.31.0", "to_version": "2.32.0", "manifest_file": "requirements.txt"}],
            "reason": "Static syntax check passed.", "stdout": "", "stderr": "", "exit_code": 0,
            "limitations": "Syntax only.",
        }
        fake_st = SimpleNamespace(session_state=session)
        with patch.object(app, "st", fake_st), patch.object(
            app, "run_compatibility_tests", return_value=[expected_result],
        ) as checker:
            updated = app._run_selected_compatibility_check(data, upload, "requests", "PyPI", "2.32.0")

        checker.assert_called_once()
        suggestion = checker.call_args.args[2][0]
        self.assertEqual(suggestion["proposed_dependency_change"]["to_version"], "2.32.0")
        saved = app._compatibility_run_for_selection(updated, "requests", "PyPI", "2.32.0")
        self.assertEqual(saved["result"], expected_result)
        self.assertEqual(saved["selected_version"], "2.32.0")

    def test_render_shows_result_only_for_selected_dependency_and_version(self):
        data = self.data(candidates=["2.32.0", "2.33.0", "2.34.0"])
        old_key = app._compatibility_run_key("requests", "PyPI", "2.32.0")
        selected_key = app._compatibility_run_key("requests", "PyPI", "2.33.0")
        other_package_key = app._compatibility_run_key("requests", "npm", "2.33.0")
        data["compatibility_check_runs"] = {
            old_key: {
                "package": "requests", "ecosystem": "PyPI", "selected_version": "2.32.0",
                "result": {"status": "PASSED", "reason": "Old target passed", "test_command": ["old-check"]},
            },
            selected_key: {
                "package": "requests", "ecosystem": "PyPI", "selected_version": "2.33.0",
                "result": {"status": "FAILED", "reason": "Selected target failed", "test_command": ["selected-check"]},
            },
            other_package_key: {
                "package": "requests", "ecosystem": "npm", "selected_version": "2.33.0",
                "result": {"status": "PASSED", "reason": "Other ecosystem passed", "test_command": ["other-check"]},
            },
        }
        output = {"text": [], "captions": [], "selectboxes": []}
        selected = {"version": "2.33.0"}
        fake_st = SimpleNamespace(
            markdown=Mock(), title=Mock(), caption=lambda value: output["captions"].append(str(value)),
            subheader=Mock(), write=lambda value: output["text"].append(str(value)),
            info=Mock(), warning=Mock(), error=Mock(), success=Mock(), code=Mock(),
            expander=lambda *_args, **_kwargs: nullcontext(),
            columns=lambda count: [nullcontext() for _ in range(count)],
            text_input=lambda *_args, **_kwargs: "",
            button=lambda *_args, **_kwargs: False,
            selectbox=lambda label, options, **kwargs: (output["selectboxes"].append(tuple(options)) or selected["version"]),
            session_state={},
        )
        with patch.object(app, "st", fake_st):
            app._render_remediation_compatibility(data)

        rendered = "\n".join(output["text"] + output["captions"])
        self.assertIn("Selected proposed version: 2.33.0", rendered)
        self.assertIn("Check result for 2.33.0: FAILED", rendered)
        self.assertIn("Selected target failed", rendered)
        self.assertNotIn("Old target passed", rendered)
        self.assertNotIn("Other ecosystem passed", rendered)
        self.assertEqual(output["selectboxes"], [("2.32.0", "2.33.0", "2.34.0")])
        self.assertIsNone(app._compatibility_run_for_selection(data, "requests", "PyPI", "2.34.0"))
        selected["version"] = "2.34.0"
        output["text"].clear()
        output["captions"].clear()
        with patch.object(app, "st", fake_st):
            app._render_remediation_compatibility(data)
        changed_selection_render = "\n".join(output["text"] + output["captions"])
        self.assertIn("Selected proposed version: 2.34.0", changed_selection_render)
        self.assertIn("No check result exists for this selected version yet", changed_selection_render)
        self.assertNotIn("Selected target failed", changed_selection_render)

    def test_dashboard_action_passes_explicit_selection_to_test_workflow(self):
        data = self.data()
        archive = make_zip({"project/requirements.txt": "requests==2.31.0\n"})
        upload = FakeUpload(archive)
        scan_identity = hashlib.sha256(archive).hexdigest()
        state = {
            "soc_uploaded_project": upload,
            "vulntriage_upload": scan_identity,
        }
        updated = dict(data)
        updated["compatibility_check_runs"] = {
            app._compatibility_run_key("requests", "PyPI", "2.33.0"): {
                "package": "requests", "ecosystem": "PyPI", "selected_version": "2.33.0",
                "result": {"status": "NOT_RUN", "reason": "Selected candidate lacks supported test setup."},
            },
        }
        fake_st = SimpleNamespace(
            markdown=Mock(), title=Mock(), caption=Mock(), subheader=Mock(), write=Mock(),
            info=Mock(), warning=Mock(), error=Mock(), success=Mock(), code=Mock(),
            expander=lambda *_args, **_kwargs: nullcontext(),
            columns=lambda count: [nullcontext() for _ in range(count)],
            selectbox=lambda _label, **_kwargs: "2.33.0",
            text_input=lambda *_args, **_kwargs: "",
            button=lambda _label, key, **_kwargs: key == app._compatibility_widget_key("requests", "PyPI", "action"),
            session_state=state,
        )
        with patch.object(app, "st", fake_st), patch.object(
            app, "_run_selected_compatibility_check", return_value=updated,
        ) as run_check:
            app._render_remediation_compatibility(data)

        run_check.assert_called_once_with(data, upload, "requests", "PyPI", "2.33.0")
        self.assertIs(state["soc_scan_data"], updated)
        self.assertEqual(
            app._compatibility_run_for_selection(state["soc_scan_data"], "requests", "PyPI", "2.33.0")["result"]["status"],
            "NOT_RUN",
        )

    def test_unsupported_maven_change_remains_not_run(self):
        project = self.root / "java"
        (project / "src").mkdir(parents=True)
        (project / "pom.xml").write_text("<project/>", encoding="utf-8")
        (project / "src" / "Main.java").write_text("import org.example.Api;\n", encoding="utf-8")
        assessment = {
            "package": "org.example:library", "ecosystem": "Maven", "installed_version": "1.0",
            "candidate_fixed_versions": ["2.0"], "assessment_status": "REVIEW_REQUIRED",
        }
        suggestion = {
            "package": "org.example:library", "ecosystem": "Maven", "source_file": "src/Main.java",
            "line_number": 1, "review_status": "REVIEW_REQUIRED",
            "proposed_dependency_change": {
                "package": "org.example:library", "ecosystem": "Maven", "from_version": "1.0",
                "to_version": "2.0", "manifest_file": "pom.xml",
            },
        }
        result = run_compatibility_tests(str(project), [assessment], [suggestion])[0]
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertIn("Only exact pinned requirements", result["reason"])

    def test_uploaded_archive_and_extracted_project_are_not_modified(self):
        archive = make_zip({
            "project/requirements.txt": "requests==2.31.0\n",
            "project/src/client.py": "import requests\n",
        })
        upload = FakeUpload(archive)
        data = self.data()
        session = {"vulntriage_upload": hashlib.sha256(archive).hexdigest()}
        fake_st = SimpleNamespace(session_state=session)
        original_tempdir = tempfile.TemporaryDirectory
        created = []
        extracted = []

        def local_tempdir(**kwargs):
            temporary = original_tempdir(dir=self.root, **kwargs)
            created.append(temporary)
            return temporary

        original_extract = app._extract_project_zip

        def track_extract(contents, destination):
            root = original_extract(contents, destination)
            extracted.append(root)
            return root

        manifest_snapshot = "requests==2.31.0\n"

        def inspect_isolated_workspace(command, workspace):
            self.assertEqual((workspace / "requirements.txt").read_text(encoding="utf-8"), "requests==2.32.0\n")
            self.assertEqual((extracted[0] / "requirements.txt").read_text(encoding="utf-8"), manifest_snapshot)
            return CompletedProcess(command, 0, "syntax ok", "")

        with patch.object(app, "st", fake_st), patch.object(app.tempfile, "TemporaryDirectory", side_effect=local_tempdir), \
             patch.object(app, "_extract_project_zip", side_effect=track_extract), \
             patch("agents.compatibility_test_agent._run_static_check", side_effect=inspect_isolated_workspace):
            updated = app._run_selected_compatibility_check(data, upload, "requests", "PyPI", "2.32.0")

        self.assertEqual(upload.getvalue(), archive)
        saved_result = updated["compatibility_check_runs"][app._compatibility_run_key("requests", "PyPI", "2.32.0")]["result"]
        self.assertEqual(saved_result["status"], "PASSED", saved_result)
        self.assertTrue(all(not Path(temp.name).exists() for temp in created))

    def test_approval_records_remain_separate_from_selected_test_runs(self):
        data = self.data()
        original_approval = data["review_proposals"][0].copy()
        archive = make_zip({
            "project/requirements.txt": "requests==2.31.0\n",
            "project/src/client.py": "import requests\n",
        })
        session = {"vulntriage_upload": hashlib.sha256(archive).hexdigest()}
        with patch.object(app, "st", SimpleNamespace(session_state=session)), patch.object(
            app, "run_compatibility_tests", return_value=[{"status": "NOT_RUN", "package": "requests", "ecosystem": "PyPI"}],
        ):
            updated = app._run_selected_compatibility_check(
                data, FakeUpload(archive), "requests", "PyPI", "2.32.0",
            )
        self.assertEqual(updated["review_proposals"], [original_approval])
        self.assertEqual(updated["review_proposals"][0]["decision"], "PENDING")


if __name__ == "__main__":
    unittest.main()
