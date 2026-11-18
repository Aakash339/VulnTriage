import io
import json
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from agents.dependency_agent import parse_dependencies
import app
from app import ArchiveValidationError, _coverage_notice, _display_coverage_notice, _extract_project_zip, _upload_identity


def make_zip(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return stream.getvalue()


def make_zip_entries(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content, mode in entries:
            info = zipfile.ZipInfo(name)
            if mode is not None:
                info.external_attr = mode << 16
            archive.writestr(info, content)
    return stream.getvalue()


def set_encrypted_flag(contents):
    data = bytearray(contents)
    local = data.index(b"PK\x03\x04")
    central = data.index(b"PK\x01\x02")
    data[local + 6] |= 1
    data[central + 8] |= 1
    return bytes(data)


def corrupt_stored_payload(contents):
    data = bytearray(contents)
    local = data.index(b"PK\x03\x04")
    name_length = int.from_bytes(data[local + 26:local + 28], "little")
    extra_length = int.from_bytes(data[local + 28:local + 30], "little")
    payload = local + 30 + name_length + extra_length
    data[payload] ^= 0xFF
    return bytes(data)


class FakeUpload:
    def __init__(self, name, contents):
        self.name = name
        self.size = len(contents)
        self._contents = contents

    def getvalue(self):
        return self._contents


class AppUploadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.rejection_index = 0

    def tearDown(self):
        self.temp.cleanup()

    def extract(self, archive):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name), _extract_project_zip(archive, Path(temporary.name))

    def test_different_same_name_same_size_archives_have_distinct_identity(self):
        first = make_zip({"project/requirements.txt": "requests==2.31.0\n"})
        second = make_zip({"project/requirements.txt": "requests==2.31.1\n"})
        self.assertEqual(len(first), len(second))

        first_upload = FakeUpload("project.zip", first)
        second_upload = FakeUpload("project.zip", second)
        self.assertEqual(first_upload.size, second_upload.size)
        self.assertNotEqual(_upload_identity(first_upload), _upload_identity(second_upload))

    def test_identical_zip_contents_have_reusable_identity(self):
        contents = make_zip({"project/pom.xml": "<project/>"})
        first = FakeUpload("first-name.zip", contents)
        second = FakeUpload("renamed.zip", contents)
        self.assertEqual(_upload_identity(first), _upload_identity(second))

    def test_scan_or_reuse_skips_scan_for_identical_content_and_scans_different_content(self):
        first_bytes = make_zip({"project/requirements.txt": "requests==2.31.0\n"})
        different_bytes = make_zip({"project/requirements.txt": "requests==2.31.1\n"})
        self.assertEqual(len(first_bytes), len(different_bytes))
        first = FakeUpload("same.zip", first_bytes)
        different = FakeUpload("same.zip", different_bytes)
        first_id = _upload_identity(first)
        state = {"vulntriage_upload": first_id, "vulntriage_findings": [{"package": "requests"}]}
        fake_streamlit = SimpleNamespace(session_state=state, info=Mock())
        with patch.object(app, "st", fake_streamlit), patch.object(app, "_scan_with_progress") as scan:
            self.assertTrue(app._scan_or_reuse(FakeUpload("renamed.zip", first_bytes), first_id))
            self.assertFalse(app._scan_or_reuse(different, _upload_identity(different)))
        self.assertEqual(scan.call_count, 1)
        self.assertEqual(state["soc_scan_status"], "completed")

    def assert_rejected_without_files(self, contents):
        self.rejection_index += 1
        destination = self.root / f"rejected-{self.rejection_index}"
        destination.mkdir()
        with self.assertRaises(ArchiveValidationError):
            _extract_project_zip(contents, destination)
        self.assertEqual(list(destination.iterdir()), [])

    def test_rejects_traversal_absolute_drive_and_backslash_paths(self):
        for name in ("../outside.txt", "safe/../../outside.txt", "/absolute.txt", "C:/drive.txt", "..\\outside.txt"):
            with self.subTest(name=name):
                self.assert_rejected_without_files(make_zip({name: "bad"}))

    def test_rejects_symlink_and_encrypted_entries(self):
        symlink = make_zip_entries([("link", "target", stat.S_IFLNK | 0o777)])
        encrypted = set_encrypted_flag(make_zip({"file.txt": "secret"}))
        self.assert_rejected_without_files(symlink)
        self.assert_rejected_without_files(encrypted)

    def test_rejects_corrupt_zip_and_corrupt_entry_data(self):
        self.assert_rejected_without_files(b"not a zip archive")
        valid = make_zip({"file.txt": "payload"})
        self.assert_rejected_without_files(corrupt_stored_payload(valid))

    def test_rejects_duplicate_archive_paths_before_extraction(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            duplicate = make_zip_entries([
                ("project/requirements.txt", "alpha==1.0\n", None),
                ("project/requirements.txt", "beta==1.0\n", None),
            ])
        self.assert_rejected_without_files(duplicate)

    def test_rejects_archive_entry_count_and_expanded_size_limits(self):
        many_entries = make_zip({"a.txt": "a", "b.txt": "b"})
        with patch.object(app, "MAX_ARCHIVE_FILES", 1):
            self.assert_rejected_without_files(many_entries)

        multiple_files = make_zip({"a.txt": "123", "b.txt": "456"})
        with patch.object(app, "MAX_EXTRACTED_BYTES", 5):
            self.assert_rejected_without_files(multiple_files)

        large_file = make_zip({"a.txt": "123"})
        with patch.object(app, "MAX_SINGLE_FILE_BYTES", 2):
            self.assert_rejected_without_files(large_file)

    def test_scan_temporary_extraction_is_cleaned_after_success_and_failure(self):
        valid = make_zip({"project/requirements.txt": "requests==2.31.0\n"})
        bad = b"not a zip"
        original_tempdir = tempfile.TemporaryDirectory

        class FakeProgress:
            def progress(self, *_args, **_kwargs):
                return None

        class FakeSlot:
            def container(self):
                from contextlib import nullcontext
                return nullcontext()

        def invoke(archive, should_fail):
            state = {}
            fake_st = SimpleNamespace(
                session_state=state,
                container=lambda **_kwargs: __import__("contextlib").nullcontext(),
                markdown=Mock(), subheader=Mock(), progress=Mock(return_value=FakeProgress()),
                empty=Mock(return_value=FakeSlot()),
            )
            created = []

            def create_tempdir(**kwargs):
                temporary = original_tempdir(dir=self.root, **kwargs)
                created.append(Path(temporary.name))
                return temporary

            extractor_patch = (
                patch.object(app, "_extract_project_zip", wraps=_extract_project_zip)
                if archive == bad else
                patch.object(app, "_extract_project_zip", side_effect=lambda _data, folder: folder)
            )
            pipeline_patch = (
                patch.object(app, "run_vulntriage", side_effect=RuntimeError("test scan failure"))
                if should_fail else
                patch.object(app, "run_vulntriage", return_value=[{"package": "requests"}])
            )
            with patch.object(app, "st", fake_st), patch.object(app.tempfile, "TemporaryDirectory", side_effect=create_tempdir), \
                 patch.object(app, "_render_pipeline"), extractor_patch, pipeline_patch:
                app._scan_with_progress(FakeUpload("project.zip", archive), "content-hash")
            self.assertEqual(len(created), 1)
            self.assertFalse(created[0].exists())
            self.assertEqual(state["soc_scan_status"], "failed" if should_fail else "completed")

        invoke(valid, should_fail=False)
        invoke(valid, should_fail=True)
        # Extraction failures also leave the temporary directory to its context manager.
        invoke(bad, should_fail=True)

    def test_coverage_display_uses_warning_and_success_channels(self):
        fake_st = SimpleNamespace(warning=Mock(), success=Mock(), error=Mock())
        with patch.object(app, "st", fake_st):
            level, message = _display_coverage_notice({"status": "PARTIAL"}, 1)
            self.assertEqual(level, "warning")
            self.assertIn("Partial scan", message)
            fake_st.warning.assert_called_once_with(message)

            level, message = _display_coverage_notice({
                "status": "COMPLETE", "dependencies_detected": 1,
                "successfully_queried_dependencies": 1,
            }, 0)
            self.assertEqual(level, "success")
            self.assertIn("no vulnerability findings", message)
            fake_st.success.assert_called_once_with(message)
            fake_st.error.assert_not_called()

    def test_java_only_nested_archive_selects_project_root(self):
        archive = make_zip({
            "outer/java-service/pom.xml": (
                "<project><dependencies><dependency><groupId>g</groupId>"
                "<artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>"
            ),
            "outer/java-service/src/Main.java": "class Main {}\n",
        })
        destination, root = self.extract(archive)
        self.assertEqual(root, destination / "outer" / "java-service")
        dependencies = parse_dependencies(str(root))
        self.assertEqual([(item["name"], item["ecosystem"]) for item in dependencies], [("g:a", "Maven")])

    def test_mixed_sibling_projects_keep_extraction_root_and_all_ecosystems(self):
        archive = make_zip({
            "workspace/python/requirements.txt": "requests==2.31.0\n",
            "workspace/web/package.json": json.dumps({"dependencies": {"lodash": "4.17.21"}}),
            "workspace/java/pom.xml": (
                "<project><dependencies><dependency><groupId>g</groupId>"
                "<artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>"
            ),
        })
        destination, root = self.extract(archive)
        self.assertEqual(root, destination)
        dependencies = parse_dependencies(str(root))
        self.assertEqual({item["ecosystem"] for item in dependencies}, {"PyPI", "npm", "Maven"})

    def test_coverage_notices_do_not_describe_incomplete_scans_as_clean(self):
        no_dependencies = _coverage_notice({"status": "NO_SUPPORTED_DEPENDENCIES"}, 0)
        all_failed = _coverage_notice({
            "status": "ALL_OSV_QUERIES_FAILED", "dependencies_detected": 2,
        }, 0)
        complete = _coverage_notice({
            "status": "COMPLETE", "dependencies_detected": 2,
            "successfully_queried_dependencies": 2,
        }, 0)
        self.assertEqual(no_dependencies[0], "warning")
        self.assertIn("not a clean scan", no_dependencies[1])
        self.assertEqual(all_failed[0], "error")
        self.assertIn("No vulnerability conclusion", all_failed[1])
        self.assertEqual(complete[0], "success")
        self.assertIn("returned no vulnerability findings", complete[1])
        unsupported = _coverage_notice({
            "status": "NO_SUPPORTED_DEPENDENCIES", "unsupported_manifests": 1,
        }, 0)
        self.assertIn("unsupported manifest", unsupported[1])


if __name__ == "__main__":
    unittest.main()
