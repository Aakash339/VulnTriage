import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents import reachability_agent
from agents.reachability_agent import check_reachability


class ReachabilityAgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative_path, contents):
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contents, bytes):
            path.write_bytes(contents)
        else:
            path.write_text(contents, encoding="utf-8")
        return path

    def check(self, *packages):
        return check_reachability(str(self.root), [{"package": p} for p in packages])

    def statuses(self, *packages):
        return {result["package"]: result for result in self.check(*packages)}

    def test_python_import_and_from_import(self):
        self.write("main.py", "import requests\nfrom flask.cli import main\n")
        result = self.statuses("requests", "flask")
        self.assertEqual(result["requests"]["status"], "USED")
        self.assertIn("main.py:1: import requests", result["requests"]["evidence"])
        self.assertEqual(result["flask"]["status"], "USED")
        self.assertIn("main.py:2: from flask.cli import main", result["flask"]["evidence"])

    def test_relative_python_import_is_not_external(self):
        self.write("pkg/mod.py", "from .requests import client\nfrom ..flask import app\n")
        self.assertEqual(self.statuses("requests", "flask")["requests"]["status"], "NOT_FOUND")
        self.assertEqual(self.statuses("flask")["flask"]["status"], "NOT_FOUND")

    def test_python_distribution_alias_mappings(self):
        self.write("aliases.py", "import bs4\nimport PIL.Image\nimport sklearn\nimport yaml\nimport cv2\nimport dateutil.parser\n")
        names = ("beautifulsoup4", "Pillow", "scikit-learn", "PyYAML", "opencv-python", "python-dateutil")
        results = self.statuses(*names)
        self.assertTrue(all(results[name]["status"] == "USED" for name in names))

    def test_javascript_es_side_effect_export_require_and_dynamic(self):
        self.write("app.js", "import lodash from 'lodash';\nimport 'left-pad';\nexport { x } from 'express/router';\nconst a = require('axios');\nconst b = import('chalk');\n")
        results = self.statuses("lodash", "left-pad", "express", "axios", "chalk")
        self.assertTrue(all(value["status"] == "USED" for value in results.values()))
        self.assertIn("app.js:1:", results["lodash"]["evidence"][0])

    def test_typescript_import_and_scoped_npm_package(self):
        self.write("src/app.tsx", "import React from 'react';\nimport { thing } from '@scope/pkg/subpath';\n")
        results = self.statuses("react", "@scope/pkg")
        self.assertTrue(all(value["status"] == "USED" for value in results.values()))
        self.assertTrue(any("@scope/pkg/subpath" in e for e in results["@scope/pkg"]["evidence"]))

    def test_ignored_directories(self):
        self.write("main.py", "print('clean source file')\n")
        for folder in (".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", "target"):
            self.write(f"{folder}/hidden.js", "import 'secret-package';\n")
        self.assertEqual(self.statuses("secret-package")["secret-package"]["status"], "NOT_FOUND")

    def test_not_found_and_empty_input(self):
        self.write("clean.py", "print('hello')\n")
        self.assertEqual(self.statuses("missing")["missing"]["status"], "NOT_FOUND")
        self.assertEqual(check_reachability(str(self.root), []), [])
        self.assertEqual(check_reachability(str(self.root), [None, {}, {"name": "x"}]), [])
        self.assertEqual(check_reachability(str(self.root), 42), [])

    def test_empty_project_or_no_supported_source_is_unknown(self):
        self.assertEqual(self.statuses("requests")["requests"]["status"], "UNKNOWN")
        self.write("README.md", "import requests\n")
        self.assertEqual(self.statuses("requests")["requests"]["status"], "UNKNOWN")
        self.write(".venv/hidden.py", "import requests\n")
        self.assertEqual(self.statuses("requests")["requests"]["status"], "UNKNOWN")

    def test_python_literal_dynamic_import_calls(self):
        self.write(
            "dynamic.py",
            'import importlib\n'
            'importlib.import_module("requests")\n'
            '__import__("flask")\n',
        )
        results = self.statuses("requests", "flask")
        self.assertEqual(results["requests"]["status"], "USED")
        self.assertEqual(results["flask"]["status"], "USED")
        self.assertTrue(any("dynamic.py:2: importlib.import_module(\"requests\")" in item
                            for item in results["requests"]["evidence"]))
        self.assertTrue(any("dynamic.py:3: __import__(\"flask\")" in item
                            for item in results["flask"]["evidence"]))

    def test_python_aliased_importlib_dynamic_import_calls(self):
        self.write(
            "aliased.py",
            'import importlib as loader\n'
            'loader.import_module("requests")\n'
            'from importlib import import_module as load\n'
            'load("flask")\n',
        )
        results = self.statuses("requests", "flask")
        self.assertEqual(results["requests"]["status"], "USED")
        self.assertEqual(results["flask"]["status"], "USED")
        self.assertTrue(any("aliased.py:2:" in item for item in results["requests"]["evidence"]))
        self.assertTrue(any("aliased.py:4:" in item for item in results["flask"]["evidence"]))

    def test_javascript_comments_and_ordinary_strings_are_not_import_evidence(self):
        self.write(
            "comments.js",
            '// import \'ghost-package\'\n'
            '/* require("ghost-package"); import("ghost-package"); */\n'
            'const example = "import \'ghost-package\'; require(\\"ghost-package\\")";\n'
            'const template = `import \'ghost-package\'`;\n'
            'import actual from "actual-package";\n',
        )
        results = self.statuses("ghost-package", "actual-package")
        self.assertEqual(results["ghost-package"]["status"], "NOT_FOUND")
        self.assertEqual(results["actual-package"]["status"], "USED")
        self.assertTrue(any("comments.js:5: import actual" in item
                            for item in results["actual-package"]["evidence"]))

    def test_unknown_missing_project_and_unreadable_encoding(self):
        missing = self.root / "does-not-exist"
        self.assertEqual(check_reachability(str(missing), [{"package": "x"}])[0]["status"], "UNKNOWN")
        self.write("bad.js", b"\xff\xfe")
        self.assertEqual(self.statuses("x")["x"]["status"], "UNKNOWN")

    def test_invalid_python_is_unknown_but_positive_evidence_survives(self):
        self.write("bad.py", "def invalid(:\n")
        self.write("good.py", "import requests\n")
        results = self.statuses("requests", "other")
        self.assertEqual(results["requests"]["status"], "USED")
        self.assertEqual(results["other"]["status"], "UNKNOWN")

    def test_duplicate_names_return_one_result(self):
        self.write("app.py", "import requests\n")
        results = check_reachability(str(self.root), [
            {"package": "requests"}, {"package": "Requests"}, {"package": "other"},
        ])
        self.assertEqual([item["package"] for item in results], ["requests", "other"])

    def test_java_regular_wildcard_and_static_imports_include_precise_evidence(self):
        self.write(
            "src/Main.java",
            "import com.google.common.collect.ImmutableList;\n"
            "import org.apache.commons.lang3.*;\n"
            "import static com.fasterxml.jackson.databind.ObjectMapper.builder;\n",
        )
        results = check_reachability(str(self.root), [
            {"package": "com.google.guava:guava", "ecosystem": "Maven"},
            {"package": "org.apache.commons:commons-lang3", "ecosystem": "Maven"},
            {"package": "com.fasterxml.jackson.core:jackson-databind", "ecosystem": "Maven"},
        ])
        by_package = {item["package"]: item for item in results}
        expected = {
            "com.google.guava:guava": "src/Main.java:1: import com.google.common.collect.ImmutableList;",
            "org.apache.commons:commons-lang3": "src/Main.java:2: import org.apache.commons.lang3.*;",
            "com.fasterxml.jackson.core:jackson-databind": "src/Main.java:3: import static com.fasterxml.jackson.databind.ObjectMapper.builder;",
        }
        for package, evidence in expected.items():
            with self.subTest(package=package):
                self.assertEqual(by_package[package]["status"], "USED")
                self.assertIn(evidence, by_package[package]["evidence"])

    def test_every_curated_maven_mapping_is_covered(self):
        for coordinate, prefixes in reachability_agent._MAVEN_PACKAGE_PREFIXES.items():
            with self.subTest(coordinate=coordinate):
                self.write("Mapped.java", f"import {prefixes[0]}.ExampleType;\n")
                result = check_reachability(str(self.root), [
                    {"package": coordinate, "ecosystem": "Maven"},
                ])[0]
                self.assertEqual(result["status"], "USED")

    def test_known_maven_mapping_without_import_is_not_found(self):
        self.write("Main.java", "package demo;\nclass Main {}\n")
        result = check_reachability(str(self.root), [
            {"package": "com.google.guava:guava", "ecosystem": "Maven"},
        ])[0]
        self.assertEqual(result["status"], "NOT_FOUND")
        self.assertEqual(result["evidence"], [])

    def test_java_package_prefix_requires_a_component_boundary(self):
        self.write("Main.java", "import com.google.commonish.collect.OtherType;\n")
        result = check_reachability(str(self.root), [
            {"package": "com.google.guava:guava", "ecosystem": "Maven"},
        ])[0]
        self.assertEqual(result["status"], "NOT_FOUND")

    def test_unmapped_and_ambiguous_maven_coordinates_are_unknown(self):
        self.write("Main.java", "import com.google.common.collect.ImmutableList;\n")
        unmapped = check_reachability(str(self.root), [
            {"package": "not.in.map:artifact", "ecosystem": "Maven"},
        ])[0]
        self.assertEqual(unmapped["status"], "UNKNOWN")

        with patch.dict(reachability_agent._MAVEN_PACKAGE_PREFIXES, {
            "com.other:guava-copy": ("com.google.common",),
        }):
            ambiguous = check_reachability(str(self.root), [
                {"package": "com.google.guava:guava", "ecosystem": "Maven"},
                {"package": "com.other:guava-copy", "ecosystem": "Maven"},
            ])
        self.assertEqual([item["status"] for item in ambiguous], ["UNKNOWN", "UNKNOWN"])

    def test_maven_reachability_is_unknown_without_java_source(self):
        self.write("main.py", "import requests\n")
        self.write("app.js", "import lodash from 'lodash';\n")
        results = check_reachability(str(self.root), [
            {"package": "requests", "ecosystem": "PyPI"},
            {"package": "lodash", "ecosystem": "npm"},
            {"package": "com.google.guava:guava", "ecosystem": "Maven"},
        ])
        by_package = {item["package"]: item for item in results}
        self.assertEqual(by_package["requests"]["status"], "USED")
        self.assertEqual(by_package["lodash"]["status"], "USED")
        self.assertEqual(by_package["com.google.guava:guava"]["status"], "UNKNOWN")

    def test_unsupported_java_import_syntax_is_unknown(self):
        self.write("Main.java", "import com.google.common..Broken;\n")
        result = check_reachability(str(self.root), [
            {"package": "com.google.guava:guava", "ecosystem": "Maven"},
        ])[0]
        self.assertEqual(result["status"], "UNKNOWN")

    def test_java_comments_strings_and_text_blocks_are_not_import_evidence(self):
        self.write(
            "Main.java",
            "// import com.google.common.collect.CommentType;\n"
            "/* import com.google.common.collect.BlockType; */\n"
            'String example = "import com.google.common.collect.StringType;";\n'
            'String text = """\nimport com.google.common.collect.TextBlockType;\n""";\n',
        )
        result = check_reachability(str(self.root), [
            {"package": "com.google.guava:guava", "ecosystem": "Maven"},
        ])[0]
        self.assertEqual(result["status"], "NOT_FOUND")
        self.assertEqual(result["evidence"], [])

    def test_java_scan_error_preserves_positive_evidence(self):
        self.write("broken.java", "/* unterminated comment\n")
        self.write("src/Good.java", "import com.google.common.collect.ImmutableList;\n")
        results = check_reachability(str(self.root), [
            {"package": "com.google.guava:guava", "ecosystem": "Maven"},
            {"package": "org.apache.commons:commons-lang3", "ecosystem": "Maven"},
        ])
        by_package = {item["package"]: item for item in results}
        self.assertEqual(by_package["com.google.guava:guava"]["status"], "USED")
        self.assertIn(
            "src/Good.java:1: import com.google.common.collect.ImmutableList;",
            by_package["com.google.guava:guava"]["evidence"],
        )
        self.assertEqual(by_package["org.apache.commons:commons-lang3"]["status"], "UNKNOWN")

    def test_mixed_python_npm_and_maven_and_duplicate_maven_records(self):
        self.write("main.py", "import requests\n")
        self.write("app.js", "import lodash from 'lodash';\n")
        self.write("Main.java", "import com.google.common.collect.ImmutableList;\n")
        results = check_reachability(str(self.root), [
            {"package": "requests", "ecosystem": "PyPI"},
            {"package": "lodash", "ecosystem": "npm"},
            {"package": "com.google.guava:guava", "ecosystem": "Maven"},
            {"package": "com.google.guava:guava", "ecosystem": "Maven"},
        ])
        by_package = {item["package"]: item for item in results}
        self.assertEqual(len(results), 3)
        self.assertEqual(by_package["requests"]["status"], "USED")
        self.assertEqual(by_package["lodash"]["status"], "USED")
        self.assertEqual(by_package["com.google.guava:guava"]["status"], "USED")

    def test_same_package_name_is_scoped_to_ecosystem_and_source_language(self):
        self.write("clean.py", "print('no import')\n")
        self.write("app.js", "import sharedpkg from 'sharedpkg';\n")
        results = check_reachability(str(self.root), [
            {"package": "sharedpkg", "ecosystem": "PyPI"},
            {"package": "sharedpkg", "ecosystem": "npm"},
        ])
        by_ecosystem = {item["ecosystem"]: item for item in results}
        self.assertEqual(by_ecosystem["PyPI"]["status"], "NOT_FOUND")
        self.assertEqual(by_ecosystem["npm"]["status"], "USED")

    def test_generated_java_source_does_not_create_reachability_evidence(self):
        self.write("Main.java", "class Main {}\n")
        self.write("target/generated-sources/Main.java", "import com.google.common.collect.ImmutableList;\n")
        result = check_reachability(str(self.root), [
            {"package": "com.google.guava:guava", "ecosystem": "Maven"},
        ])[0]
        self.assertEqual(result["status"], "NOT_FOUND")
        self.assertEqual(result["evidence"], [])


if __name__ == "__main__":
    unittest.main()
