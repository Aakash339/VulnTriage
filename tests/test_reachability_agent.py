import tempfile
import unittest
from pathlib import Path

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
        for folder in (".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist"):
            self.write(f"{folder}/hidden.js", "import 'secret-package';\n")
        self.assertEqual(self.statuses("secret-package")["secret-package"]["status"], "NOT_FOUND")

    def test_not_found_and_empty_input(self):
        self.write("clean.py", "print('hello')\n")
        self.assertEqual(self.statuses("missing")["missing"]["status"], "NOT_FOUND")
        self.assertEqual(check_reachability(str(self.root), []), [])
        self.assertEqual(check_reachability(str(self.root), [None, {}, {"name": "x"}]), [])
        self.assertEqual(check_reachability(str(self.root), 42), [])

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


if __name__ == "__main__":
    unittest.main()
