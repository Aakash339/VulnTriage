from pathlib import Path

from agents.api_impact_agent import analyze_api_impact


def dependency(name, version, ecosystem, source_file="requirements.txt"):
    return {"name": name, "version": version, "ecosystem": ecosystem, "source_file": source_file}


def compatibility(package, version, ecosystem, candidates=None, status="REVIEW_REQUIRED"):
    return {
        "package": package,
        "ecosystem": ecosystem,
        "installed_version": version,
        "candidate_fixed_versions": ["2.0.0"] if candidates is None else candidates,
        "assessment_status": status,
    }


def run(root: Path, deps, assessments=None):
    return analyze_api_impact(str(root), deps, assessments or [])


def test_python_import_and_api_call_report_precise_evidence(tmp_path):
    (tmp_path / "app.py").write_text(
        "import requests as req\nresponse = req.get('https://example.test')\n",
        encoding="utf-8",
    )
    result = run(
        tmp_path,
        [dependency("requests", "2.30.0", "PyPI")],
        [compatibility("requests", "2.30.0", "PyPI", ["2.31.0"])],
    )[0]

    assert result["status"] == "POTENTIAL_IMPACT"
    assert result["candidate_fixed_versions"] == ["2.31.0"]
    assert any(use["source_file"] == "app.py" and use["line_number"] == 1 and use["kind"] == "IMPORT"
               for use in result["usages"])
    assert any(use["line_number"] == 2 and use["reference"] == "req.get" and use["kind"] == "API_CALL"
               for use in result["usages"])
    assert any("requirements.txt" in item for item in result["evidence"])
    assert any("fixed-version candidate: 2.31.0" in item for item in result["evidence"])
    assert "impact is unverified" in result["explanation"]


def test_python_from_import_alias_is_reported_as_api_call(tmp_path):
    (tmp_path / "client.py").write_text(
        "from requests import get as fetch\nfetch('https://example.test')\n",
        encoding="utf-8",
    )
    result = run(
        tmp_path,
        [dependency("requests", "2.30.0", "PyPI")],
        [compatibility("requests", "2.30.0", "PyPI")],
    )[0]

    assert result["status"] == "POTENTIAL_IMPACT"
    assert any(use["reference"] == "fetch" and use["line_number"] == 2 for use in result["usages"])


def test_python_literal_dynamic_import_is_detected(tmp_path):
    (tmp_path / "loader.py").write_text(
        "from importlib import import_module as load\nload('requests')\n",
        encoding="utf-8",
    )
    result = run(
        tmp_path,
        [dependency("requests", "2.30.0", "PyPI")],
        [compatibility("requests", "2.30.0", "PyPI")],
    )[0]

    assert result["status"] == "POTENTIAL_IMPACT"
    assert any(use["kind"] == "DYNAMIC_IMPORT" and use["line_number"] == 2 for use in result["usages"])


def test_javascript_and_typescript_imports_and_alias_references(tmp_path):
    (tmp_path / "app.js").write_text(
        "import axios from 'axios';\naxios.get('/api');\n",
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.ts").write_text(
        "import { request as send } from 'axios';\nsend('/api');\n",
        encoding="utf-8",
    )
    result = run(
        tmp_path,
        [dependency("axios", "1.6.0", "npm", "package-lock.json")],
        [compatibility("axios", "1.6.0", "npm", ["1.7.0"])],
    )[0]

    assert result["status"] == "POTENTIAL_IMPACT"
    assert {use["source_file"] for use in result["usages"]} == {"app.js", "src/app.ts"}
    assert any(use["reference"] == "axios.get" and use["line_number"] == 2 for use in result["usages"])
    assert any(use["reference"] == "send" and use["line_number"] == 2 for use in result["usages"])


def test_scoped_npm_import_require_and_dynamic_import(tmp_path):
    (tmp_path / "app.tsx").write_text(
        "import { run as runClient } from '@scope/client/api';\n"
        "runClient();\n"
        "const other = require('@scope/client');\n"
        "other.run();\n"
        "const lazy = import('@scope/client');\n"
        "lazy.default();\n",
        encoding="utf-8",
    )
    result = run(
        tmp_path,
        [dependency("@scope/client", "1.2.0", "npm", "package-lock.json")],
        [compatibility("@scope/client", "1.2.0", "npm", ["1.3.0"])],
    )[0]

    assert result["status"] == "POTENTIAL_IMPACT"
    assert any(use["reference"] == "@scope/client/api" for use in result["usages"])
    assert any(use["reference"] == "other.run" for use in result["usages"])
    assert any("package-lock.json" in item for item in result["evidence"])


def test_javascript_comments_and_strings_do_not_create_import_evidence(tmp_path):
    (tmp_path / "main.js").write_text(
        "// import 'axios'\n"
        "/* require('axios'); */\n"
        "const sample = \"import('axios') and require('axios')\";\n"
        "console.log(sample);\n",
        encoding="utf-8",
    )
    result = run(
        tmp_path,
        [dependency("axios", "1.6.0", "npm")],
        [compatibility("axios", "1.6.0", "npm")],
    )[0]

    assert result["status"] == "NO_KNOWN_IMPACT"
    assert result["usages"] == []


def test_ambiguous_python_import_root_is_not_assigned_to_one_package(tmp_path):
    (tmp_path / "app.py").write_text("import PIL.Image\n", encoding="utf-8")
    deps = [dependency("Pillow", "10.0.0", "PyPI"), dependency("pil", "1.0.0", "PyPI")]
    assessments = [
        compatibility("Pillow", "10.0.0", "PyPI"),
        compatibility("pil", "1.0.0", "PyPI"),
    ]

    results = run(tmp_path, deps, assessments)

    assert len(results) == 2
    assert all(item["status"] == "NOT_ASSESSED" for item in results)
    assert all("ownership is ambiguous" in item["explanation"] for item in results)
    assert all(any("app.py:1" in evidence for evidence in item["evidence"]) for item in results)


def test_missing_compatibility_candidate_keeps_usage_but_is_not_assessed(tmp_path):
    (tmp_path / "main.py").write_text("import requests\n", encoding="utf-8")
    result = run(
        tmp_path,
        [dependency("requests", "2.30.0", "PyPI")],
        [compatibility("requests", "2.30.0", "PyPI", [], "NOT_ASSESSED")],
    )[0]

    assert result["status"] == "NOT_ASSESSED"
    assert result["usages"]
    assert "No matching OSV fixed-version candidate" in result["explanation"]


def test_no_detected_usage_is_no_known_impact_with_explicit_limits(tmp_path):
    (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")
    result = run(
        tmp_path,
        [dependency("requests", "2.30.0", "PyPI")],
        [compatibility("requests", "2.30.0", "PyPI")],
    )[0]

    assert result["status"] == "NO_KNOWN_IMPACT"
    assert "does not rule out dynamic" in result["explanation"]
    assert "remains unverified" in result["explanation"]


def test_malformed_python_and_javascript_are_not_reported_as_no_impact(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "broken.js").write_text("const lib = require('requests);\n", encoding="utf-8")
    results = run(
        tmp_path,
        [dependency("requests", "2.30.0", "PyPI"), dependency("axios", "1.6.0", "npm")],
        [compatibility("requests", "2.30.0", "PyPI"), compatibility("axios", "1.6.0", "npm")],
    )

    assert {item["package"]: item["status"] for item in results} == {
        "requests": "NOT_ASSESSED",
        "axios": "NOT_ASSESSED",
    }
    assert all("could not be scanned reliably" in item["explanation"] for item in results)


def test_obviously_invalid_javascript_declaration_is_not_a_clean_scan(tmp_path):
    (tmp_path / "broken.js").write_text("const = 1;\n", encoding="utf-8")
    result = run(
        tmp_path,
        [dependency("axios", "1.6.0", "npm")],
        [compatibility("axios", "1.6.0", "npm")],
    )[0]

    assert result["status"] == "NOT_ASSESSED"
    assert "could not be scanned reliably" in result["explanation"]


def test_unsupported_java_only_source_is_not_assessed(tmp_path):
    (tmp_path / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    result = run(
        tmp_path,
        [dependency("org.example:lib", "1.0", "Maven", "pom.xml")],
        [compatibility("org.example:lib", "1.0", "Maven", ["2.0"])],
    )[0]

    assert result["status"] == "NOT_ASSESSED"
    assert "currently scans Python and JavaScript/TypeScript only" in result["explanation"]


def test_mismatched_ecosystem_does_not_supply_candidates(tmp_path):
    (tmp_path / "main.py").write_text("import requests\n", encoding="utf-8")
    result = run(
        tmp_path,
        [dependency("requests", "2.30.0", "PyPI")],
        [compatibility("requests", "2.30.0", "npm", ["3.0.0"])],
    )[0]

    assert result["status"] == "NOT_ASSESSED"
    assert result["candidate_fixed_versions"] == []
    assert "No compatibility assessment matched both ecosystem and package identity" in result["explanation"]


def test_duplicate_dependency_version_records_are_consolidated(tmp_path):
    (tmp_path / "main.py").write_text("import requests\n", encoding="utf-8")
    result = run(
        tmp_path,
        [dependency("requests", "2.30.0", "PyPI"), dependency("Requests", "2.30.0", "pypi", "constraints.txt")],
        [compatibility("requests", "2.30.0", "PyPI")],
    )

    assert len(result) == 1
    assert result[0]["status"] == "POTENTIAL_IMPACT"

