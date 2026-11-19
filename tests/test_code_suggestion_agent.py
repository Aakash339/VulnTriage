from agents.code_suggestion_agent import generate_code_suggestions


def api_impact(package="requests", ecosystem="PyPI", usages=None, candidates=None):
    return {
        "package": package,
        "ecosystem": ecosystem,
        "installed_version": "2.30.0",
        "candidate_fixed_versions": ["2.31.0"] if candidates is None else candidates,
        "status": "POTENTIAL_IMPACT",
        "usages": [{
            "source_file": "app.py",
            "line_number": 2,
            "reference": "req.get",
            "statement": "response = req.get('/api')",
            "kind": "API_CALL",
        }] if usages is None else usages,
    }


def compatibility(package="requests", ecosystem="PyPI", version="2.30.0", candidates=None):
    return {
        "package": package,
        "ecosystem": ecosystem,
        "installed_version": version,
        "candidate_fixed_versions": ["2.31.0"] if candidates is None else candidates,
        "assessment_status": "REVIEW_REQUIRED",
    }


def test_valid_source_evidence_generates_no_fabricated_replacement(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("import requests as req\nresponse = req.get('/api')\n", encoding="utf-8")

    results = generate_code_suggestions(
        str(tmp_path),
        [api_impact()],
        [compatibility()],
    )

    assert len(results) == 1
    suggestion = results[0]
    assert suggestion["package"] == "requests"
    assert suggestion["ecosystem"] == "PyPI"
    assert suggestion["source_file"] == "app.py"
    assert suggestion["line_number"] == 2
    assert suggestion["detected_reference"] == "req.get"
    assert suggestion["current_code_snippet"] == "response = req.get('/api')"
    assert suggestion["candidate_fixed_versions"] == ["2.31.0"]
    assert suggestion["proposed_code_snippet"] is None
    assert suggestion["guidance_type"] == "ILLUSTRATIVE"
    assert suggestion["confidence"] == "LOW"
    assert suggestion["review_status"] == "NO_SAFE_SUGGESTION"
    assert "no verified replacement API" in suggestion["explanation"]


def test_missing_alternative_is_explicit_and_not_inferred_from_fixed_version(tmp_path):
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    results = generate_code_suggestions(
        str(tmp_path), [api_impact()], [compatibility(candidates=["2.31.0"])],
    )

    assert results[0]["proposed_code_snippet"] is None
    assert results[0]["review_status"] == "NO_SAFE_SUGGESTION"
    assert "no verified replacement API" in results[0]["explanation"]
    assert "OSV-derived candidate" in results[0]["explanation"]


def test_ambiguous_compatibility_matches_are_not_trusted(tmp_path):
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    results = generate_code_suggestions(
        str(tmp_path),
        [api_impact()],
        [compatibility(version="2.30.0", candidates=["2.31.0"]),
         compatibility(version="2.29.0", candidates=["3.0.0"])],
    )

    assert len(results) == 1
    assert results[0]["review_status"] == "NO_SAFE_SUGGESTION"
    assert results[0]["candidate_fixed_versions"] == []
    assert "candidate provenance is ambiguous" in results[0]["explanation"]


def test_missing_source_file_uses_scan_snapshot_with_caveat(tmp_path):
    results = generate_code_suggestions(
        str(tmp_path), [api_impact()], [compatibility()],
    )

    assert len(results) == 1
    assert results[0]["current_code_snippet"] == "response = req.get('/api')"
    assert "scan-time evidence" in results[0]["explanation"]
    assert results[0]["proposed_code_snippet"] is None


def test_unsupported_language_is_reported_without_code_edit(tmp_path):
    (tmp_path / "Main.java").write_text("package app;\n", encoding="utf-8")
    usage = [{
        "source_file": "Main.java", "line_number": 1, "reference": "org.example.Client",
        "statement": "import org.example.Client;", "kind": "IMPORT",
    }]
    results = generate_code_suggestions(
        str(tmp_path),
        [api_impact("org.example:client", "Maven", usage, ["2.0"])],
        [compatibility("org.example:client", "Maven", "1.0", ["2.0"])],
    )

    assert len(results) == 1
    assert results[0]["review_status"] == "NO_SAFE_SUGGESTION"
    assert results[0]["current_code_snippet"] == "import org.example.Client;"
    assert "source language is not supported" in results[0]["explanation"]


def test_mismatched_ecosystem_records_do_not_provide_candidates(tmp_path):
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    results = generate_code_suggestions(
        str(tmp_path),
        [api_impact("requests", "PyPI", candidates=[])],
        [compatibility("requests", "npm", candidates=["9.0.0"])],
    )

    assert results[0]["candidate_fixed_versions"] == []
    assert "No compatibility assessment matched" in results[0]["explanation"]


def test_inconsistent_installed_versions_suppress_candidate_association(tmp_path):
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    impact = api_impact()
    impact["installed_version"] = "2.30.0"
    results = generate_code_suggestions(
        str(tmp_path), [impact], [compatibility(version="2.29.0", candidates=["2.31.0"])],
    )

    assert results[0]["candidate_fixed_versions"] == []
    assert "disagree on the installed version" in results[0]["explanation"]


def test_inconsistent_fixed_candidate_records_are_not_combined(tmp_path):
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    results = generate_code_suggestions(
        str(tmp_path),
        [api_impact(candidates=["2.31.0"])],
        [compatibility(candidates=["3.0.0"])],
    )

    assert results[0]["candidate_fixed_versions"] == []
    assert "disagree on fixed-version candidates" in results[0]["explanation"]


def test_wrong_source_extension_is_not_read_as_supported_language(tmp_path):
    (tmp_path / "app.js").write_text("import requests;\n", encoding="utf-8")
    impact = api_impact()
    impact["usages"][0]["source_file"] = "app.js"
    results = generate_code_suggestions(
        str(tmp_path), [impact], [compatibility()],
    )

    assert results[0]["current_code_snippet"] == "response = req.get('/api')"
    assert "source language is not supported" in results[0]["explanation"]


def test_malformed_impact_records_are_skipped_safely(tmp_path):
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    malformed = [
        None,
        {},
        {"package": "requests", "ecosystem": "PyPI", "usages": "not a list"},
        {"package": "requests", "ecosystem": "PyPI", "usages": [{"source_file": "../outside.py", "line_number": 1}]},
    ]
    assert generate_code_suggestions(str(tmp_path), malformed, [compatibility()]) == []
    assert generate_code_suggestions(str(tmp_path), None, None) == []

