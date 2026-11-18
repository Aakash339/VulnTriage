from agents.compatibility_agent import analyze_compatibility


def dependency(name="requests", version="2.30.0", ecosystem="PyPI", source_file="requirements.txt"):
    return {"name": name, "version": version, "ecosystem": ecosystem, "source_file": source_file}


def vulnerability(package="requests", version="2.30.0", ecosystem="PyPI", fixed=None, vuln_id="OSV-1"):
    return {
        "package": package,
        "ecosystem": ecosystem,
        "installed_version": version,
        "vulnerability_id": vuln_id,
        "fixed_versions": ["2.31.0"] if fixed is None else fixed,
    }


def reachability(package="requests", ecosystem="PyPI", status="USED", evidence=None):
    return {
        "package": package,
        "ecosystem": ecosystem,
        "status": status,
        "evidence": ["app.py:1: import requests"] if evidence is None else evidence,
    }


def assess(deps=None, vulns=None, reaches=None):
    return analyze_compatibility(
        [dependency()] if deps is None else deps,
        [vulnerability()] if vulns is None else vulns,
        [reachability()] if reaches is None else reaches,
    )


def test_matching_records_produce_review_required_with_evidence():
    result = assess()[0]

    assert result["package"] == "requests"
    assert result["ecosystem"] == "PyPI"
    assert result["installed_version"] == "2.30.0"
    assert result["candidate_fixed_versions"] == ["2.31.0"]
    assert result["assessment_status"] == "REVIEW_REQUIRED"
    assert any("requirements.txt" in item for item in result["evidence_used"])
    assert any("OSV fixed version 2.31.0" in item for item in result["evidence_used"])
    assert any("app.py:1" in item for item in result["evidence_used"])
    assert "unverified" in result["explanation"]


def test_package_matching_is_ecosystem_aware():
    result = assess(
        deps=[dependency("common", "1.0", "npm")],
        vulns=[vulnerability("common", "1.0", "PyPI", ["2.0"])],
        reaches=[reachability("common", "npm")],
    )[0]

    assert result["assessment_status"] == "NOT_ASSESSED"
    assert result["candidate_fixed_versions"] == ["2.0"]
    assert "No dependency matched both ecosystem and package identity" in result["explanation"]
    assert "No matching reachability record" in result["explanation"]


def test_python_distribution_identity_uses_python_normalization():
    result = assess(
        deps=[dependency("my_pkg", "1.0", "PyPI")],
        vulns=[vulnerability("my.pkg", "1.0", "pypi", ["2.0"])],
        reaches=[reachability("my-pkg", "PyPI")],
    )[0]

    assert result["assessment_status"] == "REVIEW_REQUIRED"


def test_valid_python_epoch_version_is_preserved():
    result = assess(
        deps=[dependency("requests", "1!2.0", "PyPI")],
        vulns=[vulnerability("requests", "1!2.0", "PyPI", ["1!3.0"])],
    )[0]

    assert result["assessment_status"] == "REVIEW_REQUIRED"
    assert result["installed_version"] == "1!2.0"


def test_maven_coordinates_are_matched_exactly():
    result = assess(
        deps=[dependency("org.example:my-artifact", "1.0.Final", "Maven")],
        vulns=[vulnerability("org.example:my_artifact", "1.0.Final", "Maven", ["2.0"])],
        reaches=[reachability("org.example:my_artifact", "Maven")],
    )[0]

    assert result["assessment_status"] == "NOT_ASSESSED"
    assert "No dependency matched both ecosystem and package identity" in result["explanation"]


def test_exact_maven_coordinate_and_non_semver_version_can_be_reviewed():
    result = assess(
        deps=[dependency("org.example:artifact", "1.0.Final", "Maven", "pom.xml")],
        vulns=[vulnerability("org.example:artifact", "1.0.Final", "Maven", ["2.0.Final"])],
        reaches=[reachability("org.example:artifact", "Maven", "UNKNOWN", [])],
    )[0]

    assert result["assessment_status"] == "REVIEW_REQUIRED"
    assert result["installed_version"] == "1.0.Final"
    assert result["candidate_fixed_versions"] == ["2.0.Final"]
    assert any("pom.xml" in item for item in result["evidence_used"])


def test_only_osv_supplied_fixed_versions_are_candidates():
    result = assess(vulns=[vulnerability(fixed=["2.0", "2.0", "${next.version}"])])[0]

    assert result["candidate_fixed_versions"] == ["2.0"]
    assert all("3.0" not in candidate for candidate in result["candidate_fixed_versions"])
    assert "not a usable literal" in result["explanation"]


def test_multiple_fixed_versions_require_selection_and_testing():
    result = assess(vulns=[vulnerability(fixed=["2.0", "2.1"])])[0]

    assert result["assessment_status"] == "REVIEW_REQUIRED"
    assert result["candidate_fixed_versions"] == ["2.0", "2.1"]
    assert "Multiple OSV fixed versions are available" in result["explanation"]


def test_missing_or_unresolved_dependency_version_is_not_assessed():
    for version in ("", "${version}", ">=1.0", "1.+"):
        result = assess(
            deps=[dependency(version=version)],
            vulns=[vulnerability(version="1.0", fixed=["2.0"])],
        )[0]
        assert result["assessment_status"] == "NOT_ASSESSED"
        assert result["installed_version"] == "1.0"
        assert "missing or non-literal version" in result["explanation"]


def test_malformed_npm_versions_are_not_treated_as_resolved():
    result = assess(
        deps=[dependency("left-pad", "not-a-version", "npm")],
        vulns=[vulnerability("left-pad", "not-a-version", "npm", ["2.0.0"])],
        reaches=[reachability("left-pad", "npm")],
    )[0]

    assert result["assessment_status"] == "NOT_ASSESSED"
    assert result["installed_version"] == ""


def test_conflicting_dependency_and_osv_versions_are_not_assessed():
    result = assess(
        deps=[dependency(version="1.0"), dependency(version="1.1", source_file="pom.xml")],
        vulns=[vulnerability(version="1.1", fixed=["2.0"])],
    )[0]

    assert result["assessment_status"] == "NOT_ASSESSED"
    assert result["installed_version"] == ""
    assert "ambiguous or inconsistent" in result["explanation"]


def test_missing_dependency_or_vulnerability_version_is_conservative():
    cases = [
        ([dependency(version="1.0")], [vulnerability(version="", fixed=["2.0"])]),
        ([], [vulnerability(version="1.0", fixed=["2.0"])]),
    ]
    for dependencies, vulnerabilities in cases:
        result = assess(deps=dependencies, vulns=vulnerabilities)[0]
        assert result["assessment_status"] == "NOT_ASSESSED"


def test_no_osv_fix_is_not_assessed_and_candidate_list_is_empty():
    result = assess(vulns=[vulnerability(fixed=[])])[0]

    assert result["assessment_status"] == "NOT_ASSESSED"
    assert result["candidate_fixed_versions"] == []
    assert "No usable fixed-version candidate" in result["explanation"]


def test_ambiguous_reachability_is_preserved_as_evidence_not_a_compatibility_claim():
    result = assess(reaches=[
        reachability(status="USED"),
        reachability(status="UNKNOWN", evidence=[]),
    ])[0]

    assert result["assessment_status"] == "REVIEW_REQUIRED"
    assert "Reachability status: USED" in result["evidence_used"]
    assert "Reachability status: UNKNOWN" in result["evidence_used"]
    assert "unverified" in result["explanation"]


def test_malformed_and_empty_inputs_are_safe():
    assert analyze_compatibility(None, None, None) == []
    assert analyze_compatibility([None], [None, {}], [None]) == []

