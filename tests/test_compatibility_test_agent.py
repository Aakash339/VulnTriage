import json
import shutil
import subprocess

from agents import compatibility_test_agent as agent
from agents.compatibility_test_agent import run_compatibility_tests


def assessment(package="demo", ecosystem="PyPI", current="1.0", candidates=None):
    return {
        "package": package,
        "ecosystem": ecosystem,
        "installed_version": current,
        "candidate_fixed_versions": ["2.0"] if candidates is None else candidates,
        "assessment_status": "REVIEW_REQUIRED",
    }


def suggestion(package="demo", ecosystem="PyPI", source="app.py", target="2.0", manifest="requirements.txt"):
    return {
        "package": package,
        "ecosystem": ecosystem,
        "source_file": source,
        "line_number": 1,
        "review_status": "REVIEW_REQUIRED",
        "proposed_dependency_change": {
            "package": package,
            "ecosystem": ecosystem,
            "from_version": "1.0",
            "to_version": target,
            "manifest_file": manifest,
        },
    }


def test_successful_static_check_uses_isolated_copy_and_cleans_up(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    original_manifest = tmp_path / "requirements.txt"
    original_manifest.write_text("demo==1.0\n", encoding="utf-8")
    observed = {}

    def fake_check(command, workspace):
        observed["command"] = command
        observed["workspace"] = workspace
        observed["cwd"] = str(workspace.resolve())
        observed["manifest"] = (workspace / "requirements.txt").read_text(encoding="utf-8")
        observed["source_exists"] = (workspace / "app.py").is_file()
        return subprocess.CompletedProcess(command, 0, "syntax ok", "")

    monkeypatch.setattr(agent, "_run_static_check", fake_check)
    result = run_compatibility_tests(
        str(tmp_path), [assessment()], [suggestion()],
    )[0]

    assert result["status"] == "PASSED"
    assert result["test_command"] == observed["command"]
    assert observed["cwd"] != str(tmp_path.resolve())
    assert observed["manifest"] == "demo==2.0\n"
    assert observed["source_exists"]
    assert not observed["workspace"].exists()
    assert original_manifest.read_text(encoding="utf-8") == "demo==1.0\n"
    assert result["tested_dependency_changes"] == [{
        "package": "demo", "ecosystem": "PyPI", "from_version": "1.0",
        "to_version": "2.0", "manifest_file": "requirements.txt",
    }]


def test_static_python_syntax_failure_is_reported(tmp_path):
    (tmp_path / "app.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")

    result = run_compatibility_tests(str(tmp_path), [assessment()], [suggestion()])[0]

    assert result["status"] == "FAILED"
    assert result["exit_code"] != 0
    assert result["test_command"][1:4] == ["-I", "-m", "py_compile"]
    assert result["stderr"] or result["stdout"]


def test_builtin_static_python_check_passes_without_running_source(tmp_path):
    (tmp_path / "app.py").write_text("raise RuntimeError('must not execute')\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")

    result = run_compatibility_tests(str(tmp_path), [assessment()], [suggestion()])[0]

    # py_compile parses the module but must not execute its top-level statement.
    assert result["status"] == "PASSED"
    assert result["exit_code"] == 0


def test_timeout_is_failed_and_temporary_workspace_is_cleaned(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    observed = {}

    def timeout(command, workspace):
        observed["workspace"] = workspace
        observed["cwd"] = str(workspace.resolve())
        raise subprocess.TimeoutExpired(command, timeout=agent.COMMAND_TIMEOUT_SECONDS,
                                        output="partial stdout", stderr="partial stderr")

    monkeypatch.setattr(agent, "_run_static_check", timeout)
    result = run_compatibility_tests(str(tmp_path), [assessment()], [suggestion()])[0]

    assert result["status"] == "FAILED"
    assert result["exit_code"] is None
    assert "timeout" in result["reason"]
    assert result["stdout"] == "partial stdout"
    assert result["stderr"] == "partial stderr"
    assert observed["cwd"] != str(tmp_path.resolve())
    assert not observed["workspace"].exists()


def test_missing_explicit_proposal_returns_not_run(tmp_path):
    result = run_compatibility_tests(
        str(tmp_path), [assessment()], [{"package": "demo", "ecosystem": "PyPI", "usages": []}],
    )[0]

    assert result["status"] == "NOT_RUN"
    assert "No explicit proposed dependency change" in result["reason"]
    assert result["test_command"] is None


def test_unselected_or_unmatched_candidate_is_not_applied(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    result = run_compatibility_tests(
        str(tmp_path), [assessment(candidates=["2.0", "3.0"])], [suggestion(target="3.1")],
    )[0]

    assert result["status"] == "NOT_RUN"
    assert "not an exact fixed-version candidate" in result["reason"]
    assert (tmp_path / "requirements.txt").read_text(encoding="utf-8") == "demo==1.0\n"


def test_ambiguous_compatibility_identity_returns_not_run(tmp_path):
    result = run_compatibility_tests(
        str(tmp_path), [assessment(), assessment(candidates=["3.0"])], [suggestion()],
    )[0]

    assert result["status"] == "NOT_RUN"
    assert "Multiple compatibility assessments" in result["reason"]


def test_path_traversal_and_absolute_paths_are_rejected(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    unsafe_source = suggestion(source="..\\outside.py")
    unsafe_manifest = suggestion(manifest=str(tmp_path / "requirements.txt"))

    source_result = run_compatibility_tests(str(tmp_path), [assessment()], [unsafe_source])[0]
    manifest_result = run_compatibility_tests(str(tmp_path), [assessment()], [unsafe_manifest])[0]

    assert source_result["status"] == "NOT_RUN"
    assert "traversal" in source_result["reason"]
    assert manifest_result["status"] == "NOT_RUN"
    assert "absolute" in manifest_result["reason"]


def test_symlink_inputs_are_rejected_when_supported_by_platform(tmp_path):
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    outside = tmp_path.parent / "outside-test-source.py"
    outside.write_text("value = 1\n", encoding="utf-8")
    link = tmp_path / "linked.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        outside.unlink(missing_ok=True)
        return
    try:
        result = run_compatibility_tests(
            str(tmp_path), [assessment()], [suggestion(source="linked.py")],
        )[0]
        assert result["status"] == "NOT_RUN"
        assert "Symlink" in result["reason"]
    finally:
        outside.unlink(missing_ok=True)


def test_unsupported_test_configuration_returns_not_run(tmp_path):
    (tmp_path / "app.ts").write_text("const value: number = 1;\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    result = run_compatibility_tests(
        str(tmp_path), [assessment()], [suggestion(source="app.ts")],
    )[0]

    assert result["status"] == "NOT_RUN"
    assert "No safe built-in static test command" in result["reason"]


def test_npm_proposal_is_changed_only_in_workspace_and_uses_node_check_when_available(tmp_path, monkeypatch):
    (tmp_path / "app.js").write_text("const value = 1;\n", encoding="utf-8")
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies":{"demo":"1.0.0"}}', encoding="utf-8")
    proposal = suggestion("demo", "npm", "app.js", "2.0.0", "package.json")
    proposal["proposed_dependency_change"]["from_version"] = "1.0.0"
    result = run_compatibility_tests(
        str(tmp_path), [assessment("demo", "npm", "1.0.0", ["2.0.0"])], [proposal],
    )[0]

    if shutil.which("node"):
        assert result["status"] == "PASSED"
        assert result["test_command"][1] == "--check"
    else:
        assert result["status"] == "NOT_RUN"
    assert json.loads(manifest.read_text(encoding="utf-8"))["dependencies"]["demo"] == "1.0.0"


def test_project_provided_commands_are_never_used(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    proposed = suggestion()
    proposed["test_command"] = ["powershell", "-Command", "Write-Host unsafe"]
    observed = {}

    def fake_check(command, workspace):
        observed["command"] = command
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(agent, "_run_static_check", fake_check)
    result = run_compatibility_tests(str(tmp_path), [assessment()], [proposed])[0]

    assert result["status"] == "PASSED"
    assert observed["command"][1:4] == ["-I", "-m", "py_compile"]

