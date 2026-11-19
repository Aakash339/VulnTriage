"""Run narrowly allowlisted, static checks for explicit upgrade proposals.

This agent never runs project tests or application code. It copies only the
referenced source file and the selected manifest to a temporary workspace,
applies a dependency edit there, then runs a fixed syntax-check command:
Python ``py_compile`` or Node ``--check`` for plain JavaScript. Unsupported
test setups are reported as ``NOT_RUN``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Any


COMMAND_TIMEOUT_SECONDS = 8
MAX_COPIED_FILE_BYTES = 5 * 1024 * 1024
_PACKAGE_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_PYTHON_PIN = re.compile(
    r"^(?P<prefix>\s*)(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<operator>\s*==\s*)"
    r"(?P<version>[^\s;#]+)(?P<suffix>\s*(?:;[^#]*)?(?:#.*)?)$"
)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _ecosystem(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    return {"pypi": "PyPI", "npm": "npm", "maven": "Maven"}.get(value.casefold(), value)


def _identity(record: dict[str, Any], package_field: str) -> tuple[str, str] | None:
    ecosystem = _ecosystem(record.get("ecosystem"))
    package = _text(record.get(package_field))
    if not ecosystem or not package:
        return None
    if ecosystem == "Maven":
        normalized = package
    elif ecosystem == "PyPI":
        normalized = re.sub(r"[-_.]+", "-", package).casefold()
    else:
        normalized = package.casefold()
    return ecosystem, normalized


def _records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [record for record in value if isinstance(record, dict)]


def _safe_literal_version(value: str, ecosystem: str) -> bool:
    if not value or any(character.isspace() for character in value):
        return False
    if any(token in value for token in ("$", "<", ">", "=", "~", "^", "*", ",", "|")):
        return False
    if ecosystem == "npm":
        return bool(re.fullmatch(
            r"^v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
            r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
            r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
            value,
        ))
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!_+-]*", value))


def _result(package: str, ecosystem: str, status: str, command: list[str] | None,
            changes: list[dict[str, str]], reason: str, stdout: str = "", stderr: str = "",
            exit_code: int | None = None) -> dict[str, Any]:
    output_limit = 4000
    return {
        "package": package,
        "ecosystem": ecosystem,
        "status": status,
        "test_command": command,
        "tested_dependency_changes": changes,
        "stdout": stdout[:output_limit],
        "stderr": stderr[:output_limit],
        "exit_code": exit_code,
        "reason": reason,
        "limitations": "Passing static syntax checks does not prove runtime compatibility or security.",
    }


def _safe_project_file(project_path: str, relative_path: str) -> tuple[Path | None, str | None]:
    """Resolve a regular file under the project root and reject symlink paths."""
    try:
        original_root = Path(project_path)
        if original_root.is_symlink() or not original_root.is_dir():
            return None, "Project directory is missing or is a symlink."
        root = original_root.resolve(strict=True)

        # Path() follows the current platform; PureWindowsPath catches drive
        # prefixes even when a project is inspected on a non-Windows host.
        posix = relative_path.replace("\\", "/")
        windows = PureWindowsPath(relative_path)
        relative = Path(posix)
        if (not relative_path or relative.is_absolute() or windows.is_absolute()
                or windows.drive or any(part == ".." for part in relative.parts)):
            return None, "Input path is absolute, drive-prefixed, or contains traversal."

        candidate = root
        for part in relative.parts:
            if part in {"", "."}:
                continue
            candidate = candidate / part
            if candidate.is_symlink():
                return None, "Symlink paths are not allowed in compatibility test inputs."
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(root):
            return None, "Input file resolves outside the project directory."
        if not resolved.is_file():
            return None, "Input path is not a regular file."
        if resolved.stat().st_size > MAX_COPIED_FILE_BYTES:
            return None, "Input file exceeds the safe copy-size limit."
        return resolved, None
    except (OSError, RuntimeError, TypeError, ValueError):
        return None, "Input file is missing or could not be safely resolved."


def _manifest_destination(manifest_file: str, ecosystem: str, workspace: Path) -> Path | None:
    relative = Path(manifest_file.replace("\\", "/"))
    if ecosystem == "PyPI" and relative.name.casefold().startswith("requirements") and relative.suffix.casefold() == ".txt":
        return workspace / relative
    if ecosystem == "npm" and relative.name.casefold() == "package.json":
        return workspace / relative
    return None


def _apply_python_pin(manifest: Path, package: str, from_version: str, to_version: str) -> tuple[bool, str]:
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines(keepends=True)
    except (OSError, UnicodeError):
        return False, "Requirements manifest could not be read as UTF-8."
    wanted = re.sub(r"[-_.]+", "-", package).casefold()
    matches: list[int] = []
    for index, line in enumerate(lines):
        match = _PYTHON_PIN.match(line.rstrip("\r\n"))
        if match and re.sub(r"[-_.]+", "-", match.group("name")).casefold() == wanted:
            matches.append(index)
    if len(matches) != 1:
        return False, "Expected exactly one direct, exact-pinned package entry in the requirements file."
    index = matches[0]
    match = _PYTHON_PIN.match(lines[index].rstrip("\r\n"))
    if match is None or match.group("version") != from_version:
        return False, "Requirements pin does not match the proposed current version."
    ending = "\r\n" if lines[index].endswith("\r\n") else "\n" if lines[index].endswith("\n") else ""
    lines[index] = (
        match.group("prefix") + match.group("name") + match.group("operator")
        + to_version + match.group("suffix") + ending
    )
    try:
        manifest.write_text("".join(lines), encoding="utf-8", newline="")
    except OSError:
        return False, "Temporary requirements manifest could not be updated."
    return True, "Applied the explicit exact pin in the temporary workspace."


def _apply_npm_pin(manifest: Path, package: str, from_version: str, to_version: str) -> tuple[bool, str]:
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False, "package.json could not be parsed safely."
    if not isinstance(data, dict):
        return False, "package.json root must be an object."
    matches: list[tuple[dict[str, Any], str]] = []
    for section in _PACKAGE_SECTIONS:
        values = data.get(section)
        if not isinstance(values, dict):
            continue
        for name, version in values.items():
            if isinstance(name, str) and name.casefold() == package.casefold():
                matches.append((values, name))
    if len(matches) != 1:
        return False, "Expected exactly one direct dependency entry in package.json."
    values, manifest_name = matches[0]
    if values.get(manifest_name) != from_version:
        return False, "package.json version does not match the proposed current version exactly."
    values[manifest_name] = to_version
    try:
        manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError:
        return False, "Temporary package.json could not be updated."
    return True, "Applied the explicit exact version in the temporary workspace."


def _capture(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else ""


def _safe_environment(workspace: Path) -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", ""), "TEMP": str(workspace), "TMP": str(workspace)}
    for name in ("SYSTEMROOT", "WINDIR"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    env["PYTHONNOUSERSITE"] = "1"
    return env


def _run_static_check(command: list[str], workspace: Path) -> subprocess.CompletedProcess[str]:
    """Run only a fixed syntax checker, without a shell or project cwd."""
    return subprocess.run(
        command,
        cwd=str(workspace),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
        shell=False,
        env=_safe_environment(workspace),
    )


def _proposal(suggestion: dict[str, Any], matches: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str]:
    """Validate an explicit caller proposal against matching OSV candidates.

    Current code-suggestion records do not contain this optional proposal
    object. It is accepted only when a caller supplies all fields explicitly.
    """
    identity = _identity(suggestion, "package")
    if identity is None:
        return None, "Code suggestion has no valid package/ecosystem identity."
    if not matches:
        return None, "No compatibility assessment matched ecosystem and package identity."
    if len(matches) != 1:
        return None, "Multiple compatibility assessments match; proposed change is ambiguous."
    assessment = matches[0]
    if _text(assessment.get("assessment_status")).upper() != "REVIEW_REQUIRED":
        return None, "Matching compatibility assessment is not in REVIEW_REQUIRED state."
    proposal = suggestion.get("proposed_dependency_change")
    if not isinstance(proposal, dict):
        return None, "No explicit proposed dependency change was supplied; OSV candidates alone are not a selection."
    if _text(suggestion.get("review_status")).upper() != "REVIEW_REQUIRED":
        return None, "Code suggestion is not marked REVIEW_REQUIRED; no change is authorized for testing."

    proposal_identity = _identity(proposal, "package")
    if proposal_identity != identity:
        return None, "Proposed change package/ecosystem does not match the source suggestion."
    current = _text(proposal.get("from_version"))
    target = _text(proposal.get("to_version"))
    manifest_file = _text(proposal.get("manifest_file"))
    if not current or not target or not manifest_file:
        return None, "Proposed change must include exact current/target versions and a manifest path."
    if current != _text(assessment.get("installed_version")):
        return None, "Proposed current version does not match the compatibility assessment."
    if not _safe_literal_version(current, identity[0]) or not _safe_literal_version(target, identity[0]):
        return None, "Current and target versions must be safe, exact literals for the ecosystem."
    candidates = assessment.get("candidate_fixed_versions")
    if not isinstance(candidates, (list, tuple)) or target not in candidates:
        return None, "Proposed target is not an exact fixed-version candidate from the matching assessment."
    return {
        "package": _text(proposal.get("package")),
        "ecosystem": identity[0],
        "from_version": current,
        "to_version": target,
        "manifest_file": manifest_file,
    }, ""


def run_compatibility_tests(
    project_path: str,
    compatibility_assessments: list,
    code_suggestions: list,
) -> list[dict[str, Any]]:
    """Run allowlisted syntax validation for explicit dependency proposals.

    Recognized test profiles are fixed by source extension: ``.py`` uses the
    Python standard-library compiler; plain ``.js`` uses ``node --check`` if
    Node is available. JSX, TypeScript, Maven/Gradle, package scripts, pytest,
    unittest suites, installs, and user-supplied commands are not run.
    """
    assessments_by_identity: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for assessment in _records(compatibility_assessments):
        identity = _identity(assessment, "package")
        if identity:
            assessments_by_identity.setdefault(identity, []).append(assessment)

    suggestions = _records(code_suggestions)
    if not suggestions:
        return [_result("", "", "NOT_RUN", None, [], "No code-suggestion records were supplied.")]

    results: list[dict[str, Any]] = []
    for suggestion in suggestions:
        package = _text(suggestion.get("package"))
        ecosystem = _ecosystem(suggestion.get("ecosystem")) or "UNKNOWN"
        identity = _identity(suggestion, "package")
        matches = assessments_by_identity.get(identity, []) if identity else []
        proposal, problem = _proposal(suggestion, matches)
        if proposal is None:
            results.append(_result(package, ecosystem, "NOT_RUN", None, [], problem))
            continue

        source_file = _text(suggestion.get("source_file"))
        line_number = suggestion.get("line_number")
        if not source_file or not isinstance(line_number, int) or isinstance(line_number, bool) or line_number < 1:
            results.append(_result(package, ecosystem, "NOT_RUN", None, [], "Source suggestion has no safe relative file and line reference."))
            continue

        source_path, path_error = _safe_project_file(project_path, source_file)
        manifest_path, manifest_error = _safe_project_file(project_path, proposal["manifest_file"])
        manifest_supported = _manifest_destination(proposal["manifest_file"], ecosystem, Path(".")) is not None
        if path_error or manifest_error or source_path is None or manifest_path is None:
            results.append(_result(
                package, ecosystem, "NOT_RUN", None, [],
                path_error or manifest_error or "Source or manifest path could not be validated.",
            ))
            continue
        if not manifest_supported:
            results.append(_result(
                package, ecosystem, "NOT_RUN", None, [],
                "Only exact pinned requirements*.txt and direct package.json dependencies are supported.",
            ))
            continue

        suffix = source_path.suffix.casefold()
        if ecosystem == "PyPI" and suffix == ".py":
            command_name = "python"
        elif ecosystem == "npm" and suffix == ".js":
            node = shutil.which("node")
            if not node:
                results.append(_result(package, ecosystem, "NOT_RUN", None, [], "Node.js is unavailable for the fixed JavaScript syntax check."))
                continue
            command_name = "node"
        else:
            results.append(_result(
                package, ecosystem, "NOT_RUN", None, [],
                "No safe built-in static test command is configured for this source file type.",
            ))
            continue

        try:
            with tempfile.TemporaryDirectory(prefix="vulntriage-compat-") as temp_name:
                workspace = Path(temp_name).resolve()
                source_relative = Path(source_file.replace("\\", "/"))
                manifest_relative = Path(proposal["manifest_file"].replace("\\", "/"))
                copied_source = workspace / source_relative
                copied_manifest = workspace / manifest_relative
                copied_source.parent.mkdir(parents=True, exist_ok=True)
                copied_manifest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_path, copied_source)
                if copied_manifest != copied_source:
                    shutil.copyfile(manifest_path, copied_manifest)

                if ecosystem == "PyPI":
                    applied, reason = _apply_python_pin(
                        copied_manifest, proposal["package"], proposal["from_version"], proposal["to_version"]
                    )
                elif ecosystem == "npm":
                    applied, reason = _apply_npm_pin(
                        copied_manifest, proposal["package"], proposal["from_version"], proposal["to_version"]
                    )
                else:
                    applied, reason = False, "Only pinned requirements.txt and package.json edits are supported."
                if not applied:
                    results.append(_result(package, ecosystem, "NOT_RUN", None, [], reason))
                    continue

                if command_name == "python":
                    command = [sys.executable, "-I", "-m", "py_compile", source_relative.as_posix()]
                else:
                    command = [node, "--check", source_relative.as_posix()]
                change = dict(proposal)
                try:
                    completed = _run_static_check(command, workspace)
                except subprocess.TimeoutExpired as error:
                    results.append(_result(
                        package, ecosystem, "FAILED", command, [change],
                        f"Static syntax check exceeded the {COMMAND_TIMEOUT_SECONDS}-second timeout.",
                        _capture(error.stdout), _capture(error.stderr), None,
                    ))
                    continue
                except OSError as error:
                    results.append(_result(
                        package, ecosystem, "NOT_RUN", command, [change],
                        f"Allowlisted syntax checker could not be started: {error.__class__.__name__}.",
                    ))
                    continue

                status = "PASSED" if completed.returncode == 0 else "FAILED"
                reason = (
                    "Allowlisted static syntax check passed in the isolated workspace."
                    if status == "PASSED" else
                    "Allowlisted static syntax check failed; inspect its output."
                )
                results.append(_result(
                    package, ecosystem, status, command, [change], reason,
                    _capture(completed.stdout), _capture(completed.stderr), completed.returncode,
                ))
        except (OSError, shutil.Error, ValueError) as error:
            results.append(_result(
                package, ecosystem, "NOT_RUN", None, [],
                f"Isolated workspace preparation failed: {error.__class__.__name__}.",
            ))

    return results


test_compatibility = run_compatibility_tests
