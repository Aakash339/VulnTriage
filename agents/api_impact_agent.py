"""Static API-usage signals for reviewing dependency upgrades.

This module scans Python and JavaScript/TypeScript source without executing
project code. Detected references are only potential impact indicators: the
module has no release-note or API-diff data and cannot determine whether a
candidate upgrade is breaking or compatible.
"""

from __future__ import annotations

import ast
import os
import re
import tokenize
from pathlib import Path
from typing import Any


_IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", "target",
}
_PYTHON_ALIASES = {
    "beautifulsoup4": {"bs4"},
    "pillow": {"pil"},
    "scikit-learn": {"sklearn"},
    "pyyaml": {"yaml"},
    "opencv-python": {"cv2"},
    "python-dateutil": {"dateutil"},
}
_JS_MODULE_RE = re.compile(
    r"(?:\b(?:from|import)\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)"
    r"(['\"])([^'\"]+)\1"
)
_IDENTIFIER_RE = re.compile(r"(?<![\w$])[A-Za-z_$][\w$]*(?![\w$])")


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _ecosystem(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    return {"pypi": "PyPI", "npm": "npm", "maven": "Maven"}.get(value.casefold(), value)


def _package_key(ecosystem: str, package: str) -> tuple[str, str]:
    if ecosystem == "Maven":
        return ecosystem, package.strip()
    if ecosystem == "PyPI":
        return ecosystem, re.sub(r"[-_.]+", "-", package).casefold()
    return ecosystem, package.casefold()


def _record_key(record: dict[str, Any], package_field: str) -> tuple[str, str] | None:
    ecosystem = _ecosystem(record.get("ecosystem"))
    package = _text(record.get(package_field))
    return _package_key(ecosystem, package) if ecosystem and package else None


def _records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, dict)]


def _python_roots(package: str) -> set[str]:
    normalized = re.sub(r"[-_.]+", "-", package).casefold()
    roots = {normalized.replace("-", "_")}
    roots.update(_PYTHON_ALIASES.get(normalized, set()))
    return roots


def _js_root(module: str) -> str | None:
    module = module.strip()
    if not module or module.startswith((".", "/")):
        return None
    parts = module.split("/")
    return "/".join(parts[:2]) if parts[0].startswith("@") and len(parts) > 1 else parts[0]


def _line_statement(source: str, position: int) -> tuple[int, str]:
    line = source.count("\n", 0, position) + 1
    start = source.rfind("\n", 0, position) + 1
    end = source.find("\n", position)
    if end < 0:
        end = len(source)
    return line, source[start:end].strip()


def _add_usage(usages: dict[tuple[str, str], list[dict[str, Any]]], identity: tuple[str, str],
               filename: str, line: int, reference: str, statement: str, kind: str) -> None:
    record = {
        "source_file": filename,
        "line_number": line,
        "reference": reference,
        "statement": statement,
        "kind": kind,
    }
    key = (filename, str(line), reference, kind)
    if all((item["source_file"], str(item["line_number"]), item["reference"], item["kind"]) != key
           for item in usages.setdefault(identity, [])):
        usages[identity].append(record)


def _python_dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _python_dotted(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _scan_python(source: str, filename: str, roots: dict[str, set[tuple[str, str]]],
                 usages: dict[tuple[str, str], list[dict[str, Any]]],
                 ambiguous: dict[tuple[str, str], list[str]]) -> bool:
    """Scan imports and calls; return whether parsing/scanning was reliable."""
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return False

    bindings: dict[str, set[tuple[str, str]]] = {}
    def associate(module: str, node: ast.AST, binding_names: list[str], kind: str = "IMPORT") -> None:
        root = module.split(".", 1)[0].casefold()
        owners = roots.get(root, set())
        statement = ast.get_source_segment(source, node) or module
        if len(owners) > 1:
            line = getattr(node, "lineno", 1)
            for identity in owners:
                ambiguous.setdefault(identity, []).append(f"{filename}:{line}: {statement}")
            return
        if not owners:
            return
        identity = next(iter(owners))
        line = getattr(node, "lineno", 1)
        _add_usage(usages, identity, filename, line, module, statement, kind)
        for name in binding_names:
            if name:
                bindings.setdefault(name, set()).add(identity)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                associate(alias.name, node, [local])
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue
            associate(node.module, node, [alias.asname or alias.name for alias in node.names if alias.name != "*"])

    reliable = True
    importlib_names: set[str] = set()
    import_module_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_names.add(alias.asname or "importlib")
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    import_module_names.add(alias.asname or alias.name)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = _python_dotted(node.func)
            is_dynamic_loader = called == "__import__" or called in import_module_names
            if isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
                is_dynamic_loader = isinstance(node.func.value, ast.Name) and node.func.value.id in importlib_names
            if is_dynamic_loader:
                if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                    reliable = False
                else:
                    associate(node.args[0].value, node, [], "DYNAMIC_IMPORT")
                continue
            root = called.split(".", 1)[0] if called else ""
            owners = bindings.get(root, set())
            if len(owners) > 1:
                line = getattr(node, "lineno", 1)
                statement = ast.get_source_segment(source, node) or called
                for identity in owners:
                    ambiguous.setdefault(identity, []).append(f"{filename}:{line}: {statement}")
                continue
            if len(owners) == 1 and called:
                identity = next(iter(owners))
                reference = ast.get_source_segment(source, node.func) or called
                statement = ast.get_source_segment(source, node) or reference
                _add_usage(usages, identity, filename, node.lineno, reference, statement, "API_CALL")
    return reliable


def _js_lexical_info(source: str) -> tuple[str, dict[int, str], bool]:
    """Mask comments and string tokens while preserving offsets and newlines."""
    masked = list(source)
    literals: dict[int, str] = {}
    reliable = True
    index = 0

    def blank(start: int, end: int) -> None:
        for pos in range(start, end):
            if source[pos] not in "\r\n":
                masked[pos] = " "

    while index < len(source):
        if source.startswith("//", index):
            end = index + 2
            while end < len(source) and source[end] not in "\r\n":
                end += 1
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            close = source.find("*/", index + 2)
            end = len(source) if close < 0 else close + 2
            if close < 0:
                reliable = False
            blank(index, end)
            index = end
            continue
        quote = source[index]
        if quote in {"'", '"', "`"}:
            start = index
            end = index + 1
            closed = False
            while end < len(source):
                if source[end] == "\\":
                    end = min(end + 2, len(source))
                    continue
                if source[end] == quote:
                    end += 1
                    closed = True
                    break
                end += 1
            if not closed:
                reliable = False
            literals[start] = source[start + 1:end - 1 if closed else end]
            blank(start, end)
            index = end
            continue
        index += 1
    code = "".join(masked)
    # Catch obvious malformed declarations without pretending this lightweight
    # scanner is a full JavaScript/TypeScript grammar parser.
    if re.search(r"(?m)^\s*(?:const|let|var)\s*(?:=|;|$)", code):
        reliable = False
    if re.search(r"(?m)^\s*import\s*(?:from\b|;|$)", code):
        reliable = False
    return code, literals, reliable


def _js_bindings(prefix: str) -> set[str]:
    """Get simple local names from an ES import or assigned require/import()."""
    result: set[str] = set()
    import_match = re.search(r"\bimport\s+(.+?)\s*$", prefix)
    if import_match and not import_match.group(1).startswith("("):
        clause = import_match.group(1).strip().rstrip(",")
        if clause.startswith("*"):
            match = re.match(r"\*\s+as\s+([A-Za-z_$][\w$]*)", clause)
            if match:
                result.add(match.group(1))
        elif clause.startswith("{"):
            brace = clause[1:clause.find("}") if "}" in clause else len(clause)]
            for member in brace.split(","):
                parts = re.split(r"\s+as\s+", member.strip())
                name = parts[-1].strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                    result.add(name)
            default = clause.split(",", 1)[0].strip()
            if default and re.fullmatch(r"[A-Za-z_$][\w$]*", default):
                result.add(default)
        else:
            default = clause.split(",", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", default):
                result.add(default)

    simple_assignment = re.search(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*$", prefix)
    if simple_assignment:
        result.add(simple_assignment.group(1))
    destructured = re.search(r"\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*$", prefix)
    if destructured:
        for item in destructured.group(1).split(","):
            parts = re.split(r"\s*:\s*", item.strip())
            name = parts[-1].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                result.add(name)
    return result


def _scan_javascript(source: str, filename: str, roots: dict[str, set[tuple[str, str]]],
                     usages: dict[tuple[str, str], list[dict[str, Any]]],
                     ambiguous: dict[tuple[str, str], list[str]]) -> bool:
    code, literals, reliable = _js_lexical_info(source)
    bindings: list[tuple[str, tuple[str, str], int]] = []
    recognized_calls: set[int] = set()
    for match in _JS_MODULE_RE.finditer(source):
        module = literals.get(match.start(1))
        if module is None or module != match.group(2) or code[match.start()].isspace():
            continue
        recognized_calls.add(match.start())
        root = _js_root(module)
        if not root:
            continue
        owners = roots.get(root, set())
        statement_line, statement = _line_statement(source, match.start())
        if len(owners) > 1:
            for identity in owners:
                ambiguous.setdefault(identity, []).append(f"{filename}:{statement_line}: {statement}")
            continue
        if not owners:
            continue
        identity = next(iter(owners))
        kind = "IMPORT"
        _add_usage(usages, identity, filename, statement_line, module, statement, kind)
        line_start = source.rfind("\n", 0, match.start()) + 1
        prefix = source[line_start:match.start()]
        for name in _js_bindings(prefix):
            bindings.append((name, identity, match.end()))

    # Report basic references to imported aliases. The lexer-masked source
    # prevents comments and ordinary strings from looking like API calls.
    for alias, identity, start in bindings:
        for occurrence in _IDENTIFIER_RE.finditer(code, start):
            if occurrence.group(0) != alias:
                continue
            tail = code[occurrence.end():]
            next_token = re.match(r"\s*([.(\[])", tail)
            if not next_token:
                continue
            line, statement = _line_statement(source, occurrence.start())
            end = occurrence.end() + next_token.end()
            suffix = code[end:]
            member = re.match(r"\s*[A-Za-z_$][\w$]*", suffix)
            reference = alias + ("." + member.group(0).strip() if next_token.group(1) == "." and member else "")
            _add_usage(usages, identity, filename, line, reference, statement, "API_REFERENCE")

    # Nonliteral require()/import() calls cannot be mapped statically. Mark
    # the scan incomplete so absence of a match is not reported as clean.
    for call in re.finditer(r"\b(?:require|import)\s*\(", code):
        if call.start() not in recognized_calls:
            reliable = False
    return reliable


def analyze_api_impact(
    project_path: str,
    dependencies: list,
    compatibility_assessments: list,
) -> list[dict[str, Any]]:
    """Return conservative static API impact signals per dependency identity.

    Python and JavaScript/TypeScript are scanned. Maven/Java and dependencies
    without a reliable import mapping return ``NOT_ASSESSED``. A static
    reference plus a matching compatibility assessment and OSV candidate is
    ``POTENTIAL_IMPACT``; the result never claims that an upgrade breaks or
    preserves an API.
    """
    dependency_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    package_names: dict[tuple[str, str], str] = {}
    for dependency in _records(dependencies):
        identity = _record_key(dependency, "name")
        if identity is None:
            continue
        dependency_groups.setdefault(identity, []).append(dependency)
        package_names.setdefault(identity, _text(dependency.get("name")))

    compatibility_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for assessment in _records(compatibility_assessments):
        identity = _record_key(assessment, "package")
        if identity is not None:
            compatibility_groups.setdefault(identity, []).append(assessment)

    if not dependency_groups:
        return []

    import_roots: dict[str, dict[str, set[tuple[str, str]]]] = {"PyPI": {}, "npm": {}}
    for identity in dependency_groups:
        ecosystem, normalized_package = identity
        if ecosystem == "PyPI":
            roots = _python_roots(package_names[identity])
        elif ecosystem == "npm":
            roots = {_js_root(package_names[identity]) or normalized_package}
        else:
            continue
        for root in roots:
            import_roots[ecosystem].setdefault(root.casefold(), set()).add(identity)

    usages: dict[tuple[str, str], list[dict[str, Any]]] = {}
    ambiguous: dict[tuple[str, str], list[str]] = {}
    source_counts = {"PyPI": 0, "npm": 0}
    scan_reliable = {"PyPI": True, "npm": True}
    root: Path | None = None
    try:
        candidate_root = Path(project_path)
        if candidate_root.is_dir():
            root = candidate_root
    except (OSError, TypeError, ValueError):
        root = None

    if root is not None:
        def walk_error(_error: OSError) -> None:
            scan_reliable["PyPI"] = False
            scan_reliable["npm"] = False

        try:
            for current, directories, filenames in os.walk(root, onerror=walk_error):
                directories[:] = [name for name in directories if name not in _IGNORED_DIRS]
                for filename in filenames:
                    path = Path(current) / filename
                    suffix = path.suffix.casefold()
                    ecosystem = "PyPI" if suffix == ".py" else "npm" if suffix in {".js", ".jsx", ".ts", ".tsx"} else None
                    if ecosystem is None:
                        continue
                    source_counts[ecosystem] += 1
                    relative = path.relative_to(root).as_posix()
                    try:
                        if ecosystem == "PyPI":
                            with tokenize.open(path) as source_file:
                                source = source_file.read()
                            reliable = _scan_python(source, relative, import_roots[ecosystem], usages, ambiguous)
                        else:
                            source = path.read_text(encoding="utf-8")
                            reliable = _scan_javascript(source, relative, import_roots[ecosystem], usages, ambiguous)
                    except (OSError, UnicodeError, SyntaxError, ValueError):
                        reliable = False
                    if not reliable:
                        scan_reliable[ecosystem] = False
        except (OSError, ValueError):
            scan_reliable["PyPI"] = False
            scan_reliable["npm"] = False

    results: list[dict[str, Any]] = []
    for identity, dependency_records in dependency_groups.items():
        ecosystem, _ = identity
        package = package_names[identity]
        related_usages = usages.get(identity, [])
        ambiguous_evidence = list(dict.fromkeys(ambiguous.get(identity, [])))
        matching_compatibility = compatibility_groups.get(identity, [])
        explanations: list[str] = []
        candidates: list[str] = []
        compatibility_statuses: set[str] = set()
        compatibility_versions: set[str] = set()

        for record in matching_compatibility:
            status = _text(record.get("assessment_status")).upper()
            if status:
                compatibility_statuses.add(status)
            version = _text(record.get("installed_version"))
            if version:
                compatibility_versions.add(version)
            raw_candidates = record.get("candidate_fixed_versions")
            if isinstance(raw_candidates, (list, tuple)):
                for candidate in raw_candidates:
                    if isinstance(candidate, str) and candidate.strip() and candidate not in candidates:
                        candidates.append(candidate)

        dependency_versions = {
            _text(record.get("version")) for record in dependency_records if _text(record.get("version"))
        }
        dependency_version_missing = any(not _text(record.get("version")) for record in dependency_records)
        version_ambiguous = len(dependency_versions) > 1 or len(compatibility_versions) > 1
        version_mismatch = bool(dependency_versions and compatibility_versions and
                                dependency_versions != compatibility_versions)
        compatibility_conflict = len(compatibility_statuses) > 1
        if version_ambiguous:
            explanations.append("Multiple installed versions are present; resolve the dependency version before assessing impact.")
        if version_mismatch:
            explanations.append("Dependency and compatibility records disagree on the installed version.")
        if dependency_version_missing:
            explanations.append("A matching dependency record has no version; resolve it before assessing upgrade impact.")
        if compatibility_conflict:
            explanations.append("Matching compatibility records disagree; review those records before using their candidates.")
        if ecosystem not in {"PyPI", "npm"}:
            explanations.append("This module currently scans Python and JavaScript/TypeScript only; this ecosystem is unsupported.")
        elif source_counts[ecosystem] == 0:
            explanations.append("No supported source files were available for this ecosystem, so import usage could not be assessed.")
        elif not scan_reliable[ecosystem]:
            explanations.append("At least one source file could not be scanned reliably; an absence of references is inconclusive.")
        if not matching_compatibility:
            explanations.append("No compatibility assessment matched both ecosystem and package identity.")
        if not candidates:
            explanations.append("No matching OSV fixed-version candidate is available for upgrade-impact review.")
        if ambiguous_evidence:
            explanations.append("An import root maps to multiple dependencies; package ownership is ambiguous.")

        installed_versions = dependency_versions | compatibility_versions
        installed_version = next(iter(installed_versions)) if len(installed_versions) == 1 else ""
        version_is_unknown = not installed_versions
        assessment_is_reviewable = (
            matching_compatibility
            and "REVIEW_REQUIRED" in compatibility_statuses
            and bool(candidates)
            and not version_ambiguous
            and not version_mismatch
            and not dependency_version_missing
            and not compatibility_conflict
            and not version_is_unknown
        )

        if ecosystem not in {"PyPI", "npm"} or source_counts.get(ecosystem, 0) == 0:
            status = "NOT_ASSESSED"
        elif related_usages and assessment_is_reviewable:
            status = "POTENTIAL_IMPACT"
            explanations.append(
                "Static import/API references were found for a package with an OSV fixed-version candidate. "
                "No release-note or API-change evidence is available, so upgrade impact is unverified; test the upgrade."
            )
        elif related_usages:
            status = "NOT_ASSESSED"
            explanations.append("Static usage evidence exists, but package/version/fix evidence is insufficient to assess its upgrade impact.")
        elif (not scan_reliable[ecosystem] or ambiguous_evidence or not assessment_is_reviewable):
            status = "NOT_ASSESSED"
            if not scan_reliable[ecosystem]:
                explanations.append("Compatibility impact cannot be ruled out because the source scan was incomplete.")
            elif ambiguous_evidence:
                explanations.append("Compatibility impact cannot be assigned to one package because import ownership is ambiguous.")
            else:
                explanations.append("Compatibility impact cannot be assessed without a matching, reviewable fixed-version record.")
        else:
            status = "NO_KNOWN_IMPACT"
            explanations.append(
                "No matching static import/API reference was detected in supported files. This does not rule out dynamic, "
                "reflective, plugin-based, or indirect usage, and API compatibility remains unverified."
            )

        evidence = [
            f"{item['source_file']}:{item['line_number']}: {item['statement']} ({item['kind']}: {item['reference']})"
            for item in related_usages
        ]
        for dependency in dependency_records:
            version = _text(dependency.get("version")) or "version unavailable"
            source_file = _text(dependency.get("source_file"))
            detail = f"Dependency record: {version}"
            if source_file:
                detail += f" from {source_file}"
            if detail not in evidence:
                evidence.append(detail)
        for record in matching_compatibility:
            assessment_status = _text(record.get("assessment_status"))
            if assessment_status:
                evidence.append(f"Matching compatibility assessment status: {assessment_status}")
            for candidate in candidates:
                evidence.append(f"Matching compatibility assessment lists fixed-version candidate: {candidate}")
        evidence.extend(item for item in ambiguous_evidence if item not in evidence)
        results.append({
            "package": package,
            "ecosystem": ecosystem,
            "installed_version": installed_version,
            "candidate_fixed_versions": candidates,
            "status": status,
            "usages": related_usages,
            "evidence": evidence,
            "explanation": " ".join(dict.fromkeys(explanations)),
        })

    return results


analyze_upgrade_impact = analyze_api_impact
