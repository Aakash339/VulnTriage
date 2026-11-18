"""Detect source imports that correspond to vulnerable dependencies.

An import match means only that a package is imported somewhere in the scanned
source. It does not prove vulnerable functionality is used or exploitable.
Likewise, NOT_FOUND does not prove the package is unused or safe.
"""

import ast
import os
import re
import tokenize
from pathlib import Path


_IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist",
}
_SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".java"}
_PYTHON_IMPORT_NAMES = {
    "beautifulsoup4": {"bs4"},
    "pillow": {"pil"},
    "scikit-learn": {"sklearn"},
    "pyyaml": {"yaml"},
    "opencv-python": {"cv2"},
    "python-dateutil": {"dateutil"},
}

# This intentionally small allowlist maps Maven artifacts to package namespaces
# that are documented and stable for those artifacts. Unknown coordinates stay
# UNKNOWN; neither groupId nor artifactId is treated as a Java package name.
_MAVEN_PACKAGE_PREFIXES = {
    "com.google.guava:guava": ("com.google.common",),
    "org.apache.commons:commons-lang3": ("org.apache.commons.lang3",),
    "com.fasterxml.jackson.core:jackson-databind": ("com.fasterxml.jackson.databind",),
}

_JAVA_IMPORT_RE = re.compile(
    r"\bimport\s+(?:static\s+)?"
    r"(?P<module>[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:\s*\.\s*(?:[A-Za-z_$][A-Za-z0-9_$]*|\*))+ )"
    r"\s*;",
    re.VERBOSE,
)

# Captures module specifiers from ES import/export-from, side-effect import,
# require(), and dynamic import() syntax. This intentionally avoids a parser
# dependency; see the limitations in the function docstring.
_JS_MODULE_RE = re.compile(
    r"(?:\b(?:from|import)\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)"
    r"(['\"])([^'\"]+)\1"
)


def _javascript_lexical_info(source: str) -> tuple[str, dict[int, str], bool]:
    """Mask comments and quoted literals while preserving offsets and newlines.

    The returned literal map lets the caller confirm that a regex match points
    at an actual module-specifier string, rather than text inside another
    comment or string. This is deliberately a small lexer, not a JS parser.
    """
    masked = list(source)
    literals: dict[int, str] = {}
    index = 0
    length = len(source)
    reliable = True

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if source[position] not in "\r\n":
                masked[position] = " "

    while index < length:
        if source.startswith("//", index):
            end = index + 2
            while end < length and source[end] not in "\r\n":
                end += 1
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            close = source.find("*/", index + 2)
            end = length if close == -1 else close + 2
            if close == -1:
                reliable = False
            blank(index, end)
            index = end
            continue

        quote = source[index]
        if quote in {"'", '"', "`"}:
            start = index
            end = index + 1
            closed = False
            while end < length:
                if source[end] == "\\":
                    end = min(end + 2, length)
                    continue
                if source[end] == quote:
                    end += 1
                    closed = True
                    break
                end += 1
            if not closed:
                reliable = False
            content_end = end - 1 if closed else end
            literals[start] = source[start + 1:content_end]
            blank(start, end)
            index = end
            continue
        index += 1

    return "".join(masked), literals, reliable


def _normalize_name(name: str) -> str:
    """Apply npm/Python package-name normalization for exact comparisons."""
    return re.sub(r"[-_.]+", "-", name).casefold()


def _python_roots(package: str) -> set[str]:
    """Return import roots associated with a Python distribution name."""
    normalized = _normalize_name(package)
    roots = {normalized.replace("-", "_")}
    roots.update(_PYTHON_IMPORT_NAMES.get(normalized, set()))
    return roots


def _module_matches(module: str, package: str, is_python: bool) -> bool:
    """Compare a module's top-level package with a dependency name exactly."""
    module = module.strip()
    if not module or module.startswith((".", "/")):
        return False

    if is_python:
        # Python module components are separated by dots. Relative imports are
        # excluded before reaching this function (and leading dots are rejected).
        root = module.split(".", 1)[0]
        return root.casefold() in _python_roots(package)

    components = module.split("/")
    root = "/".join(components[:2]) if components[0].startswith("@") else components[0]
    return _normalize_name(root) == _normalize_name(package)


def _java_lexical_info(source: str) -> tuple[str, bool]:
    """Mask Java comments and string/character literals, preserving positions."""
    masked = list(source)
    index = 0
    reliable = True
    length = len(source)

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if source[position] not in "\r\n":
                masked[position] = " "

    while index < length:
        if source.startswith("//", index):
            end = index + 2
            while end < length and source[end] not in "\r\n":
                end += 1
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            close = source.find("*/", index + 2)
            end = length if close == -1 else close + 2
            if close == -1:
                reliable = False
            blank(index, end)
            index = end
            continue

        quote = source[index]
        if quote in {"'", '"'}:
            is_text_block = quote == '"' and source.startswith('"""', index)
            delimiter = '"""' if is_text_block else quote
            end = index + len(delimiter)
            closed = False
            while end < length:
                if source[end] == "\\":
                    end = min(end + 2, length)
                    continue
                if source.startswith(delimiter, end):
                    end += len(delimiter)
                    closed = True
                    break
                if not is_text_block and source[end] in "\r\n":
                    reliable = False
                    break
                end += 1
            if not closed:
                reliable = False
            blank(index, end)
            index = end
            continue
        index += 1

    return "".join(masked), reliable


def _java_mapping_candidates(module: str) -> set[str]:
    """Return Maven coordinates whose curated package prefix matches an import."""
    candidates: set[str] = set()
    for coordinate, prefixes in _MAVEN_PACKAGE_PREFIXES.items():
        if any(module == prefix or module.startswith(prefix + ".") for prefix in prefixes):
            candidates.add(coordinate)
    return candidates


def _java_imports(source: str):
    """Return Java module, line, and source statement tuples plus reliability."""
    code, reliable = _java_lexical_info(source)
    matches = list(_JAVA_IMPORT_RE.finditer(code))
    recognized_starts = {match.start() for match in matches}
    for keyword in re.finditer(r"\bimport\b", code):
        if keyword.start() not in recognized_starts:
            reliable = False

    imports = []
    for match in matches:
        module = re.sub(r"\s*\.\s*", ".", match.group("module"))
        line = source.count("\n", 0, match.start()) + 1
        statement = source[match.start():match.end()].strip()
        imports.append((module, line, statement))
    return imports, reliable


def _add_evidence(evidence: dict, packages: list[str], module: str,
                  is_python: bool, filename: str, line: int, statement: str) -> None:
    for package in packages:
        if _module_matches(module, package, is_python):
            item = f"{filename}:{line}: {statement.strip()}"
            if item not in evidence[package]:
                evidence[package].append(item)


def _python_dynamic_imports(tree: ast.AST):
    """Yield literal module names and call nodes for common Python loaders."""
    importlib_aliases = {"importlib"}
    import_module_aliases: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib" or alias.name.startswith("importlib."):
                    importlib_aliases.add(alias.asname or alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    import_module_aliases.add(alias.asname or alias.name)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        function = node.func
        is_loader = isinstance(function, ast.Name) and (
            function.id == "__import__" or function.id in import_module_aliases
        )
        if isinstance(function, ast.Attribute) and function.attr == "import_module":
            is_loader = isinstance(function.value, ast.Name) and function.value.id in importlib_aliases
        argument = node.args[0]
        if is_loader and isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            yield argument.value, node


def check_reachability(project_path: str, vulnerabilities: list) -> list:
    """Return one ReachabilityResult-shaped dictionary per distinct package.

    ``UNKNOWN`` is used when scanning was incomplete, no supported source file
    was available, or no match was found after an unreliable scan.
    JavaScript/TypeScript and Java syntax are recognized with lightweight
    lexical scanning rather than full language parsers. Maven reachability uses
    only the curated coordinate-to-package map above; unmapped and ambiguous
    packages remain UNKNOWN. Positive evidence is retained despite errors in
    other files. Imports do not prove runtime execution or exploitability.
    """
    if not isinstance(vulnerabilities, (list, tuple)):
        return []

    targets: list[tuple[str, str, str]] = []
    package_keys: set[str] = set()
    maven_keys: set[str] = set()
    for record in vulnerabilities or []:
        if not isinstance(record, dict):
            continue
        name = record.get("package")
        if not isinstance(name, str) or not name.strip():
            continue
        name = name.strip()
        ecosystem = record.get("ecosystem")
        if ecosystem == "Maven":
            # Maven coordinates are identifiers, not Python/npm package names.
            if name not in maven_keys:
                maven_keys.add(name)
                targets.append((name, "Maven", name))
        else:
            # Retain the existing Python/npm normalization and duplicate behavior.
            key = _normalize_name(name)
            if key not in package_keys:
                package_keys.add(key)
                targets.append((name, "other", name))

    if not targets:
        return []

    packages = [name for name, ecosystem, _ in targets if ecosystem != "Maven"]
    evidence = {package: [] for package in packages}
    maven_evidence = {key: [] for _, ecosystem, key in targets if ecosystem == "Maven"}
    maven_ambiguous: set[str] = set()
    maven_coordinates = set(maven_evidence)
    supported_files = 0
    java_files = 0
    try:
        root = Path(project_path)
        if not root.is_dir():
            scan_failed = True
            java_scan_failed = True
        else:
            scan_failed = False
            java_scan_failed = False
    except (OSError, TypeError, ValueError):
        root = None
        scan_failed = True
        java_scan_failed = True

    def on_walk_error(_error):
        nonlocal scan_failed, java_scan_failed
        scan_failed = True
        java_scan_failed = True

    if root is not None and not scan_failed:
        try:
            for current, directories, filenames in os.walk(root, onerror=on_walk_error):
                directories[:] = [name for name in directories if name not in _IGNORED_DIRS]
                for filename in filenames:
                    path = Path(current) / filename
                    suffix = path.suffix.lower()
                    if suffix not in _SUPPORTED_SUFFIXES:
                        continue
                    if suffix == ".java":
                        java_files += 1
                    else:
                        supported_files += 1
                    relative = path.relative_to(root).as_posix()
                    try:
                        if suffix == ".py":
                            with tokenize.open(path) as source_file:
                                source = source_file.read()
                        else:
                            source = path.read_text(encoding="utf-8")
                    except (OSError, UnicodeError, SyntaxError):
                        if suffix == ".java":
                            java_scan_failed = True
                        else:
                            scan_failed = True
                        continue

                    if suffix == ".py":
                        try:
                            tree = ast.parse(source, filename=relative)
                        except (SyntaxError, ValueError, TypeError, RecursionError):
                            scan_failed = True
                            continue
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Import):
                                statement = ast.get_source_segment(source, node) or "import ..."
                                for alias in node.names:
                                    _add_evidence(evidence, packages, alias.name, True,
                                                  relative, node.lineno, statement)
                            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                                statement = ast.get_source_segment(source, node) or f"from {node.module} import ..."
                                _add_evidence(evidence, packages, node.module, True,
                                              relative, node.lineno, statement)
                        for module, node in _python_dynamic_imports(tree):
                            statement = ast.get_source_segment(source, node) or "dynamic import(...)"
                            _add_evidence(evidence, packages, module, True,
                                          relative, node.lineno, statement)
                    elif suffix != ".java":
                        code_mask, string_literals, reliable = _javascript_lexical_info(source)
                        if not reliable:
                            scan_failed = True
                        for match in _JS_MODULE_RE.finditer(source):
                            # Reject import-like text inside comments and ordinary
                            # strings; accept only a real quoted token at this offset.
                            module_literal = string_literals.get(match.start(1))
                            if (
                                code_mask[match.start()].isspace()
                                or module_literal is None
                                or module_literal != match.group(2)
                            ):
                                continue
                            module = match.group(2)
                            line = source.count("\n", 0, match.start()) + 1
                            line_start = source.rfind("\n", 0, match.start()) + 1
                            line_end = source.find("\n", match.end())
                            if line_end == -1:
                                line_end = len(source)
                            statement = source[line_start:line_end]
                            _add_evidence(evidence, packages, module, False,
                                          relative, line, statement)
                    else:
                        imports, reliable = _java_imports(source)
                        if not reliable:
                            java_scan_failed = True
                            continue
                        for module, line, statement in imports:
                            candidates = _java_mapping_candidates(module)
                            if len(candidates) == 1:
                                coordinate = next(iter(candidates))
                                if coordinate in maven_evidence:
                                    item = f"{relative}:{line}: {statement}"
                                    if item not in maven_evidence[coordinate]:
                                        maven_evidence[coordinate].append(item)
                            elif len(candidates) > 1:
                                # An import alone cannot select one artifact when
                                # curated package ownership overlaps.
                                maven_ambiguous.update(candidates & maven_coordinates)
        except (OSError, ValueError):
            scan_failed = True
            java_scan_failed = True

    # No source files means there was no basis for a negative import finding.
    if supported_files == 0:
        scan_failed = True

    results = []
    for package, ecosystem, key in targets:
        if ecosystem == "Maven":
            matches = maven_evidence[key]
            if matches:
                status = "USED"
            elif (
                key not in _MAVEN_PACKAGE_PREFIXES
                or java_files == 0
                or java_scan_failed
                or key in maven_ambiguous
            ):
                status = "UNKNOWN"
            else:
                status = "NOT_FOUND"
        else:
            matches = evidence[package]
            status = "USED" if matches else ("UNKNOWN" if scan_failed else "NOT_FOUND")
        results.append({"package": package, "status": status, "evidence": matches})
    return results
