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
_SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx"}
_PYTHON_IMPORT_NAMES = {
    "beautifulsoup4": {"bs4"},
    "pillow": {"pil"},
    "scikit-learn": {"sklearn"},
    "pyyaml": {"yaml"},
    "opencv-python": {"cv2"},
    "python-dateutil": {"dateutil"},
}

# Captures module specifiers from ES import/export-from, side-effect import,
# require(), and dynamic import() syntax. This intentionally avoids a parser
# dependency; see the limitations in the function docstring.
_JS_MODULE_RE = re.compile(
    r"(?:\b(?:from|import)\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)"
    r"(['\"])([^'\"]+)\1"
)


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


def _add_evidence(evidence: dict, packages: list[str], module: str,
                  is_python: bool, filename: str, line: int, statement: str) -> None:
    for package in packages:
        if _module_matches(module, package, is_python):
            item = f"{filename}:{line}: {statement.strip()}"
            if item not in evidence[package]:
                evidence[package].append(item)


def check_reachability(project_path: str, vulnerabilities: list) -> list:
    """Return one ReachabilityResult-shaped dictionary per distinct package.

    ``UNKNOWN`` is used when scanning was incomplete and no match was found.
    JavaScript/TypeScript syntax is recognized with a conservative regular
    expression rather than a full language parser, so generated or unusual
    syntax can be missed. Positive evidence is retained even if another file
    cannot be read or parsed.
    """
    if not isinstance(vulnerabilities, (list, tuple)):
        return []

    packages: list[str] = []
    package_keys: set[str] = set()
    for record in vulnerabilities or []:
        if not isinstance(record, dict):
            continue
        name = record.get("package")
        if not isinstance(name, str) or not name.strip():
            continue
        name = name.strip()
        key = _normalize_name(name)
        if key not in package_keys:
            package_keys.add(key)
            packages.append(name)

    if not packages:
        return []

    evidence = {package: [] for package in packages}
    try:
        root = Path(project_path)
        if not root.is_dir():
            scan_failed = True
        else:
            scan_failed = False
    except (OSError, TypeError, ValueError):
        root = None
        scan_failed = True

    def on_walk_error(_error):
        nonlocal scan_failed
        scan_failed = True

    if root is not None and not scan_failed:
        try:
            for current, directories, filenames in os.walk(root, onerror=on_walk_error):
                directories[:] = [name for name in directories if name not in _IGNORED_DIRS]
                for filename in filenames:
                    path = Path(current) / filename
                    suffix = path.suffix.lower()
                    if suffix not in _SUPPORTED_SUFFIXES:
                        continue
                    relative = path.relative_to(root).as_posix()
                    try:
                        if suffix == ".py":
                            with tokenize.open(path) as source_file:
                                source = source_file.read()
                        else:
                            source = path.read_text(encoding="utf-8")
                    except (OSError, UnicodeError, SyntaxError):
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
                    else:
                        for match in _JS_MODULE_RE.finditer(source):
                            module = match.group(2)
                            line = source.count("\n", 0, match.start()) + 1
                            line_start = source.rfind("\n", 0, match.start()) + 1
                            line_end = source.find("\n", match.end())
                            if line_end == -1:
                                line_end = len(source)
                            statement = source[line_start:line_end]
                            _add_evidence(evidence, packages, module, False,
                                          relative, line, statement)
        except (OSError, ValueError):
            scan_failed = True

    results = []
    for package in packages:
        matches = evidence[package]
        status = "USED" if matches else ("UNKNOWN" if scan_failed else "NOT_FOUND")
        results.append({"package": package, "status": status, "evidence": matches})
    return results
