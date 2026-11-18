"""Dependency manifest extraction for the supported Python and npm formats."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from packaging.requirements import InvalidRequirement, Requirement


_IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
_NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _py_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _npm_name(name: str) -> str:
    # npm names are case insensitive; retaining the full name keeps scopes distinct.
    return name.lower()


def _requirement_line(raw: str) -> tuple[str, str] | None:
    line = raw.strip()
    if not line or line.startswith("#") or line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
        return None
    editable = line.startswith(("-e ", "--editable "))
    if editable:
        line = line.split(None, 1)[1].strip()
    # pip permits trailing comments after whitespace. Do not trim URL fragments.
    line = re.sub(r"\s+#.*$", "", line).strip()
    # PEP 508 direct references are parsed by packaging and retain their URL as version.
    try:
        requirement = Requirement(line)
        version = str(requirement.specifier) or (requirement.url or "")
        specs = list(requirement.specifier)
        if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
            version = specs[0].version
        # Preserve the URL fragment as the declared version; never infer an installed version.
        return requirement.name, version
    except InvalidRequirement:
        if editable:
            egg = re.search(r"[#&]egg=([^&]+)", line)
            if egg:
                return unquote(egg.group(1)), line
        return None


def _read_requirements(path: Path, root: Path) -> list[dict[str, str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    result = []
    for line in lines:
        parsed = _requirement_line(line)
        if parsed:
            name, version = parsed
            result.append(_dep(name, version, "PyPI", path, root))
    return result


def _dep(name: str, version: str, ecosystem: str, path: Path, root: Path) -> dict[str, str]:
    try:
        source = path.relative_to(root).as_posix()
    except ValueError:
        source = path.name
    return {"name": name, "version": version, "ecosystem": ecosystem, "source_file": source}


def _json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _package_manifest(path: Path, root: Path) -> list[dict[str, str]]:
    data = _json(path)
    if data is None:
        return []
    result = []
    for section in _NPM_SECTIONS:
        values = data.get(section)
        if not isinstance(values, dict):
            continue
        for name, version in values.items():
            if isinstance(name, str) and isinstance(version, str) and name.strip():
                result.append(_dep(name, version, "npm", path, root))
    return result


def _npm_lock(path: Path, root: Path) -> tuple[list[dict[str, str]], bool]:
    data = _json(path)
    if data is None:
        return [], False
    result: list[dict[str, str]] = []
    lock_version = data.get("lockfileVersion")
    if isinstance(data.get("packages"), dict) and lock_version in (2, 3):
        for package_path, info in data["packages"].items():
            if not package_path or not isinstance(info, dict):
                continue
            # Every package entry is rooted at node_modules; nested paths are valid too.
            match = re.search(r"(?:^|/)node_modules/(.+)$", package_path.replace("\\", "/"))
            if not match:
                continue
            name = match.group(1)
            version = info.get("version")
            if isinstance(version, str) and version:
                result.append(_dep(name, version, "npm", path, root))
        return result, True
    if lock_version == 1 and isinstance(data.get("dependencies"), dict):
        def walk(tree: dict[str, Any]) -> None:
            for name, info in tree.items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version")
                if isinstance(version, str) and version:
                    result.append(_dep(name, version, "npm", path, root))
                children = info.get("dependencies")
                if isinstance(children, dict):
                    walk(children)
        walk(data["dependencies"])
        return result, True
    return [], False


def _identity(dep: dict[str, str]) -> tuple[str, str, str]:
    normalize = _py_name if dep["ecosystem"] == "PyPI" else _npm_name
    return dep["ecosystem"], normalize(dep["name"]), dep["version"]


def parse_dependencies(project_path: str) -> list[dict[str, str]]:
    """Extract dependency declarations and lockfile resolutions from a project tree."""
    root = Path(project_path)
    if not root.is_dir():
        return []

    manifests: list[Path] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _IGNORED_DIRS)
        base = Path(current)
        for filename in files:
            if filename == "requirements.txt" or filename == "package.json" or filename == "package-lock.json":
                manifests.append(base / filename)
    manifests.sort(key=lambda p: p.relative_to(root).as_posix())

    python_deps: list[dict[str, str]] = []
    npm_declarations: list[dict[str, str]] = []
    npm_locks: list[tuple[Path, list[dict[str, str]], bool]] = []
    for path in manifests:
        if path.name == "requirements.txt":
            python_deps.extend(_read_requirements(path, root))
        elif path.name == "package.json":
            npm_declarations.extend(_package_manifest(path, root))
        else:
            deps, valid = _npm_lock(path, root)
            npm_locks.append((path, deps, valid))

    # Apply the nearest lockfile to declarations in its directory subtree. Where it
    # resolves a name, the lock value wins; otherwise retain the manifest declaration.
    npm_result: list[dict[str, str]] = []
    lock_entries: list[dict[str, str]] = []
    for _, entries, valid in npm_locks:
        if valid:
            lock_entries.extend(entries)
    for declaration in npm_declarations:
        source_dir = (root / declaration["source_file"]).parent
        relevant_locks = [x for x in npm_locks if x[2] and source_dir == (root / x[0].relative_to(root)).parent]
        resolved = None
        if relevant_locks:
            lock_ids = {_identity(d)[:2]: d for d in relevant_locks[0][1]}
            resolved = lock_ids.get(_identity(declaration)[:2])
        if resolved:
            npm_result.append(resolved)
        else:
            npm_result.append(declaration)
    npm_result.extend(lock_entries)

    combined = python_deps + npm_result
    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    for dep in combined:
        key = _identity(dep)
        previous = unique.get(key)
        # Prefer lockfile provenance where equivalent entries were also declared.
        if previous is None or dep["source_file"].endswith("package-lock.json"):
            unique[key] = dep
    return sorted(unique.values(), key=lambda d: (d["ecosystem"], _identity(d)[1], d["version"], d["source_file"]))
