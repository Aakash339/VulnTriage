"""Dependency manifest extraction for Python, npm, Maven, and Gradle formats."""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from packaging.requirements import InvalidRequirement, Requirement


_IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
_NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_GRADLE_CONFIGURATIONS = (
    "implementation", "api", "runtimeOnly", "compileOnly", "compileOnlyApi",
    "testImplementation", "testRuntimeOnly", "testCompileOnly", "annotationProcessor", "kapt",
)
_GRADLE_DECLARATION = re.compile(
    r"^\s*(?P<configuration>" + "|".join(sorted(_GRADLE_CONFIGURATIONS, key=len, reverse=True)) +
    r")\b\s*(?:\(\s*)?(?P<quote>['\"])(?P<coordinate>[^'\"\r\n]+)(?P=quote)\s*\)?\s*;?\s*$"
)


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


def _xml_child(element: ET.Element, name: str) -> ET.Element | None:
    """Find a direct XML child by local tag name, ignoring its namespace."""
    for child in element:
        if isinstance(child.tag, str) and child.tag.rsplit("}", 1)[-1] == name:
            return child
    return None


def _xml_text(element: ET.Element, name: str) -> str:
    child = _xml_child(element, name)
    return (child.text or "").strip() if child is not None else ""


def _maven_value(value: str, properties: dict[str, str]) -> str:
    """Resolve available simple POM properties, leaving unknown tokens intact."""
    token = re.compile(r"\$\{([^}]+)\}")
    resolved = value.strip()
    for _ in range(max(1, len(properties) + 1)):
        updated = token.sub(lambda match: properties.get(match.group(1), match.group(0)), resolved)
        if updated == resolved:
            break
        resolved = updated
    return resolved


def _maven_coordinate(dependency: ET.Element, properties: dict[str, str], root: Path,
                      source: Path, managed_versions: dict[str, str] | None = None) -> dict[str, str] | None:
    group = _maven_value(_xml_text(dependency, "groupId"), properties)
    artifact = _maven_value(_xml_text(dependency, "artifactId"), properties)
    if not group or not artifact or "${" in group or "${" in artifact:
        return None

    version = _xml_text(dependency, "version")
    if version:
        version = _maven_value(version, properties)
    else:
        version = (managed_versions or {}).get(f"{group}:{artifact}", "")
    return _dep(f"{group}:{artifact}", version, "Maven", source, root)


def _pom_dependencies(path: Path, root: Path) -> list[dict[str, str]]:
    """Read direct POM dependencies; management entries only supply versions."""
    try:
        document = ET.parse(path).getroot()
    except (OSError, ET.ParseError, ValueError):
        return []

    properties: dict[str, str] = {}
    property_element = _xml_child(document, "properties")
    if property_element is not None:
        for item in property_element:
            if isinstance(item.tag, str):
                properties[item.tag.rsplit("}", 1)[-1]] = (item.text or "").strip()

    parent = _xml_child(document, "parent")
    project_group = _xml_text(document, "groupId") or (_xml_text(parent, "groupId") if parent is not None else "")
    project_version = _xml_text(document, "version") or (_xml_text(parent, "version") if parent is not None else "")
    properties.setdefault("project.groupId", _maven_value(project_group, properties))
    properties.setdefault("pom.groupId", properties["project.groupId"])
    properties.setdefault("project.version", _maven_value(project_version, properties))
    properties.setdefault("pom.version", properties["project.version"])

    managed_versions: dict[str, str] = {}
    management = _xml_child(document, "dependencyManagement")
    management_dependencies = _xml_child(management, "dependencies") if management is not None else None
    if management_dependencies is not None:
        for dependency in management_dependencies:
            if not isinstance(dependency.tag, str) or dependency.tag.rsplit("}", 1)[-1] != "dependency":
                continue
            record = _maven_coordinate(dependency, properties, root, path)
            if record is not None and record["version"]:
                managed_versions.setdefault(record["name"], record["version"])

    direct_dependencies = _xml_child(document, "dependencies")
    if direct_dependencies is None:
        return []
    result = []
    for dependency in direct_dependencies:
        if not isinstance(dependency.tag, str) or dependency.tag.rsplit("}", 1)[-1] != "dependency":
            continue
        record = _maven_coordinate(dependency, properties, root, path, managed_versions)
        if record is not None:
            result.append(record)
    return result


def _strip_gradle_comments(source: str) -> str:
    """Blank Groovy/Kotlin comments without interpreting the build script."""
    characters = list(source)
    index = 0
    while index < len(source):
        if source[index] in "'\"":
            quote = source[index]
            triple = source.startswith(quote * 3, index)
            delimiter_length = 3 if triple else 1
            index += delimiter_length
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                    continue
                if source.startswith(quote * delimiter_length, index):
                    index += delimiter_length
                    break
                index += 1
            continue
        if source.startswith("//", index):
            end = index + 2
            while end < len(source) and source[end] not in "\r\n":
                end += 1
            for position in range(index, end):
                characters[position] = " "
            index = end
            continue
        if source.startswith("/*", index):
            close = source.find("*/", index + 2)
            end = len(source) if close == -1 else close + 2
            for position in range(index, end):
                if source[position] not in "\r\n":
                    characters[position] = " "
            index = end
            continue
        index += 1
    return "".join(characters)


def _gradle_coordinate(raw: str, path: Path, root: Path) -> dict[str, str] | None:
    parts = raw.strip().split(":")
    if len(parts) != 3:
        return None
    group, artifact, version = (part.strip() for part in parts)
    if not group or not artifact or not version or any("$" in part for part in (group, artifact)):
        return None
    return _dep(f"{group}:{artifact}", version, "Maven", path, root)


def _gradle_declarations(path: Path, root: Path) -> list[dict[str, str]]:
    try:
        source = _strip_gradle_comments(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        return []
    result = []
    for line in source.splitlines():
        match = _GRADLE_DECLARATION.fullmatch(line)
        if match:
            dependency = _gradle_coordinate(match.group("coordinate"), path, root)
            if dependency is not None:
                result.append(dependency)
    return result


def _gradle_lock(path: Path, root: Path) -> list[dict[str, str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    result = []
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#") or "=" not in value:
            continue
        coordinate = value.split("=", 1)[0].strip()
        dependency = _gradle_coordinate(coordinate, path, root)
        if dependency is not None:
            result.append(dependency)
    return result


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
    if dep["ecosystem"] == "PyPI":
        name = _py_name(dep["name"])
    elif dep["ecosystem"] == "npm":
        name = _npm_name(dep["name"])
    else:
        # Maven coordinates are exact repository identifiers; do not apply
        # Python/npm punctuation normalization to groupId:artifactId.
        name = dep["name"].strip()
    return dep["ecosystem"], name, dep["version"]


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
            if filename in {
                "requirements.txt", "package.json", "package-lock.json", "pom.xml",
                "build.gradle", "build.gradle.kts", "gradle.lockfile",
            }:
                manifests.append(base / filename)
    manifests.sort(key=lambda p: p.relative_to(root).as_posix())

    python_deps: list[dict[str, str]] = []
    npm_declarations: list[dict[str, str]] = []
    npm_locks: list[tuple[Path, list[dict[str, str]], bool]] = []
    maven_deps: list[dict[str, str]] = []
    gradle_declarations: list[dict[str, str]] = []
    gradle_locks: list[tuple[Path, list[dict[str, str]]]] = []
    for path in manifests:
        if path.name == "requirements.txt":
            python_deps.extend(_read_requirements(path, root))
        elif path.name == "package.json":
            npm_declarations.extend(_package_manifest(path, root))
        elif path.name == "package-lock.json":
            deps, valid = _npm_lock(path, root)
            npm_locks.append((path, deps, valid))
        elif path.name == "pom.xml":
            maven_deps.extend(_pom_dependencies(path, root))
        elif path.name in {"build.gradle", "build.gradle.kts"}:
            gradle_declarations.extend(_gradle_declarations(path, root))
        elif path.name == "gradle.lockfile":
            gradle_locks.append((path, _gradle_lock(path, root)))

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

    # Gradle lock state records exact resolved versions for direct and
    # transitive modules. When a declaration is present in the nearest lock,
    # omit its declared version and let the lock entry represent it.
    gradle_result: list[dict[str, str]] = []
    lock_records = [record for _, records in gradle_locks for record in records]
    for declaration in gradle_declarations:
        declaration_dir = (root / declaration["source_file"]).parent
        ancestor_locks = [
            (lock_path, records)
            for lock_path, records in gradle_locks
            if lock_path.parent == declaration_dir or lock_path.parent in declaration_dir.parents
        ]
        if ancestor_locks:
            nearest_lock_dir = max((lock_path.parent for lock_path, _ in ancestor_locks), key=lambda path: len(path.parts))
            nearest_entries = [record for lock_path, records in ancestor_locks
                               if lock_path.parent == nearest_lock_dir for record in records]
            if any(_identity(record)[:2] == _identity(declaration)[:2] for record in nearest_entries):
                continue
        gradle_result.append(declaration)
    gradle_result.extend(lock_records)

    combined = python_deps + npm_result + maven_deps + gradle_result
    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    for dep in combined:
        key = _identity(dep)
        previous = unique.get(key)
        # Prefer lockfile provenance where equivalent entries were also declared.
        if previous is None or dep["source_file"].endswith(("package-lock.json", "gradle.lockfile")):
            unique[key] = dep
    return sorted(unique.values(), key=lambda d: (d["ecosystem"], _identity(d)[1], d["version"], d["source_file"]))
