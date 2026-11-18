
from collections.abc import Callable
from typing import Any

from agents.dependency_agent import parse_dependencies
from agents.vulnerability_agent import scan_vulnerabilities
from agents.reachability_agent import check_reachability
from agents.remediation_agent import generate_remediation


def run_vulntriage(
    project_path: str,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    coverage: dict[str, Any] | None = None,
) -> list:
    """Run the existing analysis sequence, optionally reporting stage events.

    The callback receives ``started`` and ``completed`` events for each actual
    stage. Completed events carry that stage's real output for UI reporting.
    Omitting the callback preserves the original API behavior and return value.
    The optional coverage dictionary is populated in place without changing the
    existing findings return value.
    """
    if coverage is not None:
        coverage.clear()
        coverage.update({
            "manifests_scanned": 0,
            "unsupported_manifests": 0,
            "parsing_failures": 0,
            "dependencies_detected": 0,
            "successfully_queried_dependencies": 0,
            "failed_queries": 0,
            "not_queried_dependencies": 0,
            "status": "UNKNOWN",
        })

    def notify(stage: str, status: str, data: Any = None) -> None:
        if progress_callback is not None:
            event = {"stage": stage, "status": status}
            if status == "completed":
                event["data"] = data
            progress_callback(event)

    # Step 1: Extract project dependencies
    notify("dependencies", "started")
    dependencies = (
        parse_dependencies(project_path, coverage=coverage)
        if coverage is not None else parse_dependencies(project_path)
    )
    if coverage is not None:
        coverage["dependencies_detected"] = len(dependencies)
    notify("dependencies", "completed", dependencies)

    # Step 2: Find known vulnerabilities
    notify("osv", "started")
    vulnerabilities = (
        scan_vulnerabilities(dependencies, coverage=coverage)
        if coverage is not None else scan_vulnerabilities(dependencies)
    )
    if coverage is not None:
        detected = coverage["dependencies_detected"]
        accounted = (
            coverage["successfully_queried_dependencies"]
            + coverage["failed_queries"]
            + coverage["not_queried_dependencies"]
        )
        if accounted < detected:
            coverage["not_queried_dependencies"] += detected - accounted

        if detected == 0:
            coverage["status"] = "NO_SUPPORTED_DEPENDENCIES" if coverage["parsing_failures"] == 0 else "PARTIAL"
        elif (
            coverage["failed_queries"] == detected
            and coverage["successfully_queried_dependencies"] == 0
            and coverage["not_queried_dependencies"] == 0
            and coverage["parsing_failures"] == 0
        ):
            coverage["status"] = "ALL_OSV_QUERIES_FAILED"
        elif (
            coverage["parsing_failures"] > 0
            or coverage["failed_queries"] > 0
            or coverage["not_queried_dependencies"] > 0
            or coverage["unsupported_manifests"] > 0
        ):
            coverage["status"] = "PARTIAL"
        else:
            coverage["status"] = "COMPLETE"
    notify("osv", "completed", vulnerabilities)

    # Step 3: Check basic source-code reachability
    notify("reachability", "started")
    reachability = check_reachability(
        project_path,
        vulnerabilities
    )
    notify("reachability", "completed", reachability)

    # Step 4: Prioritise and recommend fixes
    notify("risk", "started")
    findings = generate_remediation(
        vulnerabilities,
        reachability
    )
    notify("risk", "completed", findings)

    return findings
