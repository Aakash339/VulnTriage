
from collections.abc import Callable
from typing import Any

from agents.dependency_agent import parse_dependencies
from agents.vulnerability_agent import scan_vulnerabilities
from agents.reachability_agent import check_reachability
from agents.remediation_agent import generate_remediation


def run_vulntriage(
    project_path: str,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> list:
    """Run the existing analysis sequence, optionally reporting stage events.

    The callback receives ``started`` and ``completed`` events for each actual
    stage. Completed events carry that stage's real output for UI reporting.
    Omitting the callback preserves the original API behavior and return value.
    """
    def notify(stage: str, status: str, data: Any = None) -> None:
        if progress_callback is not None:
            event = {"stage": stage, "status": status}
            if status == "completed":
                event["data"] = data
            progress_callback(event)

    # Step 1: Extract project dependencies
    notify("dependencies", "started")
    dependencies = parse_dependencies(project_path)
    notify("dependencies", "completed", dependencies)

    # Step 2: Find known vulnerabilities
    notify("osv", "started")
    vulnerabilities = scan_vulnerabilities(dependencies)
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
