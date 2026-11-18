
from agents.dependency_agent import parse_dependencies
from agents.vulnerability_agent import scan_vulnerabilities
from agents.reachability_agent import check_reachability
from agents.remediation_agent import generate_remediation


def run_vulntriage(project_path: str) -> list:

    # Step 1: Extract project dependencies
    dependencies = parse_dependencies(project_path)

    # Step 2: Find known vulnerabilities
    vulnerabilities = scan_vulnerabilities(dependencies)

    # Step 3: Check basic source-code reachability
    reachability = check_reachability(
        project_path,
        vulnerabilities
    )

    # Step 4: Prioritise and recommend fixes
    findings = generate_remediation(
        vulnerabilities,
        reachability
    )

    return findings
