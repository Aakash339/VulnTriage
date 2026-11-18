
from typing import TypedDict, Literal


# 1. Dependency Agent Output
class Dependency(TypedDict):
    name: str
    version: str
    ecosystem: Literal["PyPI", "npm"]
    source_file: str


# 2. Vulnerability Agent Output
class Vulnerability(TypedDict):
    package: str
    ecosystem: str
    installed_version: str
    vulnerability_id: str
    summary: str
    severity: str
    fixed_versions: list[str]
    references: list[str]


# 3. Reachability Agent Output
class ReachabilityResult(TypedDict):
    package: str
    status: Literal["USED", "NOT_FOUND", "UNKNOWN"]
    evidence: list[str]


# 4. Remediation Agent Output
class RemediationFinding(TypedDict):
    package: str
    vulnerability_id: str
    severity: str
    reachability: str
    priority: str
    installed_version: str
    recommended_version: str
    recommendation: str
    risk_score: int
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    risk_factors: list[str]
    risk_explanation: str
