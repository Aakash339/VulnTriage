"""Deterministic, explainable heuristic risk scoring for OSV findings.

Weights total 100 points: severity (50), reachability (30), fixed-version
availability (10), and evidence confidence (10). The model is triage guidance,
not a probability of exploitation or a replacement for advisory review.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


# Severity uses descending 10-point steps (50/40/30/20) so every named band has
# a distinct, visible contribution. Unknown severity uses a nonzero midpoint.
_SEVERITY_POINTS = {
    "CRITICAL": 50,
    "HIGH": 40,
    "MEDIUM": 30,
    "LOW": 20,
}
# A detected import contributes the full 30. NOT_FOUND retains 20 because a
# static import search cannot prove safety; UNKNOWN retains 25 to preserve risk.
_REACHABILITY_POINTS = {"USED": 30, "NOT_FOUND": 20, "UNKNOWN": 25}
# These are presentation bands for the weighted score, not exploitability claims.
_RISK_LEVELS = ((80, "CRITICAL"), (60, "HIGH"), (35, "MEDIUM"), (0, "LOW"))


def _record(value: Any) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _risk_level(score: int) -> str:
    for threshold, level in _RISK_LEVELS:
        if score >= threshold:
            return level
    return "LOW"


def calculate_risk(vulnerability: dict, reachability: dict) -> dict:
    """Calculate a 0–100 risk score and return its scoring evidence.

    Missing or malformed fields receive conservative uncertainty contributions
    rather than being interpreted as evidence of safety. Fixed-version data is
    read only from ``vulnerability['fixed_versions']`` (the OSV result).
    """
    vuln = _record(vulnerability)
    reach = _record(reachability)

    raw_severity = _text(vuln.get("severity")).upper()
    severity = raw_severity if raw_severity in _SEVERITY_POINTS else "UNKNOWN"
    # Unknown severity receives 25/50: below known HIGH, but not zero risk.
    severity_points = _SEVERITY_POINTS.get(severity, 25)

    raw_reachability = _text(reach.get("status")).upper()
    status = raw_reachability if raw_reachability in _REACHABILITY_POINTS else "UNKNOWN"
    reachability_points = _REACHABILITY_POINTS[status]

    raw_fixed_versions = vuln.get("fixed_versions")
    if isinstance(raw_fixed_versions, (list, tuple)):
        fixed_versions = [version.strip() for version in raw_fixed_versions if isinstance(version, str) and version.strip()]
        if fixed_versions:
            # A fix reported by OSV improves remediation options, reducing this risk component.
            fix_points = 0
            fix_detail = f"OSV reports fixed version(s) {', '.join(fixed_versions)} (0/10 unresolved-fix points)."
        else:
            fix_points = 10
            fix_detail = "OSV reports no fixed version for this finding (10/10 unresolved-fix points)."
    else:
        fix_points = 5
        fix_detail = "Fixed-version data is missing or malformed (5/10 uncertainty points)."

    evidence_value = reach.get("evidence")
    has_import_evidence = (
        isinstance(evidence_value, (list, tuple))
        and any(isinstance(item, str) and item.strip() for item in evidence_value)
    )
    if status == "USED" and has_import_evidence:
        confidence_points = 10
        confidence_detail = "Reachability includes import evidence (10/10 evidence-confidence points)."
    elif status == "NOT_FOUND":
        # Absence of a detected import is weaker evidence and must not make risk zero.
        confidence_points = 6
        confidence_detail = "No import was detected; absence is not proof of safety (6/10 points)."
    elif status == "USED":
        confidence_points = 6
        confidence_detail = "USED status lacks evidence details (6/10 evidence-confidence points)."
    else:
        confidence_points = 5
        confidence_detail = "Reachability is unknown or incomplete (5/10 evidence-confidence points)."

    score = max(0, min(100, severity_points + reachability_points + fix_points + confidence_points))
    risk_level = _risk_level(score)
    risk_factors = [
        f"Severity {severity}: {severity_points}/50 points.",
        f"Reachability {status}: {reachability_points}/30 points.",
        fix_detail,
        confidence_detail,
    ]
    explanation = (
        f"Risk score {score}/100 ({risk_level}) is based on these factors: "
        f"{' '.join(risk_factors)} "
        "This is a triage heuristic; import detection does not prove exploitability, "
        "and NOT_FOUND does not prove the dependency is safe."
    )
    return {
        "risk_score": score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "risk_explanation": explanation,
    }
