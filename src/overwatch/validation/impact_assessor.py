"""
Impact Assessor — determines the business impact of confirmed findings.
Answers: what can an attacker do with this access?
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ImpactAssessment:
    finding_id: Optional[int]
    vuln_type: str
    data_access: List[str] = field(default_factory=list)
    privilege_escalation: bool = False
    lateral_movement: bool = False
    data_exfiltration: bool = False
    service_disruption: bool = False
    business_impact: str = "unknown"  # low, medium, high, critical
    attacker_narrative: str = ""
    estimated_cvss_impact: str = ""  # C:H I:H A:H etc.


class ImpactAssessor:
    """
    Assesses what an attacker could actually do with a confirmed vulnerability.
    Uses rule-based assessment, optionally enhanced by Claude.
    """

    # Impact rules by vuln type
    IMPACT_RULES: Dict[str, Dict[str, Any]] = {
        "sql injection": {
            "data_access": ["database tables", "user credentials", "personal data"],
            "privilege_escalation": True,
            "lateral_movement": False,
            "data_exfiltration": True,
            "business_impact": "critical",
            "cvss_c": "H", "cvss_i": "H", "cvss_a": "L",
            "narrative": (
                "An attacker can dump the entire database, obtain plaintext or hashed credentials, "
                "bypass authentication, and potentially execute OS commands via SQL procedures."
            ),
        },
        "cross-site scripting": {
            "data_access": ["session cookies", "stored credentials", "keystrokes"],
            "privilege_escalation": False,
            "lateral_movement": False,
            "data_exfiltration": True,
            "business_impact": "high",
            "cvss_c": "L", "cvss_i": "L", "cvss_a": "N",
            "narrative": (
                "An attacker can steal session cookies to hijack user sessions, "
                "log keystrokes, redirect users to phishing pages, or perform actions on behalf of the victim."
            ),
        },
        "command injection": {
            "data_access": ["all server files", "environment variables", "ssh keys"],
            "privilege_escalation": True,
            "lateral_movement": True,
            "data_exfiltration": True,
            "service_disruption": True,
            "business_impact": "critical",
            "cvss_c": "H", "cvss_i": "H", "cvss_a": "H",
            "narrative": (
                "An attacker has arbitrary code execution on the server. "
                "They can install backdoors, pivot to internal systems, exfiltrate all data, "
                "and completely compromise the server and everything it can reach."
            ),
        },
        "default credentials": {
            "data_access": ["admin panel", "configuration", "all application data"],
            "privilege_escalation": True,
            "lateral_movement": False,
            "data_exfiltration": True,
            "business_impact": "critical",
            "cvss_c": "H", "cvss_i": "H", "cvss_a": "L",
            "narrative": (
                "An attacker has full administrative access to the application. "
                "They can view all user data, modify configuration, disable security controls, "
                "and potentially pivot to other systems using discovered credentials."
            ),
        },
        "idor": {
            "data_access": ["other users' data", "private files", "confidential records"],
            "privilege_escalation": False,
            "lateral_movement": False,
            "data_exfiltration": True,
            "business_impact": "high",
            "cvss_c": "H", "cvss_i": "L", "cvss_a": "N",
            "narrative": (
                "An attacker can access any resource belonging to any user by manipulating object IDs. "
                "This may expose personal data, financial records, or private files for all users."
            ),
        },
        "open port": {
            "data_access": [],
            "privilege_escalation": False,
            "lateral_movement": False,
            "data_exfiltration": False,
            "business_impact": "low",
            "cvss_c": "N", "cvss_i": "N", "cvss_a": "N",
            "narrative": "An exposed port increases attack surface. Further testing required.",
        },
    }

    def __init__(self, claude_client=None) -> None:
        self.claude_client = claude_client

    async def assess(self, finding: dict) -> ImpactAssessment:
        """Assess the impact of a confirmed finding."""
        vuln_type = finding.get("vulnerability_type", "").lower()
        finding_id = finding.get("id")

        # Look for matching rule (case-insensitive substring match)
        matched_rule = None
        for rule_key, rule_data in self.IMPACT_RULES.items():
            if rule_key in vuln_type:
                matched_rule = rule_data
                break

        if matched_rule is None:
            # Generic fallback
            return ImpactAssessment(
                finding_id=finding_id,
                vuln_type=vuln_type,
                business_impact="medium",
                attacker_narrative=(
                    f"The {vuln_type} vulnerability may allow attackers to compromise the target. "
                    "Manual assessment recommended."
                ),
            )

        cvss_c = matched_rule.get("cvss_c", "N")
        cvss_i = matched_rule.get("cvss_i", "N")
        cvss_a = matched_rule.get("cvss_a", "N")

        return ImpactAssessment(
            finding_id=finding_id,
            vuln_type=vuln_type,
            data_access=matched_rule.get("data_access", []),
            privilege_escalation=matched_rule.get("privilege_escalation", False),
            lateral_movement=matched_rule.get("lateral_movement", False),
            data_exfiltration=matched_rule.get("data_exfiltration", False),
            service_disruption=matched_rule.get("service_disruption", False),
            business_impact=matched_rule.get("business_impact", "medium"),
            attacker_narrative=matched_rule.get("narrative", ""),
            estimated_cvss_impact=f"C:{cvss_c}/I:{cvss_i}/A:{cvss_a}",
        )

    async def assess_batch(self, findings: List[dict]) -> List[ImpactAssessment]:
        """Assess a list of findings."""
        results = []
        for finding in findings:
            assessment = await self.assess(finding)
            results.append(assessment)
        return results
