"""
Known vulnerable target scenarios with expected findings.
Used by the Arena and ProficiencyScorer to measure agent performance.
"""
from typing import Any, Dict, List


# Expected findings per training target
DVWA_EXPECTED_FINDINGS: List[Dict[str, Any]] = [
    {
        "vuln_type": "SQL Injection",
        "cwe": "CWE-89",
        "location": "/vulnerabilities/sqli/",
        "parameter": "id",
        "severity": "high",
        "cvss_score": 8.8,
        "mitre": "T1190",
        "description": "Classic error-based and UNION-based SQL injection in the id parameter",
    },
    {
        "vuln_type": "Blind SQL Injection",
        "cwe": "CWE-89",
        "location": "/vulnerabilities/sqli_blind/",
        "parameter": "id",
        "severity": "high",
        "cvss_score": 8.8,
        "mitre": "T1190",
        "description": "Time-based blind SQL injection in the id parameter",
    },
    {
        "vuln_type": "Cross-Site Scripting (Reflected)",
        "cwe": "CWE-79",
        "location": "/vulnerabilities/xss_r/",
        "parameter": "name",
        "severity": "medium",
        "cvss_score": 6.1,
        "mitre": "T1185",
        "description": "Reflected XSS in the name parameter — no filtering",
    },
    {
        "vuln_type": "Cross-Site Scripting (Stored)",
        "cwe": "CWE-79",
        "location": "/vulnerabilities/xss_s/",
        "parameter": "message",
        "severity": "high",
        "cvss_score": 7.4,
        "mitre": "T1185",
        "description": "Stored XSS in the guestbook message field",
    },
    {
        "vuln_type": "Command Injection",
        "cwe": "CWE-78",
        "location": "/vulnerabilities/exec/",
        "parameter": "ip",
        "severity": "critical",
        "cvss_score": 9.8,
        "mitre": "T1059",
        "description": "OS command injection via semicolon in ip parameter",
    },
    {
        "vuln_type": "File Inclusion",
        "cwe": "CWE-22",
        "location": "/vulnerabilities/fi/",
        "parameter": "page",
        "severity": "high",
        "cvss_score": 8.1,
        "mitre": "T1083",
        "description": "Local and remote file inclusion via page parameter",
    },
    {
        "vuln_type": "CSRF",
        "cwe": "CWE-352",
        "location": "/vulnerabilities/csrf/",
        "severity": "medium",
        "cvss_score": 6.5,
        "mitre": "T1185",
        "description": "CSRF on password change — no token validation",
    },
]

JUICESHOP_EXPECTED_FINDINGS: List[Dict[str, Any]] = [
    {
        "vuln_type": "SQL Injection",
        "cwe": "CWE-89",
        "location": "/rest/user/login",
        "parameter": "email",
        "severity": "critical",
        "cvss_score": 9.8,
        "mitre": "T1190",
        "description": "Admin login bypass via ' OR 1=1-- SQL injection",
    },
    {
        "vuln_type": "Broken Object Level Authorization (IDOR)",
        "cwe": "CWE-639",
        "location": "/rest/basket/",
        "severity": "high",
        "cvss_score": 7.5,
        "mitre": "T1078",
        "description": "IDOR on basket endpoint — access other users baskets",
    },
    {
        "vuln_type": "Exposed Admin Interface",
        "cwe": "CWE-284",
        "location": "/#/administration",
        "severity": "high",
        "cvss_score": 7.3,
        "mitre": "T1078",
        "description": "Admin section accessible by any authenticated user",
    },
    {
        "vuln_type": "Sensitive Data Exposure",
        "cwe": "CWE-200",
        "location": "/ftp/",
        "severity": "medium",
        "cvss_score": 5.3,
        "mitre": "T1083",
        "description": "FTP directory with sensitive files accessible without auth",
    },
    {
        "vuln_type": "XSS (DOM-based)",
        "cwe": "CWE-79",
        "location": "/#/search",
        "parameter": "q",
        "severity": "medium",
        "cvss_score": 6.1,
        "mitre": "T1185",
        "description": "DOM-based XSS via search query parameter",
    },
]

SCENARIOS: Dict[str, List[Dict[str, Any]]] = {
    "dvwa": DVWA_EXPECTED_FINDINGS,
    "juiceshop": JUICESHOP_EXPECTED_FINDINGS,
}


def get_expected_findings(target_name: str) -> List[Dict[str, Any]]:
    """Return expected findings for a training target."""
    return SCENARIOS.get(target_name, [])
