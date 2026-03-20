"""
MITRE ATT&CK technique mapping for Overwatch V2.

Maps CWE identifiers and vulnerability type strings to ATT&CK technique IDs,
providing human-readable descriptions and remediation guidance.
"""
from __future__ import annotations

from typing import Dict, List, Optional


# ──────────────────────────── Technique metadata ────────────────────────────

_TECHNIQUE_DESCRIPTIONS: Dict[str, str] = {
    "T1190": (
        "Exploit Public-Facing Application — adversaries may attempt to take advantage "
        "of a weakness in an internet-facing system to gain initial access."
    ),
    "T1185": (
        "Browser Session Hijacking — adversaries may take advantage of security "
        "vulnerabilities to steal session cookies or session tokens."
    ),
    "T1078": (
        "Valid Accounts — adversaries may obtain and abuse credentials of existing "
        "accounts as a means of gaining access."
    ),
    "T1083": (
        "File and Directory Discovery — adversaries may enumerate files and directories "
        "or search in specific locations of a host or network share."
    ),
    "T1090": (
        "Proxy — adversaries may use a connection proxy to direct network traffic between "
        "systems or act as an intermediary for the network communications of an adversary."
    ),
    "T1059": (
        "Command and Scripting Interpreter — adversaries may abuse command and script "
        "interpreters to execute commands, scripts, or binaries."
    ),
    "T1110": (
        "Brute Force — adversaries may use brute force techniques to gain access to "
        "accounts when passwords are unknown or when password hashes are obtained."
    ),
    "T1552": (
        "Unsecured Credentials — adversaries may search compromised systems to find "
        "and obtain insecurely stored credentials."
    ),
    "T1027": (
        "Obfuscated Files or Information — adversaries may attempt to make an executable "
        "or file difficult to discover or analyze by encrypting, encoding, or otherwise "
        "obfuscating its contents."
    ),
    "T1055": (
        "Process Injection — adversaries may inject code into processes in order to evade "
        "process-based defenses as well as possibly elevate privileges."
    ),
}

_TECHNIQUE_MITIGATIONS: Dict[str, str] = {
    "T1190": (
        "Apply patches and updates promptly. Use a WAF. Implement network segmentation. "
        "Regularly audit public-facing applications for vulnerabilities."
    ),
    "T1185": (
        "Use HTTPOnly and Secure cookie flags. Implement SameSite cookie attribute. "
        "Use Content-Security-Policy headers. Regenerate session tokens after login."
    ),
    "T1078": (
        "Enforce MFA on all accounts. Use strong unique passwords. Audit account usage. "
        "Implement least-privilege principles."
    ),
    "T1083": (
        "Restrict read permissions to necessary files and directories. "
        "Use access controls and audit logging."
    ),
    "T1090": (
        "Monitor network traffic for unexpected proxy activity. "
        "Block connections to known anonymisation services."
    ),
    "T1059": (
        "Restrict execution of scripting interpreters. Implement application allowlisting. "
        "Monitor command-line arguments for suspicious patterns."
    ),
    "T1110": (
        "Enforce account lockout policies. Implement rate limiting on authentication endpoints. "
        "Use CAPTCHA and MFA."
    ),
    "T1552": (
        "Do not store credentials in plaintext. Use secrets managers. "
        "Audit file permissions on configuration files."
    ),
    "T1027": (
        "Use endpoint detection tools that can deobfuscate content. "
        "Monitor for unusual processes spawning interpreters."
    ),
    "T1055": (
        "Use endpoint protection with process injection detection. "
        "Enable exploit mitigation techniques (DEP, ASLR)."
    ),
}


# ──────────────────────────── Mapper ────────────────────────────

class MITREMapper:
    """
    Map vulnerability findings to MITRE ATT&CK techniques.

    Usage::

        mapper = MITREMapper()
        techniques = mapper.map_finding({
            "vulnerability_type": "sqli",
            "cwe_ids": ["CWE-89"],
        })
        print(techniques)   # ['T1190']
    """

    # CWE → ATT&CK technique IDs
    CWE_TO_ATTACK: Dict[str, List[str]] = {
        "CWE-89":  ["T1190"],          # SQL injection
        "CWE-79":  ["T1185"],          # XSS
        "CWE-639": ["T1078"],          # IDOR / auth bypass via object reference
        "CWE-287": ["T1078"],          # Improper authentication
        "CWE-22":  ["T1083"],          # Path traversal / file disclosure
        "CWE-611": ["T1190"],          # XML External Entity (XXE)
        "CWE-918": ["T1090"],          # Server-Side Request Forgery (SSRF)
        "CWE-78":  ["T1059"],          # OS command injection
        "CWE-521": ["T1110"],          # Weak password requirements
        "CWE-312": ["T1552"],          # Cleartext storage of sensitive info
        "CWE-319": ["T1552"],          # Cleartext transmission
        "CWE-352": ["T1185"],          # CSRF
        "CWE-502": ["T1059"],          # Deserialization of untrusted data
        "CWE-94":  ["T1059"],          # Code injection
        "CWE-601": ["T1185"],          # Open redirect
    }

    # Vulnerability type string → CWE-ID
    VULN_TYPE_TO_CWE: Dict[str, str] = {
        "sqli":              "CWE-89",
        "sql_injection":     "CWE-89",
        "xss":               "CWE-79",
        "cross_site_scripting": "CWE-79",
        "idor":              "CWE-639",
        "auth_bypass":       "CWE-287",
        "path_traversal":    "CWE-22",
        "lfi":               "CWE-22",
        "rfi":               "CWE-22",
        "xxe":               "CWE-611",
        "ssrf":              "CWE-918",
        "rce":               "CWE-78",
        "command_injection": "CWE-78",
        "os_injection":      "CWE-78",
        "weak_password":     "CWE-521",
        "cleartext_storage": "CWE-312",
        "cleartext_transmission": "CWE-319",
        "csrf":              "CWE-352",
        "deserialization":   "CWE-502",
        "code_injection":    "CWE-94",
        "open_redirect":     "CWE-601",
    }

    def map_finding(self, finding: dict) -> List[str]:
        """
        Map a finding dict to a list of ATT&CK technique IDs.

        The finding dict may contain:
          - ``vulnerability_type`` (str)
          - ``cwe_ids`` (list[str])

        Techniques are deduplicated while preserving insertion order.
        """
        techniques: List[str] = []
        seen: set = set()

        def _add(t_id: str) -> None:
            if t_id not in seen:
                seen.add(t_id)
                techniques.append(t_id)

        # 1. Map explicit CWE IDs
        for cwe in finding.get("cwe_ids", []):
            cwe_norm = self._normalise_cwe(cwe)
            for technique in self.CWE_TO_ATTACK.get(cwe_norm, []):
                _add(technique)

        # 2. Map vulnerability type string
        vuln_type = (finding.get("vulnerability_type") or "").lower().strip()
        cwe_from_type = self.VULN_TYPE_TO_CWE.get(vuln_type)
        if cwe_from_type:
            for technique in self.CWE_TO_ATTACK.get(cwe_from_type, []):
                _add(technique)

        # 3. Already-mapped techniques in the finding itself
        for technique in finding.get("mitre_techniques", []):
            _add(str(technique))

        return techniques

    def get_technique_description(self, technique_id: str) -> str:
        """Return a human-readable description for the given ATT&CK technique."""
        return _TECHNIQUE_DESCRIPTIONS.get(
            technique_id,
            f"ATT&CK Technique {technique_id} — see https://attack.mitre.org/techniques/{technique_id}/",
        )

    def get_mitigation(self, technique_id: str) -> str:
        """Return remediation guidance for the given ATT&CK technique."""
        return _TECHNIQUE_MITIGATIONS.get(
            technique_id,
            "Refer to the MITRE ATT&CK mitigation pages for this technique.",
        )

    # ── Private helpers ───────────────────────────────────────────

    @staticmethod
    def _normalise_cwe(cwe: str) -> str:
        """Normalise 'CWE-89', '89', 'cwe89' → 'CWE-89'."""
        cwe = cwe.strip().upper().replace(" ", "")
        if cwe.startswith("CWE-"):
            return cwe
        if cwe.startswith("CWE"):
            return "CWE-" + cwe[3:]
        # Plain number
        if cwe.isdigit():
            return "CWE-" + cwe
        return cwe
