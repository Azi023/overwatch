"""
Mentorship module — explains WHY each vulnerability exists in plain language.
Used for the "teaching mode" — helps developers understand root causes.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# Built-in explanations for common vulnerability types
BUILTIN_EXPLANATIONS: Dict[str, Dict[str, str]] = {
    "sql injection": {
        "root_cause": (
            "SQL injection exists because the application constructs SQL queries by concatenating "
            "user-supplied data directly into the query string without validation or parameterization. "
            "The developer treated user input as trusted code rather than untrusted data."
        ),
        "exploitation": (
            "An attacker sends SQL syntax as input (e.g., `' OR 1=1--`). "
            "When concatenated into the query, this changes the query's logic — "
            "bypassing authentication, dumping tables, or executing commands."
        ),
        "fix": (
            "Use parameterized queries (prepared statements) exclusively. "
            "Never concatenate user input into SQL strings. "
            "Example (Python): `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))` "
            "The `%s` is a placeholder — the DB driver safely handles the value separately from the query."
        ),
        "prevention": (
            "1. Always use prepared statements or an ORM that parameterizes by default. "
            "2. Apply principle of least privilege on DB accounts. "
            "3. Use a WAF as defense-in-depth. "
            "4. Enable database auditing. "
            "5. Regularly scan with tools like SQLMap in your CI/CD pipeline."
        ),
    },
    "cross-site scripting": {
        "root_cause": (
            "XSS exists because the application reflects user-supplied content in HTML responses "
            "without sanitizing or encoding it. The browser cannot distinguish between "
            "legitimate page content and attacker-injected scripts."
        ),
        "exploitation": (
            "An attacker injects `<script>alert(document.cookie)</script>` into a field that gets "
            "reflected in the page. When other users load the page, their browser executes the script "
            "in the context of the vulnerable site — allowing cookie theft, keylogging, or UI manipulation."
        ),
        "fix": (
            "Always HTML-encode user data before inserting it into HTML: "
            "`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`. "
            "Use a content security policy (CSP) header to restrict script execution. "
            "For rich text, use a sanitization library (DOMPurify, bleach) — never roll your own."
        ),
        "prevention": (
            "1. Output encoding — always encode output in the right context (HTML, JS, URL, CSS). "
            "2. Content Security Policy (CSP) headers. "
            "3. HttpOnly and Secure flags on cookies. "
            "4. Use modern frameworks that auto-escape templates (React, Vue, Angular). "
            "5. Regular code review for `innerHTML`, `document.write()`, `eval()` usage."
        ),
    },
    "command injection": {
        "root_cause": (
            "Command injection occurs when user input is passed directly to a system shell "
            "without sanitization. The application treats user data as shell commands, "
            "allowing attackers to run arbitrary OS commands."
        ),
        "exploitation": (
            "An attacker adds shell metacharacters (`;`, `|`, `&&`, backticks) to input. "
            "For example: `127.0.0.1; cat /etc/passwd`. "
            "The application runs `ping 127.0.0.1` then `cat /etc/passwd` — "
            "full server compromise with one request."
        ),
        "fix": (
            "Never pass user input to shell commands. "
            "If you must call system tools, use subprocess with a list (not string) and `shell=False`: "
            "`subprocess.run(['ping', '-c', '1', ip], shell=False)`. "
            "Whitelist allowed inputs with strict regex validation before passing to any OS call."
        ),
        "prevention": (
            "1. Never use `shell=True` in subprocess calls. "
            "2. Use language APIs instead of shell commands where possible. "
            "3. Validate and whitelist all inputs before system calls. "
            "4. Run application processes as least-privilege users. "
            "5. Use containerization to limit blast radius."
        ),
    },
    "idor": {
        "root_cause": (
            "Broken Object Level Authorization (IDOR) exists because the application verifies "
            "authentication (are you logged in?) but not authorization (do you own this resource?). "
            "The developer forgot to check that the requesting user has permission to access the specific object."
        ),
        "exploitation": (
            "An attacker changes an object ID in a request: `/api/orders/1234` → `/api/orders/1235`. "
            "If the server returns another user's order without checking ownership, IDOR is confirmed. "
            "This can expose personal data for every user on the platform."
        ),
        "fix": (
            "For every data access, verify the requesting user owns or has permission for that object: "
            "`if order.user_id != current_user.id: raise Forbidden`. "
            "Never rely on obscurity — UUIDs instead of sequential IDs hide IDOR but don't fix it."
        ),
        "prevention": (
            "1. Enforce authorization at every endpoint — authentication alone is not enough. "
            "2. Use server-side object ownership checks for every data retrieval/update/delete. "
            "3. Automated testing: test that user A cannot access user B's resources. "
            "4. Use an authorization framework (e.g., OPA, Casbin) for consistent policy enforcement. "
            "5. Log access to sensitive objects for anomaly detection."
        ),
    },
    "default credentials": {
        "root_cause": (
            "Default credentials remain in production because the development team "
            "shipped with test/vendor credentials and the deployment process lacks "
            "credential rotation requirements or hardening checks."
        ),
        "exploitation": (
            "An attacker tries well-known default username/password combinations "
            "(admin/admin, admin/password, root/root) against login endpoints. "
            "Successful login grants full administrative access with no further exploitation needed."
        ),
        "fix": (
            "Force credential change on first login. "
            "Prohibit known-weak passwords in your password policy. "
            "Include credential rotation in your deployment checklist and CI/CD security gates."
        ),
        "prevention": (
            "1. Never ship with default credentials — generate random secrets at deploy time. "
            "2. Implement account lockout after N failed attempts. "
            "3. Require MFA on all administrative interfaces. "
            "4. Regular credential audits — scan for default creds in your own systems. "
            "5. Monitor login attempts for brute-force patterns."
        ),
    },
}


class MentorshipExplainer:
    """
    Explains WHY each vulnerability exists, HOW to exploit it, and HOW to fix it.
    Uses built-in explanations first; falls back to Claude for novel vuln types.
    """

    def __init__(self, claude_client=None) -> None:
        self.claude_client = claude_client

    async def explain(self, finding: dict) -> Dict[str, str]:
        """
        Generate a mentorship explanation for a finding.

        Returns dict with: root_cause, exploitation, fix, prevention.
        """
        vuln_type = finding.get("vulnerability_type", "").lower()

        # Try built-in first
        for key, explanation in BUILTIN_EXPLANATIONS.items():
            if key in vuln_type:
                return explanation

        # Fall back to Claude if available
        if self.claude_client:
            return await self._explain_with_claude(finding)

        # Generic fallback
        return {
            "root_cause": f"The {vuln_type} vulnerability exists due to insufficient input validation or access control.",
            "exploitation": "An attacker can leverage this vulnerability to compromise the target.",
            "fix": "Consult OWASP guidelines for remediation of this vulnerability type.",
            "prevention": "Implement secure coding practices and regular security reviews.",
        }

    async def _explain_with_claude(self, finding: dict) -> Dict[str, str]:
        """Use Claude to generate explanation for novel vulnerability types."""
        try:
            system = (
                "You are a security mentor. Explain vulnerabilities in plain language "
                "that helps developers understand root causes and fix them. "
                "Be educational, not preachy. Output JSON only."
            )
            prompt = (
                f"Explain this security finding:\n"
                f"Type: {finding.get('vulnerability_type')}\n"
                f"Description: {finding.get('description')}\n"
                f"URL: {finding.get('url')}\n\n"
                f"Return JSON: {{root_cause, exploitation, fix, prevention}}"
            )
            response = await self.claude_client.complete(
                task_type="classification",
                messages=[{"role": "user", "content": prompt}],
                system_prompt=system,
            )
            if response.content:
                import json
                parsed = self.claude_client.extract_json(response.content)
                if parsed:
                    return parsed
        except Exception as exc:
            logger.warning("Claude mentorship explanation failed: %s", exc)

        return {
            "root_cause": f"Analysis of {finding.get('vulnerability_type')} requires manual review.",
            "exploitation": "See vulnerability description for exploitation details.",
            "fix": "Consult OWASP and vendor documentation for remediation guidance.",
            "prevention": "Implement defence-in-depth and regular security testing.",
        }
