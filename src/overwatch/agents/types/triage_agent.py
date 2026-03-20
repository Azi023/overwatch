"""
TriageAgent - validates and de-duplicates unconfirmed findings.

Takes a list of unvalidated findings and independently re-tests each one to
confirm real vulnerabilities or mark false positives. Follows the principle
that no finding is reported without a reproducible proof of concept.
"""
from __future__ import annotations

import asyncio
import logging
import urllib.request
import urllib.error
import ssl
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urljoin, urlparse

from ..base_agent import BaseAgent, Hypothesis, HypothesisResult

logger = logging.getLogger(__name__)


class TriageAgent(BaseAgent):
    """
    Triage agent that validates unconfirmed findings.

    Input: a list of finding dicts placed in working_memory under the key
    "unvalidated_findings" OR passed via scope_subset["findings"].

    Output: each finding is marked as either validated=True or
    false_positive=True, and the updated findings are in the agent result.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._unvalidated_findings: List[dict] = []
        self._validation_results: Dict[str, str] = {}  # finding_id → outcome

    # ─────────────────────── Abstract Methods ────────────────────

    async def orient(self) -> None:
        """
        Load unvalidated findings from scope_subset or working memory.

        Findings may be injected via scope_subset["findings"] (from coordinator)
        or pre-loaded into working_memory["unvalidated_findings"] (from prior agent).
        """
        # Priority: scope_subset > working_memory
        findings_from_scope = self.scope_subset.get("findings", [])
        if findings_from_scope:
            self._unvalidated_findings = list(findings_from_scope)
        else:
            self._unvalidated_findings = list(
                self.working_memory.get("unvalidated_findings", [])
            )

        self.working_memory.set(
            "unvalidated_findings", self._unvalidated_findings
        )
        self.working_memory.set(
            "total_to_validate", len(self._unvalidated_findings)
        )
        self.working_memory.set("validated_count", 0)

        logger.info(
            "TriageAgent %s: oriented — %d findings to validate",
            self.agent_id,
            len(self._unvalidated_findings),
        )

    async def observe(self) -> List[dict]:
        """
        Return the current list of unvalidated findings as observations.

        Called once per loop. Marks objective as met when all findings have
        been processed.
        """
        if self.working_memory.get("findings_loaded", False):
            return []

        self.working_memory.set("findings_loaded", True)

        if not self._unvalidated_findings:
            self.working_memory.set("objective_met", True)
            logger.info(
                "TriageAgent %s: no findings to validate — objective met.",
                self.agent_id,
            )
            return []

        return [
            {"type": "unvalidated_finding", "data": f}
            for f in self._unvalidated_findings
        ]

    async def hypothesize(self) -> List[Hypothesis]:
        """
        Produce one validation hypothesis per unvalidated finding.

        Already validated/fp-marked findings are skipped.
        """
        hypotheses: List[Hypothesis] = []
        processed_ids = set(self._validation_results.keys())

        for finding in self._unvalidated_findings:
            finding_id = str(
                finding.get("id")
                or finding.get("finding_id")
                or id(finding)
            )

            if finding_id in processed_ids:
                continue

            vuln_type = finding.get("vulnerability_type", "unknown")
            url = finding.get("url", "")
            description = finding.get("description", "")
            title = finding.get("title", vuln_type)

            hypothesis = Hypothesis(
                description=f"Validate finding: {title} at {url or 'N/A'}",
                confidence=finding.get("confidence", 0.5),
                target=url or finding.get("host", "unknown"),
                action=f"validate_{vuln_type.lower().replace(' ', '_')}",
                parameters={
                    "finding_id": finding_id,
                    "finding": finding,
                    "vuln_type": vuln_type,
                    "url": url,
                    "description": description,
                },
                vuln_type=vuln_type,
            )
            hypotheses.append(hypothesis)

        # When all findings have been processed, signal objective complete
        if not hypotheses and self._validation_results:
            self.working_memory.set("objective_met", True)

        return hypotheses

    async def execute_hypothesis(self, hypothesis: Hypothesis) -> HypothesisResult:
        """
        Re-test a single finding to confirm or refute it.

        The validation strategy is selected based on vulnerability type:
          - XSS → re-send the original request and check for reflection
          - SQL injection → resend and look for error signatures
          - IDOR → replay with manipulated IDs
          - Generic → HTTP probe + response analysis
        """
        finding: dict = hypothesis.parameters.get("finding", {})
        finding_id: str = hypothesis.parameters.get("finding_id", str(id(finding)))
        vuln_type: str = hypothesis.parameters.get("vuln_type", "unknown")
        url: str = hypothesis.parameters.get("url", "")

        try:
            outcome, evidence, confidence = await self._validate_finding(
                finding, vuln_type, url
            )
        except Exception as exc:
            logger.error(
                "TriageAgent %s: validation error for finding %s: %s",
                self.agent_id,
                finding_id,
                exc,
            )
            outcome = "error"
            evidence = {"error": str(exc)}
            confidence = 0.2

        # Record the validation result
        self._validation_results[finding_id] = outcome

        # Update validated/false_positive counters in working memory
        validated_count = self.working_memory.get("validated_count", 0)
        self.working_memory.set("validated_count", validated_count + 1)

        # Build the updated finding dict
        updated_finding = {
            **finding,
            "finding_id": finding_id,
            "validated": outcome == "confirmed",
            "false_positive": outcome == "false_positive",
            "validation_result": outcome,
            "validation_evidence": evidence,
            "confidence": confidence,
        }

        if outcome == "confirmed":
            return HypothesisResult(
                hypothesis=hypothesis,
                outcome="confirmed",
                evidence=evidence,
                updated_confidence=confidence,
                finding=updated_finding,
            )
        else:
            return HypothesisResult(
                hypothesis=hypothesis,
                outcome=outcome,
                evidence=evidence,
                updated_confidence=confidence,
                finding=None,
            )

    # ─────────────────────── Validation Logic ────────────────────

    async def _validate_finding(
        self, finding: dict, vuln_type: str, url: str
    ) -> tuple[str, dict, float]:
        """
        Select and run an appropriate validation strategy.

        Returns (outcome, evidence_dict, confidence_float).
        """
        vuln_lower = vuln_type.lower()

        if "xss" in vuln_lower or "cross-site" in vuln_lower:
            return await self._validate_xss(finding, url)
        elif "sql" in vuln_lower or "injection" in vuln_lower:
            return await self._validate_sqli(finding, url)
        elif "idor" in vuln_lower or "access" in vuln_lower:
            return await self._validate_idor(finding, url)
        else:
            return await self._validate_generic(finding, url)

    async def _validate_xss(
        self, finding: dict, url: str
    ) -> tuple[str, dict, float]:
        """Validate XSS by replaying the original payload and checking reflection."""
        payload = finding.get("proof_of_concept") or finding.get(
            "evidence", {}
        ).get("payload", "<script>alert(1)</script>")

        parameter = finding.get("parameter", "")
        evidence: dict = {"method": "xss_reflection_check", "url": url}

        if not url:
            return "inconclusive", {**evidence, "reason": "no URL to test"}, 0.3

        # Build test URL with payload in the reported parameter
        test_url = url
        if parameter and "?" in url:
            # Replace the parameter value with the payload
            parsed = urlparse(url)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{parameter}={urllib.request.quote(payload)}"

        try:
            loop = asyncio.get_event_loop()
            response_text, status_code = await loop.run_in_executor(
                None, self._http_get, test_url
            )

            evidence["status_code"] = status_code
            # Check if the payload appears unencoded in the response
            if payload in response_text:
                evidence["reflection_found"] = True
                evidence["payload"] = payload
                return "confirmed", evidence, 0.85
            elif urllib.request.quote(payload) not in response_text:
                evidence["reflection_found"] = False
                return "false_positive", evidence, 0.8
            else:
                evidence["reflection_found"] = "encoded"
                return "inconclusive", evidence, 0.4

        except Exception as exc:
            evidence["error"] = str(exc)
            return "error", evidence, 0.2

    async def _validate_sqli(
        self, finding: dict, url: str
    ) -> tuple[str, dict, float]:
        """Validate SQL injection by testing error-based and boolean conditions."""
        evidence: dict = {"method": "sqli_validation", "url": url}

        if not url:
            return "inconclusive", {**evidence, "reason": "no URL"}, 0.3

        parameter = finding.get("parameter", "")
        # Simple error-based test
        error_payload = "'"
        test_url = url
        if parameter:
            parsed = urlparse(url)
            test_url = (
                f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                f"?{parameter}={urllib.request.quote(error_payload)}"
            )

        sql_error_patterns = [
            "you have an error in your sql syntax",
            "mysql_fetch_array",
            "ora-01756",
            "sqlite3.operationalerror",
            "unclosed quotation mark",
            "incorrect syntax near",
            "pg::syntaxerror",
        ]

        try:
            loop = asyncio.get_event_loop()
            response_text, status_code = await loop.run_in_executor(
                None, self._http_get, test_url
            )
            response_lower = response_text.lower()
            evidence["status_code"] = status_code

            matched_patterns = [p for p in sql_error_patterns if p in response_lower]
            if matched_patterns:
                evidence["error_patterns_found"] = matched_patterns
                return "confirmed", evidence, 0.9
            else:
                evidence["error_patterns_found"] = []
                return "false_positive", evidence, 0.7

        except Exception as exc:
            evidence["error"] = str(exc)
            return "error", evidence, 0.2

    async def _validate_idor(
        self, finding: dict, url: str
    ) -> tuple[str, dict, float]:
        """Validate IDOR by checking if a modified ID returns different user data."""
        evidence: dict = {"method": "idor_validation", "url": url}

        if not url:
            return "inconclusive", {**evidence, "reason": "no URL"}, 0.3

        # Extract numeric ID from the URL (simple heuristic)
        import re
        id_match = re.search(r"/(\d+)(?:/|$|\?)", url)
        if not id_match:
            evidence["reason"] = "no numeric ID found in URL"
            return "inconclusive", evidence, 0.3

        original_id = int(id_match.group(1))
        modified_id = original_id + 1

        original_url = url
        modified_url = url.replace(
            f"/{original_id}", f"/{modified_id}", 1
        )

        try:
            loop = asyncio.get_event_loop()

            original_resp, original_status = await loop.run_in_executor(
                None, self._http_get, original_url
            )
            modified_resp, modified_status = await loop.run_in_executor(
                None, self._http_get, modified_url
            )

            evidence["original_status"] = original_status
            evidence["modified_status"] = modified_status
            evidence["original_id"] = original_id
            evidence["modified_id"] = modified_id

            # Both return 200 with different non-empty content → likely IDOR
            if (
                original_status == 200
                and modified_status == 200
                and original_resp != modified_resp
                and len(modified_resp) > 100
            ):
                evidence["content_differs"] = True
                return "confirmed", evidence, 0.75
            elif modified_status in (403, 401):
                # Server correctly rejects the modified ID
                return "false_positive", evidence, 0.8
            else:
                return "inconclusive", evidence, 0.4

        except Exception as exc:
            evidence["error"] = str(exc)
            return "error", evidence, 0.2

    async def _validate_generic(
        self, finding: dict, url: str
    ) -> tuple[str, dict, float]:
        """Generic validation: HTTP probe the reported URL and check it's reachable."""
        evidence: dict = {"method": "generic_probe", "url": url}

        if not url:
            evidence["reason"] = "no URL to probe"
            return "inconclusive", evidence, 0.3

        try:
            loop = asyncio.get_event_loop()
            _body, status_code = await loop.run_in_executor(
                None, self._http_get, url
            )
            evidence["status_code"] = status_code
            # If the target is reachable, we can't confirm or deny without more context
            return "inconclusive", evidence, 0.4

        except Exception as exc:
            evidence["error"] = str(exc)
            return "error", evidence, 0.2

    # ─────────────────────── HTTP Helper ─────────────────────────

    @staticmethod
    def _http_get(url: str) -> tuple[str, int]:
        """
        Blocking HTTP GET request.

        Returns (response_body_text, status_code).
        Raises on network errors.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Overwatch-Triage/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                body = resp.read(32768).decode(errors="replace")
                return body, resp.status
        except urllib.error.HTTPError as exc:
            return exc.read(4096).decode(errors="replace"), exc.code
