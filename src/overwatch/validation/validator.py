"""
Deterministic exploit validation — the "No PoC, no report" gate.

Every finding produced by the scanner or AI agents must pass through the
Validator before it is promoted to a confirmed finding.  The Validator:

1. Re-executes the exact payload against the live target.
2. Compares the response to the expected indicators.
3. Tracks confidence across multiple retests.
4. Returns a ValidationResult that downstream code (reporting, FP eliminator)
   can act on.

Design principle: Validator logic is *deterministic*.  Claude is NOT used
here — that prevents the LLM from "confirming" findings by hallucination.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Indicators used for response-based confirmation
# ------------------------------------------------------------------

_SQLI_ERROR_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"pg::syntaxerror",
        r"ora-\d{5}",
        r"microsoft ole db provider for sql server",
        r"sqlite_error",
        r"syntax error.*sql",
        r"invalid query",
        r"unexpected end of sql command",
    ]
]

_XSS_REFLECTION_PATTERN = re.compile(r"<script>alert\(1\)</script>", re.IGNORECASE)

# Minimum fraction of retests that must succeed for high confidence
_HIGH_CONFIDENCE_THRESHOLD = 0.8
_MEDIUM_CONFIDENCE_THRESHOLD = 0.5


@dataclass
class ValidationResult:
    """
    Result of validating a single finding.

    Attributes:
        finding_id:      Opaque ID matching the finding being validated.
        is_valid:        True when at least one retest confirmed the finding.
        confidence:      Float [0.0, 1.0] — fraction of retests that confirmed.
        evidence:        Request/response pairs captured during validation.
        retest_count:    Number of independent retests attempted.
        validator_notes: Human-readable explanation of the verdict.
    """

    finding_id: str
    is_valid: bool
    confidence: float
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    retest_count: int = 0
    validator_notes: str = ""


class Validator:
    """
    Deterministic re-testing engine for pentesting findings.

    Each vulnerability type has a dedicated ``_retest_*`` method that
    knows what a true positive looks like.  The public ``validate_finding``
    dispatcher routes to the right method based on ``finding["type"]``.
    """

    def __init__(self, http_client, claude_client=None, scope_enforcer=None) -> None:
        """
        Args:
            http_client:    An HttpClient instance for making requests.
            claude_client:  Unused in deterministic validation; reserved for
                            future evidence summarisation.
            scope_enforcer: Optional scope check before retesting.
        """
        self._http = http_client
        self._claude = claude_client  # reserved, not used in deterministic path
        self._scope_enforcer = scope_enforcer

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def validate_finding(self, finding: Dict[str, Any]) -> ValidationResult:
        """
        Validate a single finding by re-executing the exploit payload.

        Expected finding keys:
            id (str)       – opaque finding identifier
            type (str)     – "sqli" | "xss" | "idor" | "generic"
            url (str)      – vulnerable URL
            parameter (str)– affected query/body parameter
            payload (str)  – the payload that triggered the finding
            original_id    – (IDOR only) the legitimate object ID

        Returns:
            ValidationResult with is_valid and confidence populated.
        """
        finding_id = str(finding.get("id", "unknown"))
        vuln_type = (finding.get("type") or "generic").lower()

        logger.info(
            "Validating finding %s (type=%s, url=%s)",
            finding_id,
            vuln_type,
            finding.get("url", ""),
        )

        url = finding.get("url", "")
        parameter = finding.get("parameter", "")
        payload = finding.get("payload", "")

        if not url:
            return ValidationResult(
                finding_id=finding_id,
                is_valid=False,
                confidence=0.0,
                validator_notes="Cannot validate: no URL in finding",
            )

        if self._scope_enforcer and not self._scope_enforcer.is_in_scope(url):
            return ValidationResult(
                finding_id=finding_id,
                is_valid=False,
                confidence=0.0,
                validator_notes="Cannot validate: URL is out of scope",
            )

        # Dispatch to type-specific validator
        retest_results: List[bool] = []
        evidence: List[Dict[str, Any]] = []

        retest_count = 3  # Run three independent retests for confidence

        for attempt in range(1, retest_count + 1):
            try:
                if vuln_type == "sqli":
                    confirmed, ev = await self._retest_sqli(url, parameter, payload)
                elif vuln_type == "xss":
                    confirmed, ev = await self._retest_xss(url, parameter, payload)
                elif vuln_type == "idor":
                    original_id = finding.get("original_id")
                    test_id = finding.get("test_id") or finding.get("modified_id")
                    confirmed, ev = await self._retest_idor(url, original_id, test_id)
                else:
                    confirmed, ev = await self._retest_generic(url, parameter, payload)

                retest_results.append(confirmed)
                evidence.append({"attempt": attempt, "confirmed": confirmed, **ev})

            except Exception as exc:
                logger.exception("Retest attempt %d failed for finding %s", attempt, finding_id)
                retest_results.append(False)
                evidence.append({"attempt": attempt, "confirmed": False, "error": str(exc)})

        success_count = sum(retest_results)
        confidence = success_count / retest_count if retest_count > 0 else 0.0
        is_valid = success_count > 0

        if confidence >= _HIGH_CONFIDENCE_THRESHOLD:
            notes = f"HIGH CONFIDENCE: {success_count}/{retest_count} retests confirmed."
        elif confidence >= _MEDIUM_CONFIDENCE_THRESHOLD:
            notes = f"MEDIUM CONFIDENCE: {success_count}/{retest_count} retests confirmed. Manual review advised."
        elif is_valid:
            notes = f"LOW CONFIDENCE: {success_count}/{retest_count} retests confirmed. Likely false positive."
        else:
            notes = f"NOT CONFIRMED: 0/{retest_count} retests triggered the finding."

        logger.info(
            "Finding %s validation complete — valid=%s, confidence=%.2f",
            finding_id,
            is_valid,
            confidence,
        )

        return ValidationResult(
            finding_id=finding_id,
            is_valid=is_valid,
            confidence=confidence,
            evidence=evidence,
            retest_count=retest_count,
            validator_notes=notes,
        )

    # ------------------------------------------------------------------
    # Type-specific retests
    # ------------------------------------------------------------------

    async def _retest_sqli(
        self,
        url: str,
        parameter: str,
        payload: str,
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Re-test for SQL injection by injecting the payload and inspecting the
        response body for known database error strings.

        Returns (confirmed: bool, evidence: dict).
        """
        if not parameter or not payload:
            return False, {"reason": "Missing parameter or payload"}

        # Build a GET request with the injection payload in the query string
        params = {parameter: payload}
        response = await self._http.get(url, params=params)

        body = response.body or ""
        matched_pattern = None
        for pattern in _SQLI_ERROR_PATTERNS:
            m = pattern.search(body)
            if m:
                matched_pattern = m.group(0)
                break

        confirmed = matched_pattern is not None

        return confirmed, {
            "method": "GET",
            "parameter": parameter,
            "payload": payload,
            "status_code": response.status_code,
            "matched_pattern": matched_pattern,
            "response_excerpt": body[:500] if body else "",
        }

    async def _retest_xss(
        self,
        url: str,
        parameter: str,
        payload: str,
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Re-test for reflected XSS by checking if the payload appears
        unencoded in the response body.

        Returns (confirmed: bool, evidence: dict).
        """
        if not parameter or not payload:
            return False, {"reason": "Missing parameter or payload"}

        params = {parameter: payload}
        response = await self._http.get(url, params=params)

        body = response.body or ""
        # Check for unencoded reflection — a real reflection means XSS is live
        confirmed = _XSS_REFLECTION_PATTERN.search(body) is not None

        # Fallback: check if the raw payload is literally present (unencoded)
        if not confirmed and payload in body:
            confirmed = True

        return confirmed, {
            "method": "GET",
            "parameter": parameter,
            "payload": payload,
            "status_code": response.status_code,
            "reflected": confirmed,
            "response_excerpt": body[:500] if body else "",
        }

    async def _retest_idor(
        self,
        url: str,
        original_id: Any,
        test_id: Any,
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Re-test IDOR by comparing responses for two different object IDs.

        A finding is confirmed when:
        - The test_id URL returns HTTP 200, AND
        - The response body differs from an authenticated request to
          original_id (i.e. a different object was returned).

        Because we cannot authenticate, we use a heuristic: if both URLs
        return 200 and the bodies differ, it is suspicious.

        Returns (confirmed: bool, evidence: dict).
        """
        if original_id is None or test_id is None:
            return False, {"reason": "Missing original_id or test_id"}

        orig_url = url  # URL with the legitimate ID
        test_url = url.replace(str(original_id), str(test_id), 1)

        orig_response = await self._http.get(orig_url)
        test_response = await self._http.get(test_url)

        orig_ok = orig_response.status_code == 200
        test_ok = test_response.status_code == 200
        bodies_differ = (orig_response.body or "") != (test_response.body or "")

        # Confirmed when test URL returns 200 with content different from
        # the baseline (or when the original is 200 but test is also 200 with
        # different data — classic IDOR).
        confirmed = test_ok and bodies_differ and len(test_response.body or "") > 0

        return confirmed, {
            "original_url": orig_url,
            "test_url": test_url,
            "original_status": orig_response.status_code,
            "test_status": test_response.status_code,
            "bodies_differ": bodies_differ,
            "original_excerpt": (orig_response.body or "")[:300],
            "test_excerpt": (test_response.body or "")[:300],
        }

    async def _retest_generic(
        self,
        url: str,
        parameter: str,
        payload: str,
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Fallback re-test for findings without a specific validator.

        Sends the payload via GET and records the response.  Cannot
        auto-confirm — always returns False so the finding is flagged for
        manual review rather than silently promoted.
        """
        params = {parameter: payload} if parameter and payload else {}
        response = await self._http.get(url, params=params)

        return False, {
            "note": "Generic retest — manual confirmation required",
            "status_code": response.status_code,
            "response_length": len(response.body or ""),
        }
