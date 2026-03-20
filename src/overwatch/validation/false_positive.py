"""
False-positive elimination pipeline.

Before a validated finding is promoted to a report, FalsePositiveEliminator
performs additional checks to catch common false positive patterns:

1. WAF-fingerprinting — error pages that match known WAF block signatures
   do not count as confirmed vulnerabilities.
2. Baseline response comparison — if the "attack" response is identical to
   the baseline (unarmed) response, the finding is not meaningful.
3. Known-benign pattern matching — certain technologies return SQL-like error
   strings in their normal operation (e.g. some CMS debug modes).
4. Timing variance — for blind injections, random latency can mimic time-based
   delays; we require the difference to exceed a configurable threshold.

The output FPAnalysis does NOT make a binary pass/fail decision — it returns
a ``fp_probability`` float so the caller (agent or report engine) can apply
their own threshold.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known WAF block-page fingerprints (conservative — only very obvious ones)
# ---------------------------------------------------------------------------

_WAF_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"access denied.*cloudflare",
        r"sorry, you have been blocked",
        r"403 forbidden.*nginx",
        r"your request has been blocked",
        r"<title>attention required.*cloudflare</title>",
        r"mod_security",
        r"incapsula incident id",
        r"sucuri webwite firewall",
        r"barracuda networks",
        r"error 1020",
        r"ray id.*cloudflare",
        r"request id.*akamai",
    ]
]

# ---------------------------------------------------------------------------
# Known benign patterns that look like vulnerabilities but are not
# ---------------------------------------------------------------------------

_BENIGN_ERROR_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # Debug / development outputs that are intentional
        r"debug mode.*sql",
        r"this is a development server",
        r"laravel.*\(debug mode\)",
        # Generic PHP errors that don't expose DB
        r"php notice.*undefined variable",
        r"php warning.*mysqli_connect\(\).*access denied",
        # Example / placeholder pages
        r"example domain",
        r"it works!.*apache",
    ]
]

# Minimum response-body-length difference to consider bodies "different"
_BODY_DIFF_MIN_CHARS = 50

# Timing threshold for time-based blind SQLi (ms) — responses within this
# margin are considered "no delay"
_TIMING_NOISE_THRESHOLD_MS = 1500


@dataclass
class FPAnalysis:
    """
    Result of the false-positive analysis for a single finding.

    Attributes:
        finding_id:    Opaque ID matching the finding being analysed.
        fp_probability:Float [0.0, 1.0].  0 = definitely real, 1 = definitely FP.
        reasons:       Human-readable list of reasons that raised (or lowered) FP probability.
        recommendation:"confirm" | "review" | "dismiss"
    """

    finding_id: str
    fp_probability: float
    reasons: List[str] = field(default_factory=list)
    recommendation: str = "review"


class FalsePositiveEliminator:
    """
    Multi-signal false-positive analysis pipeline.

    This class is intentionally *not* the final authority — it computes a
    probability and a recommendation that the agent or report engine uses
    to make the final decision.
    """

    def __init__(self, knowledge_base=None, http_client=None) -> None:
        """
        Args:
            knowledge_base: Optional knowledge base with tool/vuln patterns.
            http_client:    HttpClient used for baseline response comparison.
        """
        self._kb = knowledge_base
        self._http = http_client

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def analyze(self, finding: Dict[str, Any]) -> FPAnalysis:
        """
        Run all FP checks against *finding* and return an FPAnalysis.

        Args:
            finding: Finding dict.  Must contain at minimum: id, url, type.
                     Optional: response_body, parameter, payload, duration_ms.

        Returns:
            FPAnalysis with fp_probability and actionable recommendation.
        """
        finding_id = str(finding.get("id", "unknown"))
        reasons: List[str] = []
        fp_signals: List[float] = []

        # --- 1. WAF block detection ---
        response_body = finding.get("response_body") or finding.get("response_excerpt") or ""
        waf_prob = self._check_waf_block(response_body)
        if waf_prob > 0:
            fp_signals.append(waf_prob)
            reasons.append(f"WAF block-page pattern detected (signal={waf_prob:.2f})")

        # --- 2. Benign error pattern check ---
        benign_prob = self._check_benign_patterns(response_body)
        if benign_prob > 0:
            fp_signals.append(benign_prob)
            reasons.append(f"Known benign error pattern matched (signal={benign_prob:.2f})")

        # --- 3. Known FP patterns from knowledge base / heuristics ---
        pattern_prob = await self._check_fp_patterns(finding)
        if pattern_prob > 0:
            fp_signals.append(pattern_prob)
            reasons.append(f"Heuristic FP pattern matched (signal={pattern_prob:.2f})")

        # --- 4. Baseline response comparison ---
        if self._http is not None:
            baseline_match = await self._cross_reference_response(finding)
            if baseline_match:
                fp_signals.append(0.9)
                reasons.append(
                    "Attack response is identical to baseline (unarmed) response — "
                    "payload not actually reflected or processed differently"
                )

        # --- 5. Timing noise (blind injection check) ---
        if finding.get("type") in ("sqli_blind", "blind_sqli", "time_based"):
            duration = finding.get("duration_ms") or 0
            if duration < _TIMING_NOISE_THRESHOLD_MS:
                fp_signals.append(0.7)
                reasons.append(
                    f"Observed delay {duration}ms is below noise threshold "
                    f"{_TIMING_NOISE_THRESHOLD_MS}ms — not reliable"
                )

        # --- 6. HTTP status signals ---
        status = finding.get("status_code") or finding.get("response_status") or 0
        if status in (429, 503, 502):
            fp_signals.append(0.6)
            reasons.append(f"HTTP {status} suggests rate limiting or WAF, not vuln confirmation")

        # Aggregate probability — max of all signals (one strong signal is enough)
        fp_probability = max(fp_signals) if fp_signals else 0.0

        # Recommendation thresholds
        if fp_probability >= 0.75:
            recommendation = "dismiss"
            if not reasons:
                reasons.append("No confirming evidence found")
        elif fp_probability >= 0.40:
            recommendation = "review"
            if not reasons:
                reasons.append("Some FP signals present — manual review recommended")
        else:
            recommendation = "confirm"
            reasons.append("No significant false-positive signals detected")

        logger.info(
            "FP analysis for %s: fp_prob=%.2f, recommendation=%s",
            finding_id,
            fp_probability,
            recommendation,
        )

        return FPAnalysis(
            finding_id=finding_id,
            fp_probability=fp_probability,
            reasons=reasons,
            recommendation=recommendation,
        )

    # ------------------------------------------------------------------
    # Individual signal checks
    # ------------------------------------------------------------------

    async def _check_fp_patterns(self, finding: Dict[str, Any]) -> float:
        """
        Check finding against heuristic and knowledge-base FP patterns.

        Returns a float in [0.0, 1.0] — higher means more likely FP.
        """
        signals: List[float] = []
        vuln_type = (finding.get("type") or "").lower()
        payload = finding.get("payload") or ""
        response_body = finding.get("response_body") or finding.get("response_excerpt") or ""

        # Heuristic: extremely short response bodies rarely contain real exploits
        if response_body and len(response_body) < 20 and vuln_type not in ("xss",):
            signals.append(0.4)

        # Heuristic: if the payload itself appears literally in the URL the
        # server may be echoing input without actually processing SQL.
        url = finding.get("url") or ""
        if payload and payload in url and vuln_type == "sqli":
            signals.append(0.3)

        # Knowledge base patterns (if available)
        if self._kb is not None:
            try:
                kb_signals = await self._check_kb_patterns(finding)
                signals.extend(kb_signals)
            except Exception as exc:
                logger.warning("Knowledge base FP check failed: %s", exc)

        return max(signals) if signals else 0.0

    async def _cross_reference_response(self, finding: Dict[str, Any]) -> bool:
        """
        Compare the attack response against a baseline (no-payload) response.

        Returns True when the baseline and attack responses are effectively
        identical — indicating the payload had no real effect.
        """
        url = finding.get("url")
        parameter = finding.get("parameter")
        attack_body = finding.get("response_body") or finding.get("response_excerpt") or ""

        if not url or not parameter or not attack_body:
            return False

        try:
            # Fetch baseline with an innocuous value
            baseline_response = await self._http.get(url, params={parameter: "baseline_test_1234"})
            baseline_body = baseline_response.body or ""

            if not baseline_body:
                return False

            # Bodies are "same" when difference is within noise threshold
            diff = abs(len(attack_body) - len(baseline_body))
            if diff < _BODY_DIFF_MIN_CHARS:
                # Also do a substring check for very similar content
                overlap = self._body_similarity(attack_body, baseline_body)
                if overlap > 0.95:
                    return True  # Bodies are essentially identical

        except Exception as exc:
            logger.debug("Baseline comparison failed: %s", exc)

        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_waf_block(body: str) -> float:
        """Return a probability that *body* is a WAF block page."""
        if not body:
            return 0.0
        for pattern in _WAF_PATTERNS:
            if pattern.search(body):
                return 0.95
        return 0.0

    @staticmethod
    def _check_benign_patterns(body: str) -> float:
        """Return a probability that *body* matches known benign patterns."""
        if not body:
            return 0.0
        for pattern in _BENIGN_ERROR_PATTERNS:
            if pattern.search(body):
                return 0.6
        return 0.0

    @staticmethod
    def _body_similarity(a: str, b: str) -> float:
        """
        Compute a rough similarity ratio between two strings.

        Uses a simple character-level overlap heuristic — fast and good enough
        for FP detection where we only need to catch near-identical responses.
        """
        if not a or not b:
            return 0.0
        longer = a if len(a) >= len(b) else b
        shorter = b if len(a) >= len(b) else a
        matches = sum(1 for c in shorter if c in longer)
        return matches / len(longer)

    async def _check_kb_patterns(self, finding: Dict[str, Any]) -> List[float]:
        """
        Query the knowledge base for known-FP patterns for this finding type.

        Returns a list of probability floats.  Each matched pattern contributes
        one signal.
        """
        if self._kb is None:
            return []

        vuln_type = finding.get("type", "")
        try:
            patterns = await self._kb.get_fp_patterns(vuln_type)
            signals: List[float] = []
            response_body = finding.get("response_body") or ""
            for pattern_info in (patterns or []):
                regex_str = pattern_info.get("regex", "")
                if not regex_str:
                    continue
                try:
                    compiled = re.compile(regex_str, re.IGNORECASE)
                    if compiled.search(response_body):
                        signals.append(float(pattern_info.get("fp_probability", 0.5)))
                except re.error:
                    pass
            return signals
        except (AttributeError, Exception):
            return []
