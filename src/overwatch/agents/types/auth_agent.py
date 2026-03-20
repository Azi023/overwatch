"""
Auth Agent — tests authentication and authorization mechanisms.
Tests: credential stuffing, default creds, session fixation, privilege escalation, IDOR.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from ..base_agent import BaseAgent, Hypothesis, HypothesisResult

logger = logging.getLogger(__name__)

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("administrator", "administrator"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
]


class AuthAgent(BaseAgent):
    """
    Agent specialising in authentication and authorization testing.
    """

    agent_type = "auth"

    async def orient(self) -> None:
        """Load known endpoints and credentials."""
        try:
            creds = await self.engagement_memory.get_credentials()
            self.working_memory.set("known_credentials", creds)
            endpoints = await self.engagement_memory.get_discoveries("endpoint")
            login_forms = [e for e in endpoints if "login" in e.get("url", "").lower()
                           or "signin" in e.get("url", "").lower()
                           or "auth" in e.get("url", "").lower()]
            self.working_memory.set("login_endpoints", login_forms)
        except Exception as exc:
            logger.warning("[%s] orient failed: %s", self.agent_id[:8], exc)
            self.working_memory.set("known_credentials", [])
            self.working_memory.set("login_endpoints", [])

    async def observe(self) -> List[dict]:
        """Look for authentication endpoints."""
        target = self.scope_subset.get("url", "")
        if not target or not self.check_scope(target):
            return []

        http_client = self.tools.get("http_client")
        if not http_client:
            return []

        observations = []
        auth_paths = ["/login", "/signin", "/auth", "/api/login", "/api/auth",
                      "/user/login", "/admin/login", "/wp-login.php"]

        for path in auth_paths:
            full_url = target.rstrip("/") + path
            if not self.check_scope(full_url):
                continue
            try:
                resp = await http_client.get(full_url)
                if resp.status_code in (200, 302, 401, 403):
                    observations.append({
                        "type": "auth_endpoint",
                        "url": full_url,
                        "status": resp.status_code,
                    })
                    self.working_memory.append_to_list("auth_endpoints_found", {
                        "url": full_url, "status": resp.status_code
                    })
            except Exception:
                pass

        return observations

    async def hypothesize(self) -> List[Hypothesis]:
        """Generate auth testing hypotheses."""
        hypotheses = []
        auth_endpoints = self.working_memory.get_list("auth_endpoints_found")
        login_eps = self.working_memory.get("login_endpoints", [])
        all_eps = auth_endpoints + login_eps

        for ep in all_eps[:3]:  # limit to first 3
            url = ep.get("url", "")
            hypotheses.append(Hypothesis(
                description=f"Default credentials on {url}",
                confidence=0.3,
                target=url,
                action="test_default_creds",
                parameters={"url": url},
                vuln_type="auth_bypass",
            ))

        return hypotheses

    async def execute_hypothesis(self, hypothesis: Hypothesis) -> HypothesisResult:
        action = hypothesis.action
        params = hypothesis.parameters

        if action == "test_default_creds":
            return await self._test_default_creds(hypothesis, params)

        return HypothesisResult(
            hypothesis=hypothesis,
            outcome="error",
            evidence={"error": f"Unknown action: {action}"},
            updated_confidence=0.0,
        )

    async def _test_default_creds(self, hypothesis: Hypothesis, params: dict) -> HypothesisResult:
        """Try a small set of default credentials against a login endpoint."""
        url = params.get("url", "")
        http_client = self.tools.get("http_client")

        if not http_client or not self.check_scope(url):
            return HypothesisResult(hypothesis=hypothesis, outcome="error",
                                     evidence={"error": "No client or out of scope"},
                                     updated_confidence=0.0)

        # Try default creds — check for redirect or 200 with auth token
        for username, password in DEFAULT_CREDENTIALS[:5]:  # limit to 5 attempts
            try:
                resp = await http_client.post(
                    url,
                    json={"username": username, "password": password},
                )
                body = resp.body.lower() if resp.body else ""
                # Success indicators: token, session, redirect away from login
                success = (
                    resp.status_code in (200, 302)
                    and ("token" in body or "session" in body or "dashboard" in body
                         or resp.status_code == 302)
                    and "invalid" not in body
                    and "incorrect" not in body
                    and "failed" not in body
                )
                if success:
                    finding = {
                        "vulnerability_type": "Default Credentials",
                        "title": f"Default credentials accepted: {username}:{password}",
                        "description": f"Login endpoint at {url} accepted default credentials",
                        "url": url,
                        "severity": "critical",
                        "confidence": 0.9,
                        "evidence": {
                            "username": username,
                            "password": password,
                            "response_code": resp.status_code,
                        },
                        "tool_name": "auth_agent",
                        "agent_type": "auth",
                    }
                    return HypothesisResult(
                        hypothesis=hypothesis,
                        outcome="confirmed",
                        evidence=finding["evidence"],
                        updated_confidence=0.9,
                        finding=finding,
                    )
            except Exception as exc:
                logger.debug("Credential test error: %s", exc)

        return HypothesisResult(
            hypothesis=hypothesis,
            outcome="refuted",
            evidence={"tested_pairs": 5},
            updated_confidence=0.05,
        )
