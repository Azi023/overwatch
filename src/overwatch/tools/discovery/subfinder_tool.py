"""
Subfinder subdomain enumeration tool integration.

Subfinder (ProjectDiscovery) performs passive subdomain enumeration using
public sources.  It outputs one subdomain per line, or one JSON object
per line when -json is passed.

Findings shape::

    {
        "subdomain": "api.example.com",
        "host": "api.example.com",
        "source": "CertificateTransparency",
        "ip": "1.2.3.4",        # only when -resolve is used
    }
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class SubfinderTool(BaseTool):
    """
    Passive subdomain enumerator using ProjectDiscovery's subfinder.

    Uses public sources (certificate transparency, DNS datasets, etc.)
    so it produces no direct traffic to the target domain.
    """

    name = "subfinder"
    description = "Passive subdomain enumerator — discovers subdomains without active scanning"
    requires_binary = "subfinder"

    async def execute(
        self,
        target: str,
        resolve: bool = True,
        max_results: int = 500,
        sources: Optional[List[str]] = None,
    ) -> ToolResult:
        """
        Enumerate subdomains for *target* domain.

        Args:
            target:      Root domain to enumerate (e.g. "example.com").
            resolve:     Resolve discovered subdomains to IP addresses.
            max_results: Cap on the number of results (default 500).
            sources:     Optional list of specific sources to use.
                         Defaults to subfinder's built-in passive sources.

        Returns:
            ToolResult with findings list of discovered subdomains.
        """
        start = time.monotonic()

        if not self._validate_target(target):
            return self._make_error_result(target, "Invalid target — injection characters detected")

        if not self._check_scope(target):
            return self._make_error_result(target, f"Target {target!r} is out of scope")

        cmd = [
            "subfinder",
            "-d", target,
            "-silent",
            "-json",
            "-no-color",
        ]

        if resolve:
            cmd += ["-resolve"]
        if max_results:
            cmd += ["-max-time", "300"]  # let subfinder run up to 5 minutes
        if sources:
            cmd += ["-sources", ",".join(sources)]

        cmd_str = " ".join(cmd)
        logger.info("SubfinderTool: %s", cmd_str)

        try:
            stdout, stderr, returncode = await self._run_process(cmd, timeout=360)
        except TimeoutError:
            return self._make_error_result(
                target,
                f"Subfinder timed out after {self.timeout}s",
                command=cmd_str,
                duration_ms=self._elapsed_ms(start),
            )
        except Exception as exc:
            logger.exception("SubfinderTool subprocess error")
            return self._make_error_result(
                target,
                str(exc),
                command=cmd_str,
                duration_ms=self._elapsed_ms(start),
            )

        duration = self._elapsed_ms(start)

        if returncode != 0 and not stdout.strip():
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                raw_output=stderr,
                error=f"subfinder exited with code {returncode}: {stderr.strip()[:500]}",
                command=cmd_str,
                duration_ms=duration,
            )

        parsed = self.parse_output(stdout)
        findings = parsed.get("findings", [])

        # Cap results
        if max_results and len(findings) > max_results:
            findings = findings[:max_results]
            parsed["findings"] = findings
            logger.info(
                "SubfinderTool: truncated to %d results (max_results=%d)",
                max_results,
                max_results,
            )

        logger.info(
            "SubfinderTool: %d subdomain(s) found for %s in %dms",
            len(findings),
            target,
            duration,
        )

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=True,
            raw_output=stdout,
            parsed_output=parsed,
            findings=findings,
            command=cmd_str,
            duration_ms=duration,
        )

    def parse_output(self, raw: str) -> Dict[str, Any]:
        """
        Parse subfinder output.

        Accepts both JSONL format (from -json flag) and plain-text format
        (one subdomain per line) for robustness.
        """
        findings: List[Dict[str, Any]] = []
        seen: set = set()

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue

            # Try JSON first
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    subdomain = obj.get("host") or obj.get("subdomain") or ""
                    if not subdomain:
                        continue
                    if subdomain in seen:
                        continue
                    seen.add(subdomain)
                    findings.append({
                        "subdomain": subdomain,
                        "host": subdomain,
                        "source": obj.get("source", ""),
                        "ip": obj.get("ip", "") or obj.get("address", ""),
                    })
                    continue
                except json.JSONDecodeError:
                    pass

            # Fall back to plain-text subdomain
            subdomain = line.lower().strip()
            if subdomain and subdomain not in seen:
                seen.add(subdomain)
                findings.append({
                    "subdomain": subdomain,
                    "host": subdomain,
                    "source": "plain_text",
                    "ip": "",
                })

        return {
            "findings": findings,
            "subdomains": [f["subdomain"] for f in findings],
        }
