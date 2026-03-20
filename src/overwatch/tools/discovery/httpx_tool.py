"""
httpx tool integration for HTTP service probing.

httpx (from ProjectDiscovery) runs with -json -silent and emits one JSON
object per line (JSONL).  We parse every line independently so a malformed
line for one URL does not abort the entire result set.

Findings shape::

    {
        "url": "https://example.com",
        "status_code": 200,
        "title": "Example Domain",
        "technologies": ["nginx", "Bootstrap"],
        "content_type": "text/html; charset=utf-8",
        "content_length": 1256,
    }
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class HttpxTool(BaseTool):
    """
    HTTP service prober and technology detector.

    Wraps ProjectDiscovery's httpx binary.  Outputs one JSON object per
    probed URL, parsed into a structured findings list.
    """

    name = "httpx"
    description = "HTTP service prober — status codes, titles, technology detection"
    requires_binary = "httpx"

    async def execute(
        self,
        target: str,
        follow_redirects: bool = True,
        timeout: int = 30,
    ) -> ToolResult:
        """
        Probe *target* with httpx.

        Args:
            target:           A URL or hostname to probe.
            follow_redirects: Pass -follow-redirects to httpx.
            timeout:          Per-request timeout in seconds passed to httpx.

        Returns:
            ToolResult with a findings list.
        """
        start = time.monotonic()

        if not self._validate_target(target):
            return self._make_error_result(target, "Invalid target — injection characters detected")

        if not self._check_scope(target):
            return self._make_error_result(target, f"Target {target!r} is out of scope")

        cmd: List[str] = [
            "httpx",
            "-u", target,
            "-json",
            "-silent",
            "-tech-detect",
            "-status-code",
            "-title",
            "-content-length",
            "-content-type",
            "-timeout", str(timeout),
        ]
        if follow_redirects:
            cmd.append("-follow-redirects")

        cmd_str = " ".join(cmd)
        logger.info("HttpxTool: %s", cmd_str)

        try:
            stdout, stderr, returncode = await self._run_process(cmd)
        except TimeoutError:
            return self._make_error_result(
                target,
                f"httpx timed out after {self.timeout}s",
                command=cmd_str,
                duration_ms=self._elapsed_ms(start),
            )
        except Exception as exc:
            logger.exception("HttpxTool subprocess error")
            return self._make_error_result(
                target,
                str(exc),
                command=cmd_str,
                duration_ms=self._elapsed_ms(start),
            )

        duration = self._elapsed_ms(start)

        # httpx exits 0 even when no results are found; a non-zero code means
        # something went wrong (e.g. binary not found, bad flag).
        if returncode != 0 and not stdout.strip():
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                raw_output=stderr,
                error=f"httpx exited with code {returncode}: {stderr.strip()[:500]}",
                command=cmd_str,
                duration_ms=duration,
            )

        parsed = self.parse_output(stdout)
        findings = parsed.get("findings", [])

        logger.info(
            "HttpxTool: %d response(s) for %s in %dms",
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

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_output(self, raw: str) -> Dict[str, Any]:
        """
        Parse httpx JSONL output.

        httpx emits one JSON object per probed URL.  Lines that are not
        valid JSON are skipped with a warning.

        Returns a dict with a ``findings`` key containing the list.
        """
        findings: List[Dict[str, Any]] = []

        for i, line in enumerate(raw.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("httpx JSONL parse error on line %d: %s", i + 1, exc)
                continue

            finding = self._normalise_entry(entry)
            if finding:
                findings.append(finding)

        return {"findings": findings, "raw_lines": len(raw.splitlines())}

    @staticmethod
    def _normalise_entry(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Map an httpx JSON entry to the canonical finding shape.

        httpx field names vary slightly between versions; we handle both
        ``url`` / ``input`` and ``tech`` / ``technologies``.
        """
        url = entry.get("url") or entry.get("input") or ""
        if not url:
            return None

        # Technology list — httpx may return a list of dicts or strings
        raw_tech = entry.get("tech") or entry.get("technologies") or []
        technologies: List[str] = []
        for item in raw_tech:
            if isinstance(item, str):
                technologies.append(item)
            elif isinstance(item, dict):
                # some versions: {"tech": "Bootstrap", "version": "5.0"}
                name = item.get("tech") or item.get("name") or ""
                ver = item.get("version", "")
                technologies.append(f"{name}/{ver}" if ver else name)

        return {
            "url": url,
            "status_code": entry.get("status_code") or entry.get("status") or 0,
            "title": entry.get("title", ""),
            "technologies": technologies,
            "content_type": entry.get("content_type", ""),
            "content_length": entry.get("content_length") or entry.get("content-length") or 0,
            "final_url": entry.get("final_url", url),
            "webserver": entry.get("webserver", ""),
            "host": entry.get("host", ""),
        }
