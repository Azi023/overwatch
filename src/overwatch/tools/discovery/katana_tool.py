"""
Katana web crawler tool integration.

Katana (ProjectDiscovery) crawls web applications and outputs discovered
endpoints in JSONL format.  We parse every line independently so a
malformed entry for one URL does not abort the entire crawl.

Findings shape::

    {
        "url": "https://example.com/api/users",
        "method": "GET",
        "status_code": 200,
        "content_type": "application/json",
        "depth": 2,
        "source": "https://example.com",
    }
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)

# Default Katana flags — no shell=True, split at call time
_DEFAULT_FLAGS = "-silent -json -depth 3 -timeout 10 -no-color"

# Extensions to skip during crawls (assets, not attack surface)
_SKIP_EXTENSIONS = frozenset({
    ".css", ".js", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".map",
})


class KatanaTool(BaseTool):
    """
    Web crawler using ProjectDiscovery's katana.

    Discovers application endpoints, forms, and JavaScript-rendered paths.
    Filters static assets so findings are actionable attack surface only.
    """

    name = "katana"
    description = "Web crawler — discovers endpoints, forms, and JS-rendered paths"
    requires_binary = "katana"

    async def execute(
        self,
        target: str,
        depth: int = 3,
        js_crawl: bool = True,
        form_extraction: bool = True,
        timeout: int = 10,
    ) -> ToolResult:
        """
        Crawl *target* URL with katana.

        Args:
            target:           Base URL to start crawling from.
            depth:            Maximum crawl depth (default 3).
            js_crawl:         Enable JavaScript rendering via headless browser.
            form_extraction:  Extract form inputs as endpoints.
            timeout:          Per-request timeout in seconds.

        Returns:
            ToolResult with findings list of discovered endpoints.
        """
        start = time.monotonic()

        if not self._validate_target(target):
            return self._make_error_result(target, "Invalid target — injection characters detected")

        if not self._check_scope(target):
            return self._make_error_result(target, f"Target {target!r} is out of scope")

        cmd = [
            "katana",
            "-u", target,
            "-depth", str(depth),
            "-timeout", str(timeout),
            "-silent",
            "-json",
            "-no-color",
        ]
        if js_crawl:
            cmd += ["-jc"]
        if form_extraction:
            cmd += ["-form-extraction"]

        cmd_str = " ".join(cmd)
        logger.info("KatanaTool: %s", cmd_str)

        try:
            stdout, stderr, returncode = await self._run_process(cmd)
        except TimeoutError:
            return self._make_error_result(
                target,
                f"Katana timed out after {self.timeout}s",
                command=cmd_str,
                duration_ms=self._elapsed_ms(start),
            )
        except Exception as exc:
            logger.exception("KatanaTool subprocess error")
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
                error=f"katana exited with code {returncode}: {stderr.strip()[:500]}",
                command=cmd_str,
                duration_ms=duration,
            )

        parsed = self.parse_output(stdout)
        findings = parsed.get("findings", [])

        logger.info(
            "KatanaTool: %d endpoint(s) discovered on %s in %dms",
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
        Parse katana JSONL output into a structured dict.

        Each line is a JSON object. Lines that fail to parse are skipped
        with a warning so one bad line does not abort the full result.
        """
        findings: List[Dict[str, Any]] = []
        urls_seen: set = set()

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("KatanaTool: skipping non-JSON line: %r", line[:120])
                continue

            url = obj.get("endpoint") or obj.get("url") or obj.get("request", {}).get("endpoint", "")
            if not url:
                continue

            # Deduplicate
            if url in urls_seen:
                continue
            urls_seen.add(url)

            # Skip static assets
            lower = url.lower()
            if any(lower.endswith(ext) for ext in _SKIP_EXTENSIONS):
                continue

            finding: Dict[str, Any] = {
                "url": url,
                "method": obj.get("request", {}).get("method", "GET"),
                "status_code": obj.get("response", {}).get("status_code"),
                "content_type": obj.get("response", {}).get("headers", {}).get("content-type", ""),
                "depth": obj.get("depth", 0),
                "source": obj.get("source", ""),
                "tags": obj.get("tag", []) or [],
            }
            findings.append(finding)

        return {
            "findings": findings,
            "total_discovered": len(findings),
        }
