"""
Nuclei tool integration for vulnerability template scanning.

Nuclei (ProjectDiscovery) scans a target URL against a library of YAML
templates and emits results as JSON when called with -json-export.

Findings shape::

    {
        "template_id": "cve-2021-44228",
        "name": "Apache Log4j RCE",
        "severity": "critical",
        "url": "https://example.com/app",
        "description": "Log4Shell ...",
        "matched_at": "https://example.com/app?q=${jndi:...}",
        "curl_command": "curl -X GET ...",
        "evidence": {...},
    }
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class NucleiTool(BaseTool):
    """
    Nuclei template-based vulnerability scanner.

    Supports filtering by severity, specific template directories, and tags.
    Results are exported as a JSON file and then read back for parsing.
    """

    name = "nuclei"
    description = "Template-based vulnerability scanner (ProjectDiscovery)"
    requires_binary = "nuclei"

    async def execute(
        self,
        target: str,
        templates: Optional[List[str]] = None,
        severity: str = "medium,high,critical",
        tags: Optional[str] = None,
        output_dir: str = "/tmp/overwatch",
    ) -> ToolResult:
        """
        Run nuclei against *target*.

        Args:
            target:     URL to scan.
            templates:  List of template paths/dirs relative to nuclei's
                        templates directory.  None means all templates.
            severity:   Comma-separated severity filter, e.g. "high,critical".
            tags:       Comma-separated tag filter, e.g. "cve,rce".
            output_dir: Directory for the JSON export file.

        Returns:
            ToolResult with findings list.
        """
        start = time.monotonic()

        if not self._validate_target(target):
            return self._make_error_result(target, "Invalid target — injection characters detected")

        if not self._check_scope(target):
            return self._make_error_result(target, f"Target {target!r} is out of scope")

        # Build output file path
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = out_dir / f"{timestamp}_nuclei.json"

        cmd: List[str] = [
            "nuclei",
            "-u", target,
            "-json-export", str(output_file),
            "-severity", severity,
            "-silent",
        ]

        if templates:
            for tmpl in templates:
                # Reject path traversal attempts in template paths
                if ".." in tmpl or tmpl.startswith("/"):
                    logger.warning("Rejected suspicious template path: %r", tmpl)
                    continue
                cmd.extend(["-t", tmpl])

        if tags:
            cmd.extend(["-tags", tags])

        cmd_str = " ".join(cmd)
        logger.info("NucleiTool: %s", cmd_str)

        try:
            stdout, stderr, returncode = await self._run_process(cmd)
        except TimeoutError:
            return self._make_error_result(
                target,
                f"nuclei timed out after {self.timeout}s",
                command=cmd_str,
                duration_ms=self._elapsed_ms(start),
            )
        except Exception as exc:
            logger.exception("NucleiTool subprocess error")
            return self._make_error_result(
                target,
                str(exc),
                command=cmd_str,
                duration_ms=self._elapsed_ms(start),
            )

        duration = self._elapsed_ms(start)

        if returncode != 0 and not output_file.exists():
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                raw_output=stderr,
                error=f"nuclei exited with code {returncode}: {stderr.strip()[:500]}",
                command=cmd_str,
                duration_ms=duration,
            )

        # Read the JSON export file that nuclei writes
        raw_json = ""
        if output_file.exists():
            try:
                raw_json = output_file.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("Could not read nuclei output file: %s", exc)

        parsed = self.parse_output(raw_json)
        findings = parsed.get("findings", [])

        logger.info(
            "NucleiTool: %d finding(s) for %s in %dms",
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
            evidence={"output_file": str(output_file)},
        )

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_output(self, raw: str) -> Dict[str, Any]:
        """
        Parse nuclei JSON export output.

        Nuclei writes one JSON object per line when -json is used in older
        versions, or a full JSON array with -json-export in newer versions.
        We handle both formats.
        """
        if not raw.strip():
            return {"findings": []}

        findings: List[Dict[str, Any]] = []

        # Try array format first (newer nuclei with -json-export)
        stripped = raw.strip()
        if stripped.startswith("["):
            try:
                entries = json.loads(stripped)
                for entry in entries:
                    finding = self._normalise_entry(entry)
                    if finding:
                        findings.append(finding)
                return {"findings": findings}
            except json.JSONDecodeError:
                pass  # Fall through to JSONL parsing

        # JSONL format — one object per line
        for i, line in enumerate(raw.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("nuclei JSONL parse error on line %d: %s", i + 1, exc)
                continue
            finding = self._normalise_entry(entry)
            if finding:
                findings.append(finding)

        return {"findings": findings}

    @staticmethod
    def _normalise_entry(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Map a nuclei result entry to the canonical finding shape."""
        # nuclei result fields depend on version; handle common variants
        template_id = (
            entry.get("template-id")
            or entry.get("templateID")
            or entry.get("template_id")
            or ""
        )
        info = entry.get("info") or {}
        name = info.get("name") or entry.get("name") or template_id
        severity = (info.get("severity") or entry.get("severity") or "unknown").lower()
        description = info.get("description") or entry.get("description") or ""

        matched_at = (
            entry.get("matched-at")
            or entry.get("matched_at")
            or entry.get("host")
            or ""
        )
        url = entry.get("url") or matched_at

        # Evidence block
        request = entry.get("request") or ""
        response = entry.get("response") or ""
        curl_command = entry.get("curl-command") or entry.get("curl_command") or ""

        return {
            "template_id": template_id,
            "name": name,
            "severity": severity,
            "url": url,
            "description": description,
            "matched_at": matched_at,
            "curl_command": curl_command,
            "evidence": {
                "request": request[:2000] if request else "",
                "response": response[:2000] if response else "",
            },
            "tags": info.get("tags") or [],
            "reference": info.get("reference") or [],
        }
