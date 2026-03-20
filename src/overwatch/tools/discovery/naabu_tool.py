"""
Naabu port scanner tool integration.

Naabu (ProjectDiscovery) is a fast, SYN-based port scanner.  It outputs
one JSON object per open port in JSONL format.

Findings shape::

    {
        "host": "192.168.1.1",
        "port": 443,
        "protocol": "tcp",
        "service": "https",
    }
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)

# Ports naabu will never scan unless explicitly allowed
_SENSITIVE_PORTS = frozenset({22, 3389})


class NaabuTool(BaseTool):
    """
    Fast port scanner using ProjectDiscovery's naabu.

    Suitable for rapid discovery of open ports at scale.  Uses -json
    output for reliable parsing.  For detailed service/version detection
    prefer NmapTool after naabu identifies open ports.
    """

    name = "naabu"
    description = "Fast port scanner — quickly discovers open TCP/UDP ports"
    requires_binary = "naabu"

    async def execute(
        self,
        target: str,
        ports: Optional[str] = None,
        top_ports: int = 1000,
        rate: int = 1000,
        exclude_ports: Optional[str] = None,
    ) -> ToolResult:
        """
        Scan *target* with naabu.

        Args:
            target:        IP address, hostname, or CIDR range.
            ports:         Comma-separated port list or range (e.g. "80,443,8000-9000").
                           Overrides top_ports when set.
            top_ports:     Scan the top N most common ports (default 1000).
            rate:          Packets per second (default 1000 — safe for most networks).
            exclude_ports: Ports to exclude even if in scope (e.g. "22,3389").

        Returns:
            ToolResult with findings list of open ports.
        """
        start = time.monotonic()

        if not self._validate_target(target):
            return self._make_error_result(target, "Invalid target — injection characters detected")

        if not self._check_scope(target):
            return self._make_error_result(target, f"Target {target!r} is out of scope")

        cmd = [
            "naabu",
            "-host", target,
            "-silent",
            "-json",
            "-no-color",
            "-rate", str(rate),
        ]

        if ports:
            if not self._validate_target(ports):
                return self._make_error_result(target, "Invalid ports specification")
            cmd += ["-p", ports]
        else:
            cmd += ["-top-ports", str(top_ports)]

        if exclude_ports:
            if not self._validate_target(exclude_ports):
                return self._make_error_result(target, "Invalid exclude-ports specification")
            cmd += ["-exclude-ports", exclude_ports]

        cmd_str = " ".join(cmd)
        logger.info("NaabuTool: %s", cmd_str)

        try:
            stdout, stderr, returncode = await self._run_process(cmd)
        except TimeoutError:
            return self._make_error_result(
                target,
                f"Naabu timed out after {self.timeout}s",
                command=cmd_str,
                duration_ms=self._elapsed_ms(start),
            )
        except Exception as exc:
            logger.exception("NaabuTool subprocess error")
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
                error=f"naabu exited with code {returncode}: {stderr.strip()[:500]}",
                command=cmd_str,
                duration_ms=duration,
            )

        parsed = self.parse_output(stdout)
        findings = parsed.get("findings", [])

        logger.info(
            "NaabuTool: %d open port(s) found on %s in %dms",
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
        Parse naabu JSONL output into a structured dict.

        Each line from naabu -json contains {"ip": ..., "port": ..., ...}.
        Lines that fail to parse are skipped with a warning.
        """
        findings: List[Dict[str, Any]] = []
        seen: set = set()

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("NaabuTool: skipping non-JSON line: %r", line[:120])
                continue

            host = obj.get("ip") or obj.get("host") or ""
            port = obj.get("port")
            if not host or port is None:
                continue

            key = (host, port)
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "host": host,
                "port": int(port),
                "protocol": obj.get("protocol", "tcp"),
                "service": obj.get("service", ""),
            })

        return {
            "findings": findings,
            "open_ports": [f["port"] for f in findings],
        }
