"""
Nmap tool integration for port scanning and service detection.

Runs nmap as a subprocess (no shell=True), writes XML output to a temp file,
and parses it with the stdlib xml.etree.ElementTree so there is no extra
dependency.

Findings shape::

    {
        "port": 443,
        "protocol": "tcp",
        "state": "open",
        "service": "https",
        "product": "nginx",
        "version": "1.24.0",
        "cpe": "cpe:/a:nginx:nginx:1.24.0",
    }
"""
from __future__ import annotations

import logging
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)

# Predefined scan profiles — no shell expansion, these are split() at call time
_PROFILES: Dict[str, str] = {
    "safe": "-sV -T2",
    "balanced": "-sV -sC -T3",
    "quick": "-sV -T4 -F",
    "aggressive": "-A -T4",
}


class NmapTool(BaseTool):
    """
    Nmap network scanner.

    Supports multiple scan profiles and optional port-range overrides.
    Results are parsed from nmap's XML output for reliability.
    """

    name = "nmap"
    description = "Network port scanner and service/version detector"
    requires_binary = "nmap"

    async def execute(
        self,
        target: str,
        profile: str = "balanced",
        ports: Optional[str] = None,
        output_dir: str = "/tmp/overwatch/scans",
    ) -> ToolResult:
        """
        Run nmap against *target*.

        Args:
            target:     IP address, hostname, or CIDR range.
            profile:    One of safe | balanced | quick | aggressive.
            ports:      Optional port specification, e.g. "80,443" or "1-1000".
                        Ignored when the quick profile is used (it sets -F).
            output_dir: Directory in which the XML output file is written.

        Returns:
            ToolResult with findings list and parsed_output dict.
        """
        start = time.monotonic()

        if not self._validate_target(target):
            return self._make_error_result(target, "Invalid target — injection characters detected")

        if not self._check_scope(target):
            return self._make_error_result(target, f"Target {target!r} is out of scope")

        flags = _PROFILES.get(profile, _PROFILES["balanced"])

        # Append port spec unless the quick profile already limits via -F
        if ports and "-F" not in flags:
            if not self._validate_target(ports):
                return self._make_error_result(target, "Invalid ports specification")
            flags = f"{flags} -p {ports}"

        # Prepare output path
        safe_target = target.replace("/", "_").replace(":", "_").replace("*", "_")
        out_dir = Path(output_dir) / safe_target
        out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_file = out_dir / f"{timestamp}_nmap.xml"

        cmd = ["nmap", *flags.split(), "-oX", str(xml_file), target]
        cmd_str = " ".join(cmd)
        logger.info("NmapTool: %s", cmd_str)

        try:
            stdout, stderr, returncode = await self._run_process(cmd)
        except TimeoutError:
            return self._make_error_result(
                target,
                f"Nmap timed out after {self.timeout}s",
                command=cmd_str,
                duration_ms=self._elapsed_ms(start),
            )
        except Exception as exc:
            logger.exception("NmapTool subprocess error")
            return self._make_error_result(
                target,
                str(exc),
                command=cmd_str,
                duration_ms=self._elapsed_ms(start),
            )

        duration = self._elapsed_ms(start)

        if returncode != 0:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                raw_output=stderr,
                error=f"nmap exited with code {returncode}: {stderr.strip()[:500]}",
                command=cmd_str,
                duration_ms=duration,
            )

        # Parse XML output
        parsed = self._parse_xml_file(str(xml_file))
        findings = parsed.get("findings", [])

        logger.info(
            "NmapTool: %d open port(s) found on %s in %dms",
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
            evidence={"xml_path": str(xml_file)},
        )

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_output(self, raw: str) -> Dict[str, Any]:
        """
        Parse nmap stdout text.

        Nmap's plain-text output is hard to parse reliably; callers should
        prefer the XML path via execute().  This implementation returns a
        minimal dict from the text output as a fallback.
        """
        lines = raw.splitlines()
        open_lines = [ln for ln in lines if "/tcp" in ln or "/udp" in ln]
        return {"raw_lines": open_lines}

    def _parse_xml_file(self, xml_path: str) -> Dict[str, Any]:
        """Parse nmap XML output file into structured data."""
        try:
            tree = ET.parse(xml_path)
        except (ET.ParseError, FileNotFoundError) as exc:
            logger.warning("Failed to parse nmap XML %s: %s", xml_path, exc)
            return {"findings": [], "hosts": []}

        root = tree.getroot()
        hosts: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        for host_elem in root.findall("host"):
            host_info = self._parse_host(host_elem)
            hosts.append(host_info)
            findings.extend(host_info.get("ports", []))

        return {
            "hosts": hosts,
            "findings": findings,
            "scan_args": root.get("args", ""),
            "scan_start": root.get("start", ""),
        }

    def _parse_host(self, host_elem: ET.Element) -> Dict[str, Any]:
        """Extract host-level data from a <host> XML element."""
        # Address
        addr_elem = host_elem.find("address")
        ip = addr_elem.get("addr") if addr_elem is not None else "unknown"

        # Status
        status_elem = host_elem.find("status")
        state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

        # Hostnames
        hostnames: List[str] = []
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                name = hn.get("name")
                if name:
                    hostnames.append(name)

        # OS detection (best match)
        os_match = ""
        osmatch = host_elem.find(".//osmatch")
        if osmatch is not None:
            os_match = osmatch.get("name", "")

        # Ports
        ports: List[Dict[str, Any]] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_data = self._parse_port(port_elem, ip)
                ports.append(port_data)

        return {
            "ip": ip,
            "state": state,
            "hostnames": hostnames,
            "os": os_match,
            "ports": ports,
        }

    @staticmethod
    def _parse_port(port_elem: ET.Element, host_ip: str) -> Dict[str, Any]:
        """Extract port-level data from a <port> XML element."""
        port_id = int(port_elem.get("portid", 0))
        protocol = port_elem.get("protocol", "tcp")

        state_elem = port_elem.find("state")
        state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

        service_elem = port_elem.find("service")
        service = ""
        product = ""
        version = ""
        cpe = ""

        if service_elem is not None:
            service = service_elem.get("name", "")
            product = service_elem.get("product", "")
            version = service_elem.get("version", "")
            cpe_elem = service_elem.find("cpe")
            if cpe_elem is not None and cpe_elem.text:
                cpe = cpe_elem.text

        return {
            "host": host_ip,
            "port": port_id,
            "protocol": protocol,
            "state": state,
            "service": service,
            "product": product,
            "version": version,
            "cpe": cpe,
        }
