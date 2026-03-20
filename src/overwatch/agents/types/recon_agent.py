"""
ReconAgent - network and service reconnaissance agent.

Uses nmap (and optionally subfinder, httpx) to discover hosts, open ports,
running services, and HTTP endpoints. Discovered services seed hypotheses
for subsequent specialist agents.
"""
from __future__ import annotations

import asyncio
import logging
import re
import shlex
import subprocess
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree

from ..base_agent import BaseAgent, Hypothesis, HypothesisResult

logger = logging.getLogger(__name__)

# Services that warrant deeper investigation
_HIGH_VALUE_SERVICES: Dict[str, str] = {
    "21": "ftp",
    "22": "ssh",
    "23": "telnet",
    "25": "smtp",
    "80": "http",
    "443": "https",
    "445": "smb",
    "3306": "mysql",
    "5432": "postgresql",
    "6379": "redis",
    "8080": "http-alt",
    "8443": "https-alt",
    "27017": "mongodb",
}


class ReconAgent(BaseAgent):
    """
    Reconnaissance agent that maps the attack surface of a target.

    Discovers:
      - Open TCP ports and running services (via nmap)
      - Subdomains (via subfinder if available)
      - HTTP services and their response metadata (via httpx if available)

    Stores all discoveries in engagement_memory so subsequent agents can
    build on the recon results without repeating scans.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # Extract primary target from scope_subset or objective
        self._target: str = self._resolve_target()
        self._discovered_ports: List[dict] = []
        self._discovered_subdomains: List[str] = []
        self._http_services: List[dict] = []

    # ─────────────────────── Abstract Methods ────────────────────

    async def orient(self) -> None:
        """
        Load prior recon context from engagement memory.

        If previous agents or scans already discovered ports/subdomains for this
        target, load them so we don't duplicate work.
        """
        prior_discoveries = await self.engagement_memory.get_discoveries()
        prior_ports: List[dict] = []
        prior_subdomains: List[str] = []

        for disc in prior_discoveries:
            disc_type = disc.get("_type", "")
            if disc_type == "open_port":
                prior_ports.append(disc)
            elif disc_type == "subdomain":
                sub = disc.get("hostname", "")
                if sub:
                    prior_subdomains.append(sub)

        self.working_memory.set("prior_ports", prior_ports)
        self.working_memory.set("prior_subdomains", prior_subdomains)
        self.working_memory.set("target", self._target)

        logger.info(
            "ReconAgent %s: oriented — target='%s' prior_ports=%d prior_subdomains=%d",
            self.agent_id,
            self._target,
            len(prior_ports),
            len(prior_subdomains),
        )

    async def observe(self) -> List[dict]:
        """
        Run nmap to discover open ports and services.

        Only runs nmap once per target per agent lifecycle (tracked in
        working_memory to prevent duplicate scans on subsequent loops).
        """
        if self.working_memory.get("nmap_done", False):
            return []

        observations: List[dict] = []

        if not self.check_scope(self._target):
            logger.warning(
                "ReconAgent %s: target '%s' is out of scope, skipping nmap.",
                self.agent_id,
                self._target,
            )
            self.working_memory.set("nmap_done", True)
            return observations

        nmap_results = await self._run_nmap(self._target)
        self.working_memory.set("nmap_done", True)
        self.working_memory.set("nmap_results", nmap_results)
        self._discovered_ports = nmap_results

        for port_info in nmap_results:
            observations.append({"type": "open_port", "data": port_info})
            # Store in shared engagement memory
            await self.engagement_memory.store_discovery("open_port", port_info)

        # Attempt subdomain enumeration if the target looks like a domain
        if self._looks_like_domain(self._target) and not self.working_memory.get("subfinder_done", False):
            subdomains = await self._run_subfinder(self._target)
            self.working_memory.set("subfinder_done", True)
            self._discovered_subdomains = subdomains
            for sub in subdomains:
                disc = {"hostname": sub, "parent": self._target}
                observations.append({"type": "subdomain", "data": disc})
                await self.engagement_memory.store_discovery("subdomain", disc)

        return observations

    async def hypothesize(self) -> List[Hypothesis]:
        """
        Generate hypotheses based on discovered services.

        Produces one hypothesis per interesting open port that hasn't been
        tested yet in this agent's lifecycle.
        """
        nmap_results: List[dict] = self.working_memory.get("nmap_results", [])
        tested_ports: List[str] = self.working_memory.get("tested_ports", [])
        hypotheses: List[Hypothesis] = []

        for port_info in nmap_results:
            port_str = str(port_info.get("port", ""))
            service = port_info.get("service", "unknown")

            if port_str in tested_ports:
                continue

            if port_str in _HIGH_VALUE_SERVICES:
                action = f"probe_{_HIGH_VALUE_SERVICES[port_str]}"
                vuln_type = self._service_to_vuln_type(service)
                hypothesis = Hypothesis(
                    description=(
                        f"Service '{service}' on port {port_str} of "
                        f"{self._target} may expose vulnerabilities"
                    ),
                    confidence=0.6,
                    target=f"{self._target}:{port_str}",
                    action=action,
                    parameters={
                        "port": port_str,
                        "service": service,
                        "host": self._target,
                    },
                    vuln_type=vuln_type,
                )
                hypotheses.append(hypothesis)

        return hypotheses

    async def execute_hypothesis(self, hypothesis: Hypothesis) -> HypothesisResult:
        """
        Probe the service identified in the hypothesis.

        For HTTP/HTTPS services, fetches the root path and records metadata.
        For other services, records the open port as a discovery.
        """
        port_str = hypothesis.parameters.get("port", "")
        service = hypothesis.parameters.get("service", "unknown")
        host = hypothesis.parameters.get("host", self._target)

        # Track tested ports to avoid re-testing
        tested = self.working_memory.get_list("tested_ports")
        self.working_memory.set("tested_ports", tested + [port_str])

        evidence: Dict[str, Any] = {
            "port": port_str,
            "service": service,
            "host": host,
            "discoveries": [],
        }

        try:
            if service in ("http", "https", "http-alt", "https-alt"):
                http_info = await self._probe_http(host, port_str, service)
                evidence["http_info"] = http_info
                evidence["discoveries"].append(
                    {"type": "http_service", **http_info}
                )
                await self.engagement_memory.store_discovery("http_service", http_info)
                self._http_services.append(http_info)

                return HypothesisResult(
                    hypothesis=hypothesis,
                    outcome="confirmed",
                    evidence=evidence,
                    updated_confidence=0.7,
                    finding=None,  # HTTP service presence is a discovery, not a finding
                )
            else:
                # Non-HTTP service — record as discovery, inconclusive for now
                evidence["discoveries"].append(
                    {
                        "type": "network_service",
                        "host": host,
                        "port": port_str,
                        "service": service,
                    }
                )
                return HypothesisResult(
                    hypothesis=hypothesis,
                    outcome="inconclusive",
                    evidence=evidence,
                    updated_confidence=0.5,
                )

        except Exception as exc:
            logger.error(
                "ReconAgent %s: hypothesis execution error for port %s: %s",
                self.agent_id,
                port_str,
                exc,
            )
            return HypothesisResult(
                hypothesis=hypothesis,
                outcome="error",
                evidence={"error": str(exc)},
                updated_confidence=0.3,
            )

    # ─────────────────────── Tool Runners ────────────────────────

    async def _run_nmap(self, target: str) -> List[dict]:
        """
        Execute a fast nmap SYN scan and parse the XML output.

        Returns a list of open-port dicts: {port, protocol, service, version, state}.
        Falls back to empty list on any error.
        """
        # Use nmap tool from registry if available, else invoke directly
        nmap_tool = self.tools.get("nmap")
        if nmap_tool is not None and hasattr(nmap_tool, "scan"):
            try:
                return await nmap_tool.scan(target)
            except Exception as exc:
                logger.warning("ReconAgent: nmap tool error: %s — trying direct invocation", exc)

        return await self._run_nmap_direct(target)

    async def _run_nmap_direct(self, target: str) -> List[dict]:
        """Invoke nmap directly as a subprocess and parse the XML output."""
        import tempfile
        import os

        results: List[dict] = []
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cmd = [
                "nmap",
                "-sS", "-sV",       # SYN scan + version detection
                "-Pn",              # skip ping (target may block ICMP)
                "--open",           # only show open ports
                "-T3",              # balanced timing
                "-oX", tmp_path,    # XML output
                "--top-ports", "1000",
                target,
            ]
            logger.debug("ReconAgent: running nmap: %s", " ".join(cmd))

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=300
            )

            if proc.returncode != 0:
                logger.warning(
                    "ReconAgent: nmap returned code %d: %s",
                    proc.returncode,
                    stderr.decode(errors="replace")[:500],
                )

            results = self._parse_nmap_xml(tmp_path)

        except asyncio.TimeoutError:
            logger.error("ReconAgent: nmap timed out for target '%s'", target)
        except FileNotFoundError:
            logger.error(
                "ReconAgent: nmap not found. Install nmap and ensure it is on PATH."
            )
        except Exception as exc:
            logger.error("ReconAgent: nmap error: %s", exc)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        return results

    @staticmethod
    def _parse_nmap_xml(xml_path: str) -> List[dict]:
        """Parse nmap XML output and return a list of open-port dicts."""
        results: List[dict] = []
        try:
            tree = ElementTree.parse(xml_path)
            root = tree.getroot()

            for host_elem in root.findall(".//host"):
                status = host_elem.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                addr_elem = host_elem.find("address[@addrtype='ipv4']")
                ip = addr_elem.get("addr", "unknown") if addr_elem is not None else "unknown"

                for port_elem in host_elem.findall(".//port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue

                    service_elem = port_elem.find("service")
                    port_info = {
                        "host": ip,
                        "port": port_elem.get("portid", ""),
                        "protocol": port_elem.get("protocol", "tcp"),
                        "state": "open",
                        "service": service_elem.get("name", "unknown")
                        if service_elem is not None
                        else "unknown",
                        "product": service_elem.get("product", "")
                        if service_elem is not None
                        else "",
                        "version": service_elem.get("version", "")
                        if service_elem is not None
                        else "",
                    }
                    results.append(port_info)

        except ElementTree.ParseError as exc:
            logger.warning("ReconAgent: nmap XML parse error: %s", exc)
        except FileNotFoundError:
            logger.warning("ReconAgent: nmap XML output file not found: %s", xml_path)
        except Exception as exc:
            logger.warning("ReconAgent: error parsing nmap XML: %s", exc)

        return results

    async def _run_subfinder(self, domain: str) -> List[str]:
        """
        Run subfinder for subdomain enumeration.

        Returns a list of discovered subdomain strings.
        Falls back to empty list if subfinder is not installed.
        """
        subdomains: List[str] = []
        try:
            cmd = ["subfinder", "-d", domain, "-silent"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=120
            )
            raw_output = stdout.decode(errors="replace")
            subdomains = [
                line.strip()
                for line in raw_output.splitlines()
                if line.strip()
            ]
            logger.info(
                "ReconAgent %s: subfinder found %d subdomains for '%s'",
                self.agent_id,
                len(subdomains),
                domain,
            )
        except FileNotFoundError:
            logger.debug("ReconAgent: subfinder not installed — skipping subdomain enumeration.")
        except asyncio.TimeoutError:
            logger.warning("ReconAgent: subfinder timed out for domain '%s'", domain)
        except Exception as exc:
            logger.warning("ReconAgent: subfinder error: %s", exc)

        return subdomains

    async def _probe_http(self, host: str, port: str, service: str) -> dict:
        """
        Probe an HTTP/HTTPS endpoint and return metadata.

        Returns a dict with status_code, title, server header, and redirect info.
        """
        import urllib.request
        import urllib.error

        scheme = "https" if service in ("https", "https-alt") else "http"
        url = f"{scheme}://{host}:{port}/"

        http_info: dict = {
            "url": url,
            "host": host,
            "port": port,
            "scheme": scheme,
            "status_code": None,
            "title": None,
            "server": None,
            "redirect_url": None,
        }

        # Try httpx tool first if available
        httpx_tool = self.tools.get("httpx")
        if httpx_tool is not None and hasattr(httpx_tool, "probe"):
            try:
                result = await httpx_tool.probe(url)
                http_info.update(result)
                return http_info
            except Exception:
                pass

        # Fall back to stdlib urllib (async wrapper)
        try:
            loop = asyncio.get_event_loop()
            response_data = await loop.run_in_executor(
                None, self._urllib_probe, url
            )
            http_info.update(response_data)
        except Exception as exc:
            http_info["error"] = str(exc)
            logger.debug("ReconAgent: HTTP probe error for %s: %s", url, exc)

        return http_info

    @staticmethod
    def _urllib_probe(url: str) -> dict:
        """Blocking HTTP probe using urllib."""
        import urllib.request
        import urllib.error
        import ssl

        result: dict = {}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Overwatch-Recon/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                result["status_code"] = resp.status
                result["server"] = resp.headers.get("Server", "")
                body = resp.read(4096).decode(errors="replace")
                # Extract <title>
                title_match = re.search(
                    r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL
                )
                result["title"] = (
                    title_match.group(1).strip() if title_match else None
                )
        except urllib.error.HTTPError as exc:
            result["status_code"] = exc.code
        except urllib.error.URLError as exc:
            result["error"] = str(exc.reason)
        except Exception as exc:
            result["error"] = str(exc)

        return result

    # ─────────────────────── Utilities ───────────────────────────

    def _resolve_target(self) -> str:
        """Extract the primary target from scope_subset or objective text."""
        if self.scope_subset and "target" in self.scope_subset:
            return str(self.scope_subset["target"])
        # Try to extract IP/hostname from objective string
        ip_match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
            r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
            self.objective,
        )
        if ip_match:
            return ip_match.group(0)
        return self.objective.strip()

    @staticmethod
    def _looks_like_domain(target: str) -> bool:
        """Return True if target looks like a domain name (not a bare IP)."""
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        return not ip_pattern.match(target) and "." in target

    @staticmethod
    def _service_to_vuln_type(service: str) -> Optional[str]:
        """Map a service name to a likely vulnerability type for knowledge_base lookup."""
        mapping = {
            "http": "xss",
            "https": "xss",
            "mysql": "sql_injection",
            "postgresql": "sql_injection",
            "ftp": "unencrypted_protocol",
            "telnet": "unencrypted_protocol",
            "smb": "smb_vulnerability",
            "redis": "unauthenticated_service",
            "mongodb": "unauthenticated_service",
        }
        return mapping.get(service.lower())
