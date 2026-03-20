"""
Scope enforcement for Overwatch engagements.

Validates every planned action against the engagement's scope configuration
before it is executed. Supports exact host matching, wildcards, and CIDR ranges.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ──────────────────────────── Result dataclass ────────────────────────────

@dataclass(frozen=True)
class ScopeCheckResult:
    """Immutable result of a scope check."""

    allowed: bool
    reason: str


# ──────────────────────────── Helpers ────────────────────────────

def _hostname_matches(hostname: str, pattern: str) -> bool:
    """
    Return True if hostname matches pattern.

    Supported patterns:
    - Exact match:    "api.example.com"
    - Wildcard:       "*.example.com"  (one level)
    - Double wild:    "**.example.com" (any depth)
    """
    hostname = hostname.lower().strip(".")
    pattern = pattern.lower().strip(".")

    if pattern.startswith("**."):
        suffix = pattern[3:]
        return hostname == suffix or hostname.endswith("." + suffix)

    if pattern.startswith("*."):
        suffix = pattern[2:]
        parts = hostname.split(".")
        if len(parts) < 2:
            return False
        return hostname.endswith("." + suffix) and "." not in hostname[: -(len(suffix) + 1)]

    return hostname == pattern


def _ip_in_cidr(ip_str: str, cidr: str) -> bool:
    """Return True if ip_str falls within the CIDR network."""
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ──────────────────────────── ScopeEnforcer ────────────────────────────

class ScopeEnforcer:
    """
    Validates hosts, ports, URLs, and actions against the engagement scope.

    scope_config schema::

        {
          "allowed_hosts": ["example.com", "*.example.com", "10.0.0.0/24"],
          "allowed_ports": [80, 443, 8080],          # empty = all ports allowed
          "excluded_paths": ["/admin/backup", "/api/delete"],
          "time_windows": [],                          # future: restrict by time-of-day
          "allowed_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"]
        }
    """

    _ALWAYS_BLOCKED_PORTS = frozenset({22, 3389})  # SSH/RDP — require explicit allowance

    def __init__(self, scope_config: Dict[str, Any]) -> None:
        self._allowed_hosts: List[str] = scope_config.get("allowed_hosts", [])
        self._allowed_ports: List[int] = [int(p) for p in scope_config.get("allowed_ports", [])]
        self._excluded_paths: List[str] = scope_config.get("excluded_paths", [])
        self._allowed_methods: List[str] = [
            m.upper() for m in scope_config.get("allowed_methods", [
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
            ])
        ]

    # ── Host checking ──────────────────────────────────────────────────────

    def is_host_allowed(self, hostname: str) -> bool:
        """
        Return True if hostname is within scope.

        Checks:
        1. Exact string match
        2. Wildcard pattern match
        3. CIDR match (for IP addresses)
        """
        if not hostname:
            return False

        hostname_clean = hostname.lower().strip()

        for pattern in self._allowed_hosts:
            pattern_clean = pattern.lower().strip()

            # CIDR for IP inputs
            if "/" in pattern_clean and _is_ip_address(hostname_clean):
                if _ip_in_cidr(hostname_clean, pattern_clean):
                    return True
                continue

            if _hostname_matches(hostname_clean, pattern_clean):
                return True

        return False

    # ── Port checking ──────────────────────────────────────────────────────

    def is_port_allowed(self, port: int) -> bool:
        """
        Return True if port is within scope.

        If allowed_ports is empty, all ports are allowed *except* always-blocked ones
        unless they are explicitly listed in allowed_ports.
        """
        if port in self._ALWAYS_BLOCKED_PORTS and port not in self._allowed_ports:
            return False
        if not self._allowed_ports:
            return True
        return port in self._allowed_ports

    # ── Path checking ──────────────────────────────────────────────────────

    def _is_path_excluded(self, path: str) -> bool:
        """Return True if the path matches an excluded prefix or exact path."""
        path_clean = path.rstrip("/")
        for excluded in self._excluded_paths:
            excluded_clean = excluded.rstrip("/")
            if path_clean == excluded_clean or path_clean.startswith(excluded_clean + "/"):
                return True
        return False

    # ── URL checking ──────────────────────────────────────────────────────

    def is_url_allowed(self, url: str, method: str = "GET") -> bool:
        """
        Return True if the given URL (and HTTP method) is within scope.

        Checks: host allowed + port allowed + path not excluded + method allowed.
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return False

        hostname = parsed.hostname or ""
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        path = parsed.path or "/"

        if not self.is_host_allowed(hostname):
            return False
        if not self.is_port_allowed(port):
            return False
        if self._is_path_excluded(path):
            return False
        if method.upper() not in self._allowed_methods:
            return False

        return True

    # ── General action checking ────────────────────────────────────────────

    def check_action(
        self,
        action_type: str,
        target: str,
        **kwargs: Any,
    ) -> ScopeCheckResult:
        """
        Unified scope check for any planned action.

        Args:
            action_type:  One of: "http_request", "port_scan", "dns_lookup",
                          "vulnerability_scan", "host_connect", or any string.
            target:       The target string (URL, host:port, IP, hostname).
            **kwargs:     Extra context (e.g., method="POST", port=8080).

        Returns:
            ScopeCheckResult with allowed=True/False and a human-readable reason.
        """
        action_type = action_type.lower()

        if action_type == "http_request":
            url = target
            method = str(kwargs.get("method", "GET")).upper()
            if self.is_url_allowed(url, method):
                return ScopeCheckResult(allowed=True, reason="URL and method are in scope.")
            return ScopeCheckResult(
                allowed=False,
                reason=f"URL '{url}' or method '{method}' is out of scope.",
            )

        if action_type == "port_scan":
            host = target
            ports: List[int] = kwargs.get("ports", [])
            if not self.is_host_allowed(host):
                return ScopeCheckResult(
                    allowed=False, reason=f"Host '{host}' is not in the allowed hosts list."
                )
            if ports:
                blocked = [p for p in ports if not self.is_port_allowed(p)]
                if blocked:
                    return ScopeCheckResult(
                        allowed=False,
                        reason=f"Ports {blocked} are not in the allowed ports list.",
                    )
            return ScopeCheckResult(allowed=True, reason="Host and ports are in scope.")

        if action_type in {"dns_lookup", "subdomain_enum"}:
            host = target
            if self.is_host_allowed(host):
                return ScopeCheckResult(allowed=True, reason="Host is in scope.")
            # Allow lookup of parent domains if child is in scope
            for allowed in self._allowed_hosts:
                if allowed.lstrip("*.") == host or host.endswith("." + allowed.lstrip("*.")):
                    return ScopeCheckResult(
                        allowed=True,
                        reason="Host is a parent of an in-scope pattern.",
                    )
            return ScopeCheckResult(
                allowed=False, reason=f"Host '{host}' is not in scope."
            )

        if action_type in {"host_connect", "vulnerability_scan"}:
            host = target
            port = kwargs.get("port")
            if not self.is_host_allowed(host):
                return ScopeCheckResult(
                    allowed=False, reason=f"Host '{host}' is not in scope."
                )
            if port is not None and not self.is_port_allowed(int(port)):
                return ScopeCheckResult(
                    allowed=False, reason=f"Port {port} is not in scope."
                )
            return ScopeCheckResult(allowed=True, reason="Host and port are in scope.")

        # Generic: try to parse target as a URL first, then as a hostname
        if "://" in target:
            if self.is_url_allowed(target):
                return ScopeCheckResult(allowed=True, reason="Target URL is in scope.")
            return ScopeCheckResult(allowed=False, reason=f"Target URL '{target}' is out of scope.")

        if self.is_host_allowed(target):
            return ScopeCheckResult(allowed=True, reason="Target host is in scope.")

        return ScopeCheckResult(
            allowed=False,
            reason=f"Target '{target}' does not match any in-scope pattern for action '{action_type}'.",
        )
