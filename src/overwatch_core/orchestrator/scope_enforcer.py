"""
Scope enforcement to prevent out-of-scope scanning.
"""
import re
import ipaddress
import logging
from urllib.parse import urlparse
from typing import List

from src.overwatch_core.persistence.models import Target

logger = logging.getLogger(__name__)


class ScopeEnforcer:
    """
    Enforces scanning scope rules to prevent unauthorized scanning.
    """

    def __init__(self, target: Target):
        self.target = target
        self.allowed_hosts = target.allowed_hosts or []
        self.allowed_ports = target.allowed_ports or []
        self.scope_rules = target.scope_rules or {}

    def is_in_scope(self, url_or_ip: str) -> bool:
        """
        Check if a URL or IP is within the allowed scope.

        Args:
            url_or_ip: URL or IP address to check

        Returns:
            True if in scope, False otherwise
        """
        # Parse URL if it's a URL
        if url_or_ip.startswith('http://') or url_or_ip.startswith('https://'):
            parsed = urlparse(url_or_ip)
            hostname = parsed.hostname
            port = parsed.port
        else:
            hostname = url_or_ip
            port = None

        # Check hostname/IP is allowed
        if not self._is_host_allowed(hostname):
            logger.warning(f"Host {hostname} is not in allowed hosts: {self.allowed_hosts}")
            return False

        # Check port is allowed (if specified)
        if port and self.allowed_ports and port not in self.allowed_ports:
            logger.warning(f"Port {port} is not in allowed ports: {self.allowed_ports}")
            return False

        return True

    def _is_host_allowed(self, hostname: str) -> bool:
        """
        Check if hostname is in allowed hosts.

        Supports:
        - Exact match: "example.com"
        - Wildcard: "*.example.com"
        - IP address: "192.168.1.1"
        - CIDR notation: "192.168.1.0/24"
        """
        if not self.allowed_hosts:
            # If no allowed hosts specified, only allow target's own host
            return hostname == self.target.url or hostname == self.target.ip_address

        for allowed in self.allowed_hosts:
            # Exact match
            if hostname == allowed:
                return True

            # Wildcard match
            if allowed.startswith('*.'):
                domain = allowed[2:]
                if hostname.endswith('.' + domain):
                    return True

            # CIDR notation (for IP ranges)
            if '/' in allowed:
                try:
                    ip = ipaddress.ip_address(hostname)
                    network = ipaddress.ip_network(allowed, strict=False)
                    if ip in network:
                        return True
                except ValueError:
                    continue

        return False

    def validate_ports(self, ports: List[int]) -> List[int]:
        """
        Filter ports to only those allowed in scope.

        Args:
            ports: List of ports to validate

        Returns:
            List of allowed ports
        """
        if not self.allowed_ports:
            return ports

        return [p for p in ports if p in self.allowed_ports]
