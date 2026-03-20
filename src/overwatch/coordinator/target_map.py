"""
In-memory representation of the attack surface discovered during an engagement.

TargetMap stores hosts, services, endpoints, and technologies.
It follows an immutable update pattern — mutating methods return a new TargetMap
so that callers always have a consistent snapshot.
"""
from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ──────────────────────────── Internal dataclasses ────────────────────────────

@dataclass(frozen=True)
class ServiceRecord:
    port: int
    protocol: str          # "tcp" or "udp"
    service_name: str
    version: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service_name": self.service_name,
            "version": self.version,
            "properties": self.properties,
        }


@dataclass(frozen=True)
class HostRecord:
    ip: str
    hostname: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    services: tuple = field(default_factory=tuple)          # tuple[ServiceRecord]
    technologies: tuple = field(default_factory=tuple)      # tuple[dict]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "properties": self.properties,
            "services": [s.to_dict() for s in self.services],
            "technologies": list(self.technologies),
        }


@dataclass(frozen=True)
class EndpointRecord:
    url: str
    method: str
    parameters: tuple = field(default_factory=tuple)        # tuple[str]
    auth_required: Optional[bool] = None
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": list(self.parameters),
            "auth_required": self.auth_required,
            "properties": self.properties,
        }


# ──────────────────────────── TargetMap ────────────────────────────

class TargetMap:
    """
    Immutable-update representation of all discovered attack surface.

    Mutating methods (add_host, add_service, etc.) return a NEW TargetMap
    with the change applied rather than modifying self. This enables callers
    to keep a reference to a previous snapshot while building a new one.

    Internal state is stored in plain dicts keyed by canonical identifiers.
    """

    def __init__(
        self,
        engagement_id: int,
        _hosts: Optional[Dict[str, HostRecord]] = None,
        _endpoints: Optional[Dict[str, EndpointRecord]] = None,
    ) -> None:
        self._engagement_id = engagement_id
        # key: IP address string
        self._hosts: Dict[str, HostRecord] = _hosts if _hosts is not None else {}
        # key: "METHOD:url"
        self._endpoints: Dict[str, EndpointRecord] = _endpoints if _endpoints is not None else {}

    # ── Internal copy helper ───────────────────────────────────────────────

    def _clone(
        self,
        hosts: Optional[Dict[str, HostRecord]] = None,
        endpoints: Optional[Dict[str, EndpointRecord]] = None,
    ) -> "TargetMap":
        return TargetMap(
            engagement_id=self._engagement_id,
            _hosts=hosts if hosts is not None else dict(self._hosts),
            _endpoints=endpoints if endpoints is not None else dict(self._endpoints),
        )

    # ── Host operations ────────────────────────────────────────────────────

    def add_host(
        self,
        ip: str,
        hostname: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> "TargetMap":
        """
        Add or update a host record.

        If a host with this IP already exists, its hostname and properties
        are merged (new values take precedence). Existing services are preserved.
        Returns a new TargetMap.
        """
        existing = self._hosts.get(ip)
        merged_hostname = hostname or (existing.hostname if existing else None)
        merged_props = {**(existing.properties if existing else {}), **(properties or {})}
        existing_services = existing.services if existing else ()
        existing_techs = existing.technologies if existing else ()

        new_host = HostRecord(
            ip=ip,
            hostname=merged_hostname,
            properties=merged_props,
            services=existing_services,
            technologies=existing_techs,
        )
        new_hosts = {**self._hosts, ip: new_host}
        logger.debug("TargetMap.add_host: %s (%s)", ip, merged_hostname)
        return self._clone(hosts=new_hosts)

    def add_service(
        self,
        host: str,
        port: int,
        protocol: str,
        service_name: str,
        version: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> "TargetMap":
        """
        Add a service to a host (creates the host if not present).

        If a service on the same port/protocol already exists, it is replaced.
        Returns a new TargetMap.
        """
        updated = self if host in self._hosts else self.add_host(host)

        existing_host = updated._hosts[host]
        new_service = ServiceRecord(
            port=port,
            protocol=protocol.lower(),
            service_name=service_name,
            version=version,
            properties=properties or {},
        )

        # Replace existing service on same port+protocol or append
        services_list = [
            s for s in existing_host.services
            if not (s.port == port and s.protocol == protocol.lower())
        ]
        services_list.append(new_service)

        new_host = HostRecord(
            ip=existing_host.ip,
            hostname=existing_host.hostname,
            properties=existing_host.properties,
            services=tuple(services_list),
            technologies=existing_host.technologies,
        )
        new_hosts = {**updated._hosts, host: new_host}
        logger.debug("TargetMap.add_service: %s:%d/%s (%s)", host, port, protocol, service_name)
        return updated._clone(hosts=new_hosts)

    def add_technology(
        self,
        host: str,
        tech_name: str,
        version: Optional[str] = None,
    ) -> "TargetMap":
        """
        Tag a technology stack item to a host.

        Deduplicates by tech_name (case-insensitive). Returns a new TargetMap.
        """
        updated = self if host in self._hosts else self.add_host(host)
        existing_host = updated._hosts[host]

        existing_tech_names = {t["name"].lower() for t in existing_host.technologies}
        if tech_name.lower() in existing_tech_names:
            return updated  # No change needed

        new_tech = {"name": tech_name, "version": version}
        new_techs = existing_host.technologies + (new_tech,)

        new_host = HostRecord(
            ip=existing_host.ip,
            hostname=existing_host.hostname,
            properties=existing_host.properties,
            services=existing_host.services,
            technologies=new_techs,
        )
        new_hosts = {**updated._hosts, host: new_host}
        logger.debug("TargetMap.add_technology: %s → %s %s", host, tech_name, version or "")
        return updated._clone(hosts=new_hosts)

    # ── Endpoint operations ────────────────────────────────────────────────

    def add_endpoint(
        self,
        url: str,
        method: str,
        parameters: Optional[List[str]] = None,
        auth_required: Optional[bool] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> "TargetMap":
        """
        Add or update a web endpoint.

        Key is "METHOD:url" (case-normalised). Returns a new TargetMap.
        """
        method_upper = method.upper()
        key = f"{method_upper}:{url}"

        existing = self._endpoints.get(key)
        merged_auth = auth_required if auth_required is not None else (
            existing.auth_required if existing else None
        )
        merged_props = {**(existing.properties if existing else {}), **(properties or {})}
        merged_params = tuple(parameters) if parameters else (
            existing.parameters if existing else ()
        )

        new_endpoint = EndpointRecord(
            url=url,
            method=method_upper,
            parameters=merged_params,
            auth_required=merged_auth,
            properties=merged_props,
        )
        new_endpoints = {**self._endpoints, key: new_endpoint}
        logger.debug("TargetMap.add_endpoint: %s %s", method_upper, url)
        return self._clone(endpoints=new_endpoints)

    # ── Query methods ──────────────────────────────────────────────────────

    def get_all_services(self) -> List[Dict[str, Any]]:
        """Return a flat list of all services across all hosts."""
        result = []
        for host_record in self._hosts.values():
            for svc in host_record.services:
                result.append({
                    "host_ip": host_record.ip,
                    "host_hostname": host_record.hostname,
                    **svc.to_dict(),
                })
        return result

    def get_web_endpoints(self) -> List[Dict[str, Any]]:
        """Return all recorded web endpoints as dicts."""
        return [ep.to_dict() for ep in self._endpoints.values()]

    def get_host(self, ip: str) -> Optional[Dict[str, Any]]:
        """Return a single host record as a dict, or None if not found."""
        record = self._hosts.get(ip)
        return record.to_dict() if record else None

    def get_all_hosts(self) -> List[Dict[str, Any]]:
        """Return all host records as dicts."""
        return [h.to_dict() for h in self._hosts.values()]

    def get_attack_surface_summary(self) -> Dict[str, Any]:
        """
        Return a concise summary of the total attack surface.

        Useful for feeding into LLM planning prompts.
        """
        all_services = self.get_all_services()
        web_services = [
            s for s in all_services
            if s.get("service_name", "").lower() in {"http", "https", "http-proxy", "http-alt"}
            or s.get("port") in {80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 8888}
        ]

        tech_names: List[str] = []
        for h in self._hosts.values():
            for t in h.technologies:
                name = t.get("name", "")
                if name and name not in tech_names:
                    tech_names.append(name)

        return {
            "engagement_id": self._engagement_id,
            "total_hosts": len(self._hosts),
            "total_services": len(all_services),
            "web_services_count": len(web_services),
            "total_endpoints": len(self._endpoints),
            "technology_stack": tech_names,
            "host_ips": list(self._hosts.keys()),
        }

    # ── Serialisation ──────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Full serialisable representation of the target map."""
        return {
            "engagement_id": self._engagement_id,
            "hosts": {ip: record.to_dict() for ip, record in self._hosts.items()},
            "endpoints": {key: ep.to_dict() for key, ep in self._endpoints.items()},
            "summary": self.get_attack_surface_summary(),
        }

    def __len__(self) -> int:
        return len(self._hosts)

    def __repr__(self) -> str:
        return (
            f"TargetMap(engagement_id={self._engagement_id}, "
            f"hosts={len(self._hosts)}, endpoints={len(self._endpoints)})"
        )
