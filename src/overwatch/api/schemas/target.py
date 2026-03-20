"""
Pydantic schemas for Target API endpoints.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


# Only allow http/https schemes for target URLs
_ALLOWED_SCHEMES = {"http", "https"}


class TargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Human-readable target name")
    url: Optional[str] = Field(None, max_length=512, description="Primary URL for web targets")
    ip_address: Optional[str] = Field(None, max_length=45, description="IP address (IPv4 or IPv6)")
    scope_rules: Dict[str, Any] = Field(default_factory=dict, description="Scope constraints")
    allowed_hosts: List[str] = Field(default_factory=list, description="Hostnames in scope")
    allowed_ports: List[int] = Field(default_factory=list, description="Ports in scope")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in _ALLOWED_SCHEMES:
            raise ValueError(f"URL scheme must be http or https, got {parsed.scheme!r}")
        if not parsed.hostname:
            raise ValueError("URL must have a valid hostname")
        return v

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v!r}")
        return v

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, v: List[int]) -> List[int]:
        for port in v:
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} out of valid range (1-65535)")
        return v


class TargetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    url: Optional[str] = Field(None, max_length=512)
    ip_address: Optional[str] = Field(None, max_length=45)
    scope_rules: Optional[Dict[str, Any]] = None
    allowed_hosts: Optional[List[str]] = None
    allowed_ports: Optional[List[int]] = None


class TargetResponse(BaseModel):
    id: int
    name: str
    url: Optional[str]
    ip_address: Optional[str]
    scope_rules: Dict[str, Any]
    allowed_hosts: List[str]
    allowed_ports: List[int]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
