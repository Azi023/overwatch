"""
Pydantic schemas for Target API endpoints.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Human-readable target name")
    url: Optional[str] = Field(None, max_length=512, description="Primary URL for web targets")
    ip_address: Optional[str] = Field(None, max_length=45, description="IP address (IPv4 or IPv6)")
    scope_rules: Dict[str, Any] = Field(default_factory=dict, description="Scope constraints")
    allowed_hosts: List[str] = Field(default_factory=list, description="Hostnames in scope")
    allowed_ports: List[int] = Field(default_factory=list, description="Ports in scope")


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
