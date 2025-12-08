"""
Pydantic schemas for Target endpoints.
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator
import re


class TargetBase(BaseModel):
    """Base target schema."""
    name: str = Field(..., min_length=1, max_length=255)
    url: Optional[str] = Field(None, max_length=512)
    ip_address: Optional[str] = Field(None, max_length=45)
    scope_rules: dict = Field(default_factory=dict)
    allowed_hosts: List[str] = Field(default_factory=list)
    allowed_ports: List[int] = Field(default_factory=list)

    @field_validator('ip_address')
    @classmethod
    def validate_ip(cls, v):
        """Validate IP address format."""
        if v and not _is_valid_ip(v):
            raise ValueError('Invalid IP address format')
        return v


class TargetCreate(TargetBase):
    """Schema for creating a target."""
    pass


class TargetUpdate(BaseModel):
    """Schema for updating a target."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    url: Optional[str] = None
    ip_address: Optional[str] = None
    scope_rules: Optional[dict] = None
    allowed_hosts: Optional[List[str]] = None
    allowed_ports: Optional[List[int]] = None


class TargetResponse(TargetBase):
    """Schema for target response."""
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


def _is_valid_ip(ip: str) -> bool:
    """Simple IP validation."""
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    return bool(re.match(ipv4_pattern, ip) or re.match(cidr_pattern, ip))
