"""
Pydantic schemas for Scan API endpoints.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from ...persistence.models import ScanStatus


class ScanCreate(BaseModel):
    target_id: int = Field(..., description="ID of the target to scan")
    scan_type: str = Field(..., min_length=1, max_length=100, description="Type of scan (e.g. 'nmap', 'web')")
    config: Dict[str, Any] = Field(default_factory=dict, description="Scanner-specific configuration")
    engagement_id: Optional[int] = Field(None, description="Optional engagement this scan belongs to")


class ScanUpdate(BaseModel):
    status: Optional[ScanStatus] = None


class ScanResponse(BaseModel):
    id: int
    target_id: int
    engagement_id: Optional[int]
    scan_type: str
    status: ScanStatus
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    raw_output_path: Optional[str]
    summary: Optional[Dict[str, Any]]

    model_config = {"from_attributes": True}
