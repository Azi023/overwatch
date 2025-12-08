"""
Pydantic schemas for Scan endpoints.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

from src.overwatch_core.persistence.models import ScanStatus


class ScanCreate(BaseModel):
    """Schema for creating a scan."""
    target_id: int
    scan_type: str = Field(..., description="Type of scan: nmap, nuclei, etc.")
    config: dict = Field(default_factory=dict, description="Scan configuration")


class ScanResponse(BaseModel):
    """Schema for scan response."""
    id: int
    target_id: int
    scan_type: str
    status: ScanStatus
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    raw_output_path: Optional[str]
    summary: Optional[dict]

    class Config:
        from_attributes = True


class ScanUpdate(BaseModel):
    """Schema for updating a scan."""
    status: Optional[ScanStatus] = None
    summary: Optional[dict] = None
