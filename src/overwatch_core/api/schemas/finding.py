"""
Pydantic schemas for Finding endpoints.
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel

from src.overwatch_core.persistence.models import SeverityLevel


class FindingResponse(BaseModel):
    """Schema for finding response."""
    id: int
    scan_job_id: int
    vulnerability_type: str
    title: str
    description: str
    url: Optional[str]
    parameter: Optional[str]
    severity: SeverityLevel
    confidence: float
    validated: bool
    false_positive: bool
    proof_of_concept: Optional[str]
    remediation_advice: Optional[str]
    cvss_score: Optional[float]
    cve_ids: List[str]
    discovered_at: datetime

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    """Schema for updating a finding."""
    validated: Optional[bool] = None
    false_positive: Optional[bool] = None
    remediation_advice: Optional[str] = None
