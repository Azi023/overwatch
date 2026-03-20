"""
Pydantic schemas for Engagement API endpoints.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ...persistence.models import EngagementStatus


class EngagementCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Engagement name")
    description: Optional[str] = Field(None, description="Detailed description")
    target_id: int = Field(..., description="Target to test")
    objectives: List[str] = Field(default_factory=list, description="Testing objectives")
    scope_config: Dict[str, Any] = Field(default_factory=dict, description="Scope constraints")
    token_budget: Optional[int] = Field(None, ge=0, description="Max tokens to spend")
    time_budget_seconds: Optional[int] = Field(None, ge=0, description="Max runtime in seconds")
    cost_budget_usd: Optional[float] = Field(None, ge=0.0, description="Max cost in USD")


class EngagementUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    objectives: Optional[List[str]] = None
    scope_config: Optional[Dict[str, Any]] = None


class EngagementResponse(BaseModel):
    id: int
    target_id: int
    name: str
    description: Optional[str]
    status: EngagementStatus
    objectives: List[str]
    scope_config: Dict[str, Any]
    token_budget: Optional[int]
    time_budget_seconds: Optional[int]
    cost_budget_usd: Optional[float]
    tokens_used: int
    cost_usd: float
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    kill_switch_activated: bool
    kill_switch_reason: Optional[str]

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    """Embedded finding in engagement context."""
    id: int
    vulnerability_type: str
    title: str
    description: str
    severity: str
    confidence: float
    validated: bool
    false_positive: bool
    proof_of_concept: Optional[str]
    remediation_advice: Optional[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    cwe_ids: List[str]
    mitre_techniques: List[str]
    url: Optional[str]
    tool_name: Optional[str]
    agent_type: Optional[str]
    discovered_at: datetime

    model_config = {"from_attributes": True}


class TimelineEvent(BaseModel):
    """A single event in the engagement timeline."""
    timestamp: datetime
    event_type: str
    agent_id: Optional[str]
    agent_type: Optional[str]
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)


class FeedbackCreate(BaseModel):
    finding_id: Optional[int] = Field(None, description="Finding to attach feedback to")
    observation_id: Optional[str] = Field(None, max_length=16, description="Observation ID")
    feedback_type: str = Field(..., min_length=1, max_length=50, description="Type of feedback")
    feedback_value: Dict[str, Any] = Field(..., description="Feedback payload")
    user_id: Optional[int] = Field(None, description="Submitting user ID")
