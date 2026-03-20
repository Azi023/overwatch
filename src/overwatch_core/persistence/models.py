"""
Database models for Overwatch.
Uses SQLAlchemy ORM for PostgreSQL.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional, List
from enum import Enum as PyEnum  
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    JSON,
    Float,
    Boolean,
    ForeignKey,
)
from sqlalchemy import Enum as SQLEnum  # SQLAlchemy Enum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from typing import Optional, List, Dict, Any


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


# -----------------------------
# Enums
# -----------------------------
class ScanStatus(str, PyEnum):
    """Scan job status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, PyEnum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# -----------------------------
# Target model
# -----------------------------
class Target(Base):
    """Target systems to be tested."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # Scope definition
    scope_rules: Mapped[dict] = mapped_column(JSON, default=dict)
    allowed_hosts: Mapped[list] = mapped_column(JSON, default=list)
    allowed_ports: Mapped[list] = mapped_column(JSON, default=list)

    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    scan_jobs: Mapped[list["ScanJob"]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
    )

    observations = relationship("ObservationModel", back_populates="target")

# -----------------------------
# ScanJob model
# -----------------------------
class ScanJob(Base):
    """Individual scan jobs."""

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))

    # Job details
    scan_type: Mapped[str] = mapped_column(String(100))  # nmap, nuclei, sqli, etc.
    status: Mapped[ScanStatus] = mapped_column(
        SQLEnum(ScanStatus, name="scanstatus"),  # SQLAlchemy Enum
        default=ScanStatus.PENDING,
        nullable=False,
    )

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Results
    raw_output_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Relationships
    target: Mapped["Target"] = relationship(back_populates="scan_jobs")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan_job",
        cascade="all, delete-orphan",
    )
    ai_decisions: Mapped[list["AIDecision"]] = relationship(
        back_populates="scan_job",
        cascade="all, delete-orphan",
    )
    observations: Mapped[list["ObservationModel"]] = relationship(
        back_populates="scan_job",
        cascade="all, delete-orphan",
    )

    def __init__(self, **kwargs):
        """Initialize with default status if not provided."""
        if 'status' not in kwargs:
            kwargs['status'] = ScanStatus.PENDING
        super().__init__(**kwargs)

# -----------------------------
# Finding model
# -----------------------------
class Finding(Base):
    """Security vulnerabilities discovered."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))

    # Vulnerability details
    vulnerability_type: Mapped[str] = mapped_column(
        String(255)
    )  # SQL Injection, XSS, etc.
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)

    # Location
    url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Severity & Confidence
    severity: Mapped[SeverityLevel] = mapped_column(
        SQLEnum(SeverityLevel, name="severitylevel"),
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(default=0.0)  # 0.0 to 1.0

    # Validation
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)

    # Evidence
    proof_of_concept: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    screenshot_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # Remediation
    remediation_advice: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    scan_job: Mapped["ScanJob"] = relationship(back_populates="findings")


# -----------------------------
# AIDecision model
# -----------------------------
class AIDecision(Base):
    """Log of all AI agent decisions."""

    __tablename__ = "ai_decisions"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))

    # Decision details
    decision_type: Mapped[str] = mapped_column(
        String(100)
    )  # scan, exploit, validate, etc.
    action: Mapped[str] = mapped_column(String(255))
    reasoning: Mapped[str] = mapped_column(Text)

    # Parameters & Results
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    outcome: Mapped[dict] = mapped_column(JSON, default=dict)
    success: Mapped[bool] = mapped_column(Boolean)

    # Confidence & Risk
    confidence: Mapped[float] = mapped_column(default=0.0)
    risk_level: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Approval tracking
    required_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Metadata
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    agent_model: Mapped[str] = mapped_column(String(100), default="claude-sonnet-4")

    # Relationships
    scan_job: Mapped["ScanJob"] = relationship(back_populates="ai_decisions")


# -----------------------------
# Observation model
# -----------------------------


class ObservationModel(Base):
    """
    Stores scan observations for learning.
    
    Every scan creates observations. Each observation captures:
    - What the scanner saw (raw_data)
    - Numeric features for ML (features)
    - What predictors thought (predictions)
    - What actually was true (ground_truth)
    """
    __tablename__ = "observations"
    
    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    observation_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Links
    target_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    scan_job_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Observation content
    raw_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    features: Mapped[Dict[str, float]] = mapped_column(JSON, nullable=False, default=dict)
    context_ids: Mapped[List[str]] = mapped_column(JSON, nullable=True, default=list)
    predictions: Mapped[Dict[str, float]] = mapped_column(JSON, nullable=False, default=dict)
    
    # Ground truth (filled via validation)
    ground_truth: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    ground_truth_source: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    ground_truth_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    target: Mapped["Target"] = relationship(back_populates="observations")
    scan_job: Mapped["ScanJob"] = relationship(back_populates="observations")
    feedback: Mapped[List["FeedbackModel"]] = relationship(back_populates="observation")


# -----------------------------
# Feedback model
# -----------------------------

class FeedbackModel(Base):
    """
    Stores human feedback for learning.
    
    This is how the system learns from human validation.
    Every feedback creates ground truth for training.
    """
    __tablename__ = "feedback"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    
    # Links to what was validated
    observation_id: Mapped[Optional[str]] = mapped_column(
        String(16), 
        ForeignKey("observations.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    finding_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    
    # Feedback details
    feedback_type: Mapped[str] = mapped_column(
        String(50), 
        nullable=False,
        index=True
    )
    feedback_value: Mapped[Dict[str, Any]] = mapped_column(
        JSON, 
        nullable=False,
        default=dict
    )
    
    # Metadata
    source: Mapped[str] = mapped_column(
        String(50), 
        nullable=False,
        default="api"
    )
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, 
        nullable=True
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime, 
        nullable=False,
        default=datetime.utcnow
    )
    
    # Relationships
    observation: Mapped[Optional["ObservationModel"]] = relationship(
        back_populates="feedback"
    )

# Update existing Finding model to add validation fields
class FindingUpdates:
    """
    Add these fields to your existing Finding model.
    """
    # Validation status
    validated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    validation_result: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    
    # Link to observation that generated this finding
    observation_id: Mapped[Optional[str]] = mapped_column(
        String(16),
        ForeignKey("observations.id", ondelete="SET NULL"),
        nullable=True
    )


# Update Target model to add observations relationship
class TargetUpdates:
    """
    Add this relationship to your existing Target model.
    """
    observations: Mapped[List["ObservationModel"]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan"
    )


# Update ScanJob model to add observations relationship  
class ScanJobUpdates:
    """
    Add this relationship to your existing ScanJob model.
    """
    observations: Mapped[List["ObservationModel"]] = relationship(
        back_populates="scan_job",
        cascade="all, delete-orphan"
    )