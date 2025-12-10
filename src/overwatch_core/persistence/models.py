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

    def __init__(self, **kwargs):
        """Initialize with default status if not provided."""
        if 'status' not in kwargs:
            kwargs['status'] = ScanStatus.PENDING
        super().__init__(**kwargs)

observations = relationship("ObservationModel", back_populates="scan_job")

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
    """Observation storage for learning."""
    __tablename__ = "observations"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    observation_type: Mapped[str] = mapped_column(String(50), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), nullable=False)
    
    raw_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    features: Mapped[dict] = mapped_column(JSONB, nullable=False, default={})
    context_ids: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String(16)), nullable=True, default=lambda: [])
    predictions: Mapped[dict] = mapped_column(JSONB, nullable=False, default={})
    
    ground_truth: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    ground_truth_source: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    ground_truth_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    target = relationship("Target", back_populates="observations")
    scan_job = relationship("ScanJob", back_populates="observations")


class FeedbackModel(Base):
    """Human feedback on findings for learning."""
    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    observation_id: Mapped[str] = mapped_column(String(16), ForeignKey("observations.id"), nullable=False)
    finding_id: Mapped[Optional[int]] = mapped_column(ForeignKey("findings.id"), nullable=True)
    
    feedback_type: Mapped[str] = mapped_column(String(50), nullable=False)
    feedback_value: Mapped[dict] = mapped_column(JSONB, nullable=False)
    
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    observation = relationship("ObservationModel")
    finding = relationship("Finding")