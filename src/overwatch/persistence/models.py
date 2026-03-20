"""
Database models for Overwatch V2.
SQLAlchemy 2.0 async ORM with PostgreSQL.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum as PyEnum
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    BigInteger,
)
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy import event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


@event.listens_for(Base, "init", propagate=True)
def _apply_column_defaults(target: Any, args: tuple, kwargs: dict) -> None:
    """Apply column defaults at Python instantiation time.

    SQLAlchemy only applies ``default=`` values during INSERT; this event
    ensures new instances carry correct attribute values before a flush so
    that unit tests and business logic can rely on them.

    Note: SQLAlchemy classifies ``default=list`` / ``default=dict`` as
    ``is_scalar=True`` (not ``is_callable``) because ``list``/``dict`` are
    types, not ``FunctionType`` instances. We handle both cases by checking
    whether the scalar arg is itself callable (e.g. list, dict) and calling
    it if so.
    """
    try:
        mapper = target.__class__.__mapper__
    except Exception:
        return
    for col_prop in mapper.column_attrs:
        col = col_prop.columns[0]
        attr_name = col_prop.key
        if attr_name in kwargs or col.default is None:
            continue
        if col.default.is_scalar:
            arg = col.default.arg
            kwargs[attr_name] = arg() if callable(arg) else arg
        elif col.default.is_callable and callable(col.default.arg):
            # SQLAlchemy wraps callables with a context arg; pass None.
            try:
                kwargs[attr_name] = col.default.arg(None)
            except TypeError:
                pass


# ──────────────────────────── Enums ────────────────────────────

class ScanStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EngagementStatus(str, PyEnum):
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    STOPPED = "stopped"
    FAILED = "failed"


class AgentStatus(str, PyEnum):
    SPAWNED = "spawned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    KILLED = "killed"


class ActionCategory(str, PyEnum):
    PASSIVE = "passive"
    ACTIVE = "active"
    INVASIVE = "invasive"
    DESTRUCTIVE = "destructive"


# ──────────────────────────── Target ────────────────────────────

class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    scope_rules: Mapped[dict] = mapped_column(JSON, default=dict)
    allowed_hosts: Mapped[list] = mapped_column(JSON, default=list)
    allowed_ports: Mapped[list] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    scan_jobs: Mapped[List["ScanJob"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    observations: Mapped[List["ObservationModel"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    engagements: Mapped[List["Engagement"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


# ──────────────────────────── Engagement ────────────────────────────

class Engagement(Base):
    """A full pentesting engagement against a target."""
    __tablename__ = "engagements"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))

    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[EngagementStatus] = mapped_column(
        SQLEnum(EngagementStatus, name="engagementstatus"),
        default=EngagementStatus.CREATED,
    )

    objectives: Mapped[list] = mapped_column(JSON, default=list)
    scope_config: Mapped[dict] = mapped_column(JSON, default=dict)

    # Budget / limits
    token_budget: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    time_budget_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cost_budget_usd: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Tracking
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Kill switch
    kill_switch_activated: Mapped[bool] = mapped_column(Boolean, default=False)
    kill_switch_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    target: Mapped["Target"] = relationship(back_populates="engagements")
    agent_runs: Mapped[List["AgentRun"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    attack_graph_nodes: Mapped[List["AttackGraphNode"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    findings: Mapped[List["Finding"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )


# ──────────────────────────── ScanJob ────────────────────────────

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    engagement_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("engagements.id"), nullable=True
    )

    scan_type: Mapped[str] = mapped_column(String(100))
    status: Mapped[ScanStatus] = mapped_column(
        SQLEnum(ScanStatus, name="scanstatus"),
        default=ScanStatus.PENDING,
        nullable=False,
    )

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    raw_output_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    target: Mapped["Target"] = relationship(back_populates="scan_jobs")
    findings: Mapped[List["Finding"]] = relationship(
        back_populates="scan_job", cascade="all, delete-orphan"
    )
    ai_decisions: Mapped[List["AIDecision"]] = relationship(
        back_populates="scan_job", cascade="all, delete-orphan"
    )
    observations: Mapped[List["ObservationModel"]] = relationship(
        back_populates="scan_job", cascade="all, delete-orphan"
    )


# ──────────────────────────── AgentRun ────────────────────────────

class AgentRun(Base):
    """Tracks an individual agent's lifecycle within an engagement."""
    __tablename__ = "agent_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))

    agent_type: Mapped[str] = mapped_column(String(100))  # recon, webapp, auth, triage
    agent_id: Mapped[str] = mapped_column(String(64))  # UUID
    objective: Mapped[str] = mapped_column(Text)

    status: Mapped[AgentStatus] = mapped_column(
        SQLEnum(AgentStatus, name="agentstatus"),
        default=AgentStatus.SPAWNED,
    )

    # Reasoning loop stats
    loop_iterations: Mapped[int] = mapped_column(Integer, default=0)
    hypotheses_tested: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    # Token / cost tracking
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)

    # System prompt (for meta-prompting tracking)
    system_prompt_version: Mapped[int] = mapped_column(Integer, default=1)
    current_system_prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Error tracking
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    spawned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    engagement: Mapped["Engagement"] = relationship(back_populates="agent_runs")


# ──────────────────────────── AttackGraph ────────────────────────────

class AttackGraphNode(Base):
    """Node in the attack graph (host, service, account, data asset)."""
    __tablename__ = "attack_graph_nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))

    node_type: Mapped[str] = mapped_column(String(50))  # host, service, account, data
    node_id: Mapped[str] = mapped_column(String(255))  # e.g., "192.168.1.1:80"
    label: Mapped[str] = mapped_column(String(255))

    properties: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)

    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    discovered_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    engagement: Mapped["Engagement"] = relationship(back_populates="attack_graph_nodes")
    outgoing_edges: Mapped[List["AttackGraphEdge"]] = relationship(
        back_populates="source_node",
        foreign_keys="AttackGraphEdge.source_node_id",
        cascade="all, delete-orphan",
    )
    incoming_edges: Mapped[List["AttackGraphEdge"]] = relationship(
        back_populates="target_node",
        foreign_keys="AttackGraphEdge.target_node_id",
        cascade="all, delete-orphan",
    )


class AttackGraphEdge(Base):
    """Edge in the attack graph (relationship between nodes)."""
    __tablename__ = "attack_graph_edges"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_node_id: Mapped[int] = mapped_column(ForeignKey("attack_graph_nodes.id"))
    target_node_id: Mapped[int] = mapped_column(ForeignKey("attack_graph_nodes.id"))

    edge_type: Mapped[str] = mapped_column(String(50))  # can_reach, has_credential, can_exploit, can_pivot
    properties: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    source_node: Mapped["AttackGraphNode"] = relationship(
        back_populates="outgoing_edges", foreign_keys=[source_node_id]
    )
    target_node: Mapped["AttackGraphNode"] = relationship(
        back_populates="incoming_edges", foreign_keys=[target_node_id]
    )


# ──────────────────────────── Credential ────────────────────────────

class Credential(Base):
    """Encrypted credential storage scoped per engagement."""
    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))

    credential_type: Mapped[str] = mapped_column(String(50))  # password, token, key, cookie
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    scope: Mapped[str] = mapped_column(String(255), default="engagement")

    # Encrypted value (Fernet)
    encrypted_value: Mapped[str] = mapped_column(Text)

    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True)


# ──────────────────────────── Memory ────────────────────────────

class Memory(Base):
    """Long-term cross-engagement memory (supports vector search via pgvector)."""
    __tablename__ = "memories"

    id: Mapped[int] = mapped_column(primary_key=True)

    memory_type: Mapped[str] = mapped_column(String(50))  # vulnerability_pattern, attack_chain, tool_insight
    title: Mapped[str] = mapped_column(String(512))
    content: Mapped[str] = mapped_column(Text)
    memory_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    # Tech stack context (for filtering)
    tech_stack: Mapped[list] = mapped_column(JSON, default=list)
    vuln_types: Mapped[list] = mapped_column(JSON, default=list)

    # Statistics
    times_recalled: Mapped[int] = mapped_column(Integer, default=0)
    times_useful: Mapped[int] = mapped_column(Integer, default=0)
    success_rate: Mapped[float] = mapped_column(Float, default=0.0)

    # Embedding stored as JSON array (pgvector alternative if extension unavailable)
    embedding: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    source_engagement_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("engagements.id"), nullable=True
    )


# ──────────────────────────── ToolProficiency ────────────────────────────

class ToolProficiencyScore(Base):
    """Tracks how well each agent type performs with each tool."""
    __tablename__ = "tool_proficiency_scores"

    id: Mapped[int] = mapped_column(primary_key=True)
    agent_type: Mapped[str] = mapped_column(String(100))
    tool_name: Mapped[str] = mapped_column(String(100))
    vuln_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Success metrics
    total_attempts: Mapped[int] = mapped_column(Integer, default=0)
    successful_findings: Mapped[int] = mapped_column(Integer, default=0)
    false_positives: Mapped[int] = mapped_column(Integer, default=0)
    proficiency_score: Mapped[float] = mapped_column(Float, default=0.5)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


# ──────────────────────────── AIUsageLog ────────────────────────────

class AIUsageLog(Base):
    """Tracks Claude API usage and costs."""
    __tablename__ = "ai_usage_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("engagements.id"), nullable=True
    )
    agent_run_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("agent_runs.id"), nullable=True
    )

    model: Mapped[str] = mapped_column(String(100))
    task_type: Mapped[str] = mapped_column(String(100))

    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cached_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost: Mapped[float] = mapped_column(Float, default=0.0)

    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ──────────────────────────── Finding ────────────────────────────

class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scan_jobs.id"), nullable=True
    )
    engagement_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("engagements.id"), nullable=True
    )

    vulnerability_type: Mapped[str] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)

    url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    severity: Mapped[SeverityLevel] = mapped_column(
        SQLEnum(SeverityLevel, name="severitylevel"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, default=0.0)

    # Validation
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    validation_result: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Evidence
    proof_of_concept: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    screenshot_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Scoring
    remediation_advice: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)
    cwe_ids: Mapped[list] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)

    # Tool that found it
    tool_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    agent_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Links
    observation_id: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan_job: Mapped[Optional["ScanJob"]] = relationship(back_populates="findings")
    engagement: Mapped[Optional["Engagement"]] = relationship(back_populates="findings")


# ──────────────────────────── AIDecision ────────────────────────────

class AIDecision(Base):
    __tablename__ = "ai_decisions"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))

    decision_type: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(255))
    reasoning: Mapped[str] = mapped_column(Text)

    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    outcome: Mapped[dict] = mapped_column(JSON, default=dict)
    success: Mapped[bool] = mapped_column(Boolean)

    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    action_category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    required_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    agent_model: Mapped[str] = mapped_column(String(100), default="claude-sonnet-4-6")

    scan_job: Mapped["ScanJob"] = relationship(back_populates="ai_decisions")


# ──────────────────────────── Observation ────────────────────────────

class ObservationModel(Base):
    __tablename__ = "observations"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    observation_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    target_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_job_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )

    raw_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    features: Mapped[Dict[str, float]] = mapped_column(JSON, nullable=False, default=dict)
    context_ids: Mapped[List[str]] = mapped_column(JSON, nullable=True, default=list)
    predictions: Mapped[Dict[str, float]] = mapped_column(JSON, nullable=False, default=dict)

    ground_truth: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    ground_truth_source: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    ground_truth_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    target: Mapped["Target"] = relationship(back_populates="observations")
    scan_job: Mapped["ScanJob"] = relationship(back_populates="observations")
    feedback: Mapped[List["FeedbackModel"]] = relationship(back_populates="observation")


# ──────────────────────────── Feedback ────────────────────────────

class FeedbackModel(Base):
    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    observation_id: Mapped[Optional[str]] = mapped_column(
        String(16), ForeignKey("observations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    finding_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )

    feedback_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    feedback_value: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    source: Mapped[str] = mapped_column(String(50), nullable=False, default="api")
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    observation: Mapped[Optional["ObservationModel"]] = relationship(back_populates="feedback")
