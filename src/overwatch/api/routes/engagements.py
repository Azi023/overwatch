"""
Engagement CRUD and control API routes.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...persistence.database import AsyncSessionLocal, get_session
from ...persistence.models import (
    AgentRun,
    Engagement,
    EngagementStatus,
    FeedbackModel,
    Finding,
    Target,
)
from ..schemas.engagement import (
    EngagementCreate,
    EngagementResponse,
    EngagementUpdate,
    FeedbackCreate,
    FindingResponse,
    TimelineEvent,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/engagements", tags=["engagements"])


# ──────────────────────────── helpers ────────────────────────────

async def _get_engagement_or_404(
    engagement_id: int, session: AsyncSession
) -> Engagement:
    engagement = await session.get(Engagement, engagement_id)
    if engagement is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement {engagement_id} not found",
        )
    return engagement


async def _run_engagement(engagement_id: int) -> None:
    """
    Background task: launch the engagement coordinator.

    Marks the engagement as RUNNING and then defers to the coordinator
    once it is implemented. Currently logs a placeholder.
    """
    async with AsyncSessionLocal() as session:
        try:
            engagement = await session.get(Engagement, engagement_id)
            if engagement is None:
                logger.error("Background task: engagement %d not found", engagement_id)
                return

            engagement.status = EngagementStatus.RUNNING
            engagement.started_at = datetime.utcnow()
            await session.commit()
            logger.info("Engagement %d status → RUNNING", engagement_id)

            # TODO: instantiate and call coordinator once implemented
            # from ...coordinator.coordinator import Coordinator
            # coordinator = Coordinator(engagement_id=engagement_id, session_factory=AsyncSessionLocal)
            # await coordinator.run()

        except Exception as exc:
            logger.exception("Engagement %d failed to start: %s", engagement_id, exc)
            try:
                engagement = await session.get(Engagement, engagement_id)
                if engagement:
                    engagement.status = EngagementStatus.FAILED
                    await session.commit()
            except Exception:
                pass


# ──────────────────────────── CRUD ────────────────────────────

@router.post("/", response_model=EngagementResponse, status_code=status.HTTP_201_CREATED)
async def create_engagement(
    payload: EngagementCreate,
    session: AsyncSession = Depends(get_session),
) -> EngagementResponse:
    """Create a new penetration testing engagement."""
    target = await session.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {payload.target_id} not found",
        )

    engagement = Engagement(
        name=payload.name,
        description=payload.description,
        target_id=payload.target_id,
        objectives=payload.objectives,
        scope_config=payload.scope_config,
        token_budget=payload.token_budget,
        time_budget_seconds=payload.time_budget_seconds,
        cost_budget_usd=payload.cost_budget_usd,
        status=EngagementStatus.CREATED,
    )
    session.add(engagement)
    await session.flush()
    await session.refresh(engagement)
    logger.info("Created engagement id=%d name=%s", engagement.id, engagement.name)
    return EngagementResponse.model_validate(engagement)


@router.get("/", response_model=List[EngagementResponse])
async def list_engagements(
    skip: int = 0,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
) -> List[EngagementResponse]:
    """List engagements with pagination."""
    result = await session.execute(
        select(Engagement).order_by(Engagement.id.desc()).offset(skip).limit(limit)
    )
    engagements = result.scalars().all()
    return [EngagementResponse.model_validate(e) for e in engagements]


@router.get("/{engagement_id}", response_model=EngagementResponse)
async def get_engagement(
    engagement_id: int,
    session: AsyncSession = Depends(get_session),
) -> EngagementResponse:
    """Get full details for one engagement."""
    engagement = await _get_engagement_or_404(engagement_id, session)
    return EngagementResponse.model_validate(engagement)


# ──────────────────────────── Control ────────────────────────────

@router.post("/{engagement_id}/start", response_model=EngagementResponse)
async def start_engagement(
    engagement_id: int,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_session),
) -> EngagementResponse:
    """Launch an engagement (coordinator runs in background)."""
    engagement = await _get_engagement_or_404(engagement_id, session)

    if engagement.status not in (EngagementStatus.CREATED, EngagementStatus.PAUSED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot start engagement in status '{engagement.status}'",
        )

    background_tasks.add_task(_run_engagement, engagement_id)
    logger.info("Queued start for engagement id=%d", engagement_id)
    return EngagementResponse.model_validate(engagement)


@router.post("/{engagement_id}/stop", response_model=EngagementResponse)
async def stop_engagement(
    engagement_id: int,
    reason: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
) -> EngagementResponse:
    """Activate the kill switch and stop all agent activity."""
    engagement = await _get_engagement_or_404(engagement_id, session)

    if engagement.status in (EngagementStatus.COMPLETED, EngagementStatus.STOPPED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Engagement already in terminal state '{engagement.status}'",
        )

    engagement.status = EngagementStatus.STOPPED
    engagement.kill_switch_activated = True
    engagement.kill_switch_reason = reason or "Manual stop via API"
    engagement.completed_at = datetime.utcnow()

    await session.flush()
    await session.refresh(engagement)
    logger.warning("Kill switch activated for engagement id=%d reason=%s", engagement_id, reason)
    return EngagementResponse.model_validate(engagement)


# ──────────────────────────── Data endpoints ────────────────────────────

@router.get("/{engagement_id}/findings", response_model=List[FindingResponse])
async def get_engagement_findings(
    engagement_id: int,
    skip: int = 0,
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
) -> List[FindingResponse]:
    """Return all findings discovered in this engagement."""
    await _get_engagement_or_404(engagement_id, session)

    result = await session.execute(
        select(Finding)
        .where(Finding.engagement_id == engagement_id)
        .order_by(Finding.discovered_at.desc())
        .offset(skip)
        .limit(limit)
    )
    findings = result.scalars().all()
    return [FindingResponse.model_validate(f) for f in findings]


@router.get("/{engagement_id}/report")
async def get_engagement_report(
    engagement_id: int,
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    """
    Generate and return a JSON report for the engagement.

    Uses ReportEngine when a claude_client is available; falls back to
    a lightweight summary when the Claude API key is not configured.
    """
    from ...reporting.report_engine import ReportEngine

    await _get_engagement_or_404(engagement_id, session)

    try:
        from ...reasoning.claude_client import ClaudeClient
        claude_client: Optional[Any] = ClaudeClient()
    except (ValueError, ImportError):
        claude_client = None

    engine = ReportEngine(
        session_factory=AsyncSessionLocal,
        claude_client=claude_client,
    )
    return await engine.generate_report(engagement_id)


@router.get("/{engagement_id}/timeline", response_model=List[TimelineEvent])
async def get_engagement_timeline(
    engagement_id: int,
    session: AsyncSession = Depends(get_session),
) -> List[TimelineEvent]:
    """Return a chronological stream of engagement events."""
    engagement = await _get_engagement_or_404(engagement_id, session)

    events: List[TimelineEvent] = []

    # Engagement created
    events.append(
        TimelineEvent(
            timestamp=engagement.created_at,
            event_type="engagement_created",
            agent_id=None,
            agent_type=None,
            description=f"Engagement '{engagement.name}' created",
            details={"status": engagement.status.value},
        )
    )

    if engagement.started_at:
        events.append(
            TimelineEvent(
                timestamp=engagement.started_at,
                event_type="engagement_started",
                agent_id=None,
                agent_type=None,
                description="Engagement launched",
                details={},
            )
        )

    # Agent runs
    agent_result = await session.execute(
        select(AgentRun)
        .where(AgentRun.engagement_id == engagement_id)
        .order_by(AgentRun.spawned_at.asc())
    )
    for agent in agent_result.scalars().all():
        events.append(
            TimelineEvent(
                timestamp=agent.spawned_at,
                event_type="agent_spawned",
                agent_id=agent.agent_id,
                agent_type=agent.agent_type,
                description=f"Agent '{agent.agent_type}' spawned: {agent.objective[:80]}",
                details={
                    "status": agent.status.value,
                    "loop_iterations": agent.loop_iterations,
                    "findings_count": agent.findings_count,
                    "tokens_used": agent.tokens_used,
                },
            )
        )
        if agent.completed_at:
            events.append(
                TimelineEvent(
                    timestamp=agent.completed_at,
                    event_type="agent_completed",
                    agent_id=agent.agent_id,
                    agent_type=agent.agent_type,
                    description=f"Agent '{agent.agent_type}' finished with status '{agent.status.value}'",
                    details={"findings_count": agent.findings_count},
                )
            )

    # Findings
    finding_result = await session.execute(
        select(Finding)
        .where(Finding.engagement_id == engagement_id)
        .order_by(Finding.discovered_at.asc())
    )
    for finding in finding_result.scalars().all():
        events.append(
            TimelineEvent(
                timestamp=finding.discovered_at,
                event_type="finding_discovered",
                agent_id=None,
                agent_type=finding.agent_type,
                description=f"[{finding.severity.value.upper()}] {finding.title}",
                details={
                    "finding_id": finding.id,
                    "severity": finding.severity.value,
                    "validated": finding.validated,
                    "tool": finding.tool_name,
                },
            )
        )

    if engagement.completed_at:
        events.append(
            TimelineEvent(
                timestamp=engagement.completed_at,
                event_type="engagement_completed",
                agent_id=None,
                agent_type=None,
                description=f"Engagement finished with status '{engagement.status.value}'",
                details={"kill_switch": engagement.kill_switch_activated},
            )
        )

    # Sort all events chronologically
    events.sort(key=lambda e: e.timestamp)
    return events


@router.post("/{engagement_id}/feedback", status_code=status.HTTP_201_CREATED)
async def submit_engagement_feedback(
    engagement_id: int,
    payload: FeedbackCreate,
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    """Submit human feedback on a finding within this engagement."""
    await _get_engagement_or_404(engagement_id, session)

    if payload.finding_id is not None:
        finding = await session.get(Finding, payload.finding_id)
        if finding is None or finding.engagement_id != engagement_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found in this engagement",
            )

    feedback = FeedbackModel(
        observation_id=payload.observation_id,
        finding_id=payload.finding_id,
        feedback_type=payload.feedback_type,
        feedback_value=payload.feedback_value,
        source="api",
        user_id=payload.user_id,
    )
    session.add(feedback)
    await session.flush()
    await session.refresh(feedback)
    logger.info(
        "Feedback id=%d for engagement id=%d finding=%s",
        feedback.id,
        engagement_id,
        payload.finding_id,
    )
    return {
        "id": feedback.id,
        "feedback_type": feedback.feedback_type,
        "created_at": feedback.created_at.isoformat(),
    }
