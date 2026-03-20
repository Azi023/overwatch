"""
Feedback API routes for observations and findings.
"""
from __future__ import annotations

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...persistence.database import get_session
from ...persistence.models import FeedbackModel, ObservationModel
from ..schemas.engagement import FeedbackCreate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/feedback", tags=["feedback"])


@router.post("/", status_code=status.HTTP_201_CREATED)
async def submit_feedback(
    payload: FeedbackCreate,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Submit human feedback on an observation or finding."""
    if payload.observation_id is None and payload.finding_id is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Either observation_id or finding_id must be provided.",
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
        "Feedback id=%d type=%s obs=%s finding=%s",
        feedback.id,
        feedback.feedback_type,
        feedback.observation_id,
        feedback.finding_id,
    )
    return {
        "id": feedback.id,
        "feedback_type": feedback.feedback_type,
        "created_at": feedback.created_at.isoformat(),
    }


@router.get("/observation/{obs_id}")
async def get_feedback_for_observation(
    obs_id: str,
    session: AsyncSession = Depends(get_session),
) -> List[dict]:
    """Get all feedback submitted for a given observation."""
    # Verify the observation exists
    obs = await session.get(ObservationModel, obs_id)
    if obs is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Observation {obs_id} not found",
        )

    result = await session.execute(
        select(FeedbackModel)
        .where(FeedbackModel.observation_id == obs_id)
        .order_by(FeedbackModel.created_at.asc())
    )
    items = result.scalars().all()
    return [
        {
            "id": fb.id,
            "feedback_type": fb.feedback_type,
            "feedback_value": fb.feedback_value,
            "source": fb.source,
            "user_id": fb.user_id,
            "created_at": fb.created_at.isoformat(),
        }
        for fb in items
    ]
