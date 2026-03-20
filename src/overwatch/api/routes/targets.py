"""
Target CRUD API routes.
"""
from __future__ import annotations

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...persistence.database import get_session
from ...persistence.models import Target
from ..schemas.target import TargetCreate, TargetResponse, TargetUpdate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("/", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(
    payload: TargetCreate,
    session: AsyncSession = Depends(get_session),
) -> TargetResponse:
    """Create a new penetration testing target."""
    target = Target(
        name=payload.name,
        url=payload.url,
        ip_address=payload.ip_address,
        scope_rules=payload.scope_rules,
        allowed_hosts=payload.allowed_hosts,
        allowed_ports=payload.allowed_ports,
    )
    session.add(target)
    await session.flush()
    await session.refresh(target)
    logger.info("Created target id=%d name=%s", target.id, target.name)
    return TargetResponse.model_validate(target)


@router.get("/", response_model=List[TargetResponse])
async def list_targets(
    skip: int = 0,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
) -> List[TargetResponse]:
    """List all targets with pagination."""
    limit = min(limit, 500)
    result = await session.execute(
        select(Target).order_by(Target.id.desc()).offset(skip).limit(limit)
    )
    targets = result.scalars().all()
    return [TargetResponse.model_validate(t) for t in targets]


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> TargetResponse:
    """Retrieve a target by ID."""
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    return TargetResponse.model_validate(target)


@router.patch("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: int,
    payload: TargetUpdate,
    session: AsyncSession = Depends(get_session),
) -> TargetResponse:
    """Partially update a target."""
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(target, field, value)

    await session.flush()
    await session.refresh(target)
    logger.info("Updated target id=%d fields=%s", target_id, list(update_data.keys()))
    return TargetResponse.model_validate(target)


@router.delete("/{target_id}", status_code=status.HTTP_200_OK)
async def delete_target(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Delete a target and all associated data."""
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    await session.delete(target)
    await session.flush()
    logger.info("Deleted target id=%d", target_id)
    return {"deleted": target_id}
