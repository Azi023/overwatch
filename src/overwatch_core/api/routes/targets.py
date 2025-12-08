"""
Target management endpoints.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.overwatch_core.persistence.database import get_session
from src.overwatch_core.persistence.models import Target
from src.overwatch_core.api.schemas.target import (
    TargetCreate,
    TargetUpdate,
    TargetResponse
)

router = APIRouter()


@router.post("/", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(
    target_data: TargetCreate,
    session: AsyncSession = Depends(get_session)
):
    """
    Create a new target.
    """
    target = Target(**target_data.model_dump())
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


@router.get("/", response_model=List[TargetResponse])
async def list_targets(
    skip: int = 0,
    limit: int = 100,
    session: AsyncSession = Depends(get_session)
):
    """
    List all targets with pagination.
    """
    result = await session.execute(
        select(Target).offset(skip).limit(limit)
    )
    targets = result.scalars().all()
    return targets


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: int,
    session: AsyncSession = Depends(get_session)
):
    """
    Get a specific target by ID.
    """
    result = await session.execute(
        select(Target).where(Target.id == target_id)
    )
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target with id {target_id} not found"
        )

    return target


@router.patch("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: int,
    target_data: TargetUpdate,
    session: AsyncSession = Depends(get_session)
):
    """
    Update a target.
    """
    result = await session.execute(
        select(Target).where(Target.id == target_id)
    )
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target with id {target_id} not found"
        )

    # Update fields
    update_data = target_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(target, field, value)

    await session.commit()
    await session.refresh(target)
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: int,
    session: AsyncSession = Depends(get_session)
):
    """
    Delete a target.
    """
    result = await session.execute(
        select(Target).where(Target.id == target_id)
    )
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target with id {target_id} not found"
        )

    await session.delete(target)
    await session.commit()
