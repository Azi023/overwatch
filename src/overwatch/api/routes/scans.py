"""
Scan management API routes.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...persistence.database import get_session
from ...persistence.models import ScanJob, ScanStatus, Target
from ..schemas.scan import ScanCreate, ScanResponse, ScanUpdate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    """Create and queue a new scan job."""
    # Validate target exists
    target = await session.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {payload.target_id} not found",
        )

    scan = ScanJob(
        target_id=payload.target_id,
        engagement_id=payload.engagement_id,
        scan_type=payload.scan_type,
        status=ScanStatus.PENDING,
        summary=payload.config if payload.config else None,
    )
    session.add(scan)
    await session.flush()
    await session.refresh(scan)
    logger.info(
        "Created scan id=%d type=%s target_id=%d",
        scan.id,
        scan.scan_type,
        scan.target_id,
    )
    return ScanResponse.model_validate(scan)


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    target_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
) -> List[ScanResponse]:
    """List all scans, optionally filtered by target_id."""
    query = select(ScanJob).order_by(ScanJob.id.desc()).offset(skip).limit(limit)
    if target_id is not None:
        query = query.where(ScanJob.target_id == target_id)

    result = await session.execute(query)
    scans = result.scalars().all()
    return [ScanResponse.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    """Retrieve a scan job by ID."""
    scan = await session.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return ScanResponse.model_validate(scan)


@router.patch("/{scan_id}", response_model=ScanResponse)
async def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    """Partially update a scan job (e.g. mark as cancelled)."""
    scan = await session.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(scan, field, value)

    await session.flush()
    await session.refresh(scan)
    logger.info("Updated scan id=%d fields=%s", scan_id, list(update_data.keys()))
    return ScanResponse.model_validate(scan)
