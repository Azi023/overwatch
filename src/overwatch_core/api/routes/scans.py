"""
Scan management endpoints.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.overwatch_core.persistence.database import get_session
from src.overwatch_core.persistence.models import ScanJob, Target, ScanStatus
from src.overwatch_core.api.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanUpdate
)
from src.overwatch_core.scanners.nmap_runner import NmapScanner

router = APIRouter()


async def run_scan_background(scan_id: int, scan_type: str, target_url: str, config: dict):
    """
    Background task to run the actual scan.
    """
    from src.overwatch_core.persistence.database import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        # Get scan job
        result = await session.execute(
            select(ScanJob).where(ScanJob.id == scan_id)
        )
        scan_job = result.scalar_one()

        # Update status to running
        scan_job.status = ScanStatus.RUNNING
        scan_job.started_at = datetime.utcnow()
        await session.commit()

        try:
            # Run the scan based on type
            if scan_type == "nmap":
                scanner = NmapScanner()
                result = await scanner.scan(target_url, config)

                # Update scan job with results
                scan_job.status = ScanStatus.COMPLETED if result.success else ScanStatus.FAILED
                scan_job.completed_at = datetime.utcnow()
                scan_job.raw_output_path = result.metadata.get("xml_path")
                scan_job.summary = {"ports": result.findings}

            else:
                raise ValueError(f"Unknown scan type: {scan_type}")

        except Exception as e:
            scan_job.status = ScanStatus.FAILED
            scan_job.completed_at = datetime.utcnow()
            scan_job.summary = {"error": str(e)}

        await session.commit()


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    session: AsyncSession = Depends(get_session)
):
    """
    Create and queue a new scan.
    """
    # Verify target exists
    result = await session.execute(
        select(Target).where(Target.id == scan_data.target_id)
    )
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target with id {scan_data.target_id} not found"
        )

    # Create scan job
    scan_job = ScanJob(
        target_id=scan_data.target_id,
        scan_type=scan_data.scan_type,
        status=ScanStatus.PENDING
    )
    session.add(scan_job)
    await session.commit()
    await session.refresh(scan_job)

    # Queue scan task (Celery)
    from src.overwatch_core.orchestrator.tasks import run_scan_task
    task = run_scan_task.delay(
        scan_id=scan_job.id,
        scan_type=scan_data.scan_type,
        target_id=scan_data.target_id,
        config=scan_data.config
    )

    # Store Celery task ID
    scan_job.summary = {"celery_task_id": task.id}
    await session.commit()

    return scan_job


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    target_id: int = None,
    skip: int = 0,
    limit: int = 100,
    session: AsyncSession = Depends(get_session)
):
    """
    List all scans with optional filtering by target.
    """
    query = select(ScanJob)

    if target_id:
        query = query.where(ScanJob.target_id == target_id)

    query = query.offset(skip).limit(limit).order_by(ScanJob.created_at.desc())

    result = await session.execute(query)
    scans = result.scalars().all()
    return scans


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_session)
):
    """
    Get a specific scan by ID.
    """
    result = await session.execute(
        select(ScanJob).where(ScanJob.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with id {scan_id} not found"
        )

    return scan
