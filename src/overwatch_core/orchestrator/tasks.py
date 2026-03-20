"""
Celery task definitions with observation capture integration.
"""
from celery import Celery
from typing import Dict, Any
from datetime import datetime
from sqlalchemy import select

from ..persistence.database import AsyncSessionLocal
from ..persistence.models import ScanJob, Target, Finding, ScanStatus
from ..scanners.nmap_runner import NmapScanner
from ..security.scope_enforcer import ScopeEnforcer
from ..learning.observation_store import ObservationStore

# Import celery app
from .celery_app import celery_app


@celery_app.task(name="run_scan", bind=True, max_retries=3)
def run_scan(self, scan_id: int, scan_type: str, target_id: int, config: Dict[str, Any]):
    """
    Execute a scan job with observation capture.
    
    Args:
        scan_id: ID of the ScanJob
        scan_type: Type of scan (nmap, nuclei, etc.)
        target_id: Target ID
        config: Scan configuration
    """
    import asyncio
    return asyncio.run(_run_scan_async(scan_id, scan_type, target_id, config))


async def _run_scan_async(scan_id: int, scan_type: str, target_id: int, config: Dict[str, Any]):
    """
    Async implementation of scan execution with observation capture.
    """
    async with AsyncSessionLocal() as session:
        # Get scan job and target
        scan_result = await session.execute(
            select(ScanJob).where(ScanJob.id == scan_id)
        )
        scan_job = scan_result.scalar_one()

        target_result = await session.execute(
            select(Target).where(Target.id == target_id)
        )
        target = target_result.scalar_one()

        # Update status to running
        scan_job.status = ScanStatus.RUNNING
        scan_job.started_at = datetime.utcnow()
        await session.commit()

        try:
            # Enforce scope
            scope_enforcer = ScopeEnforcer(target)
            target_url = target.url or target.ip_address

            if not scope_enforcer.is_in_scope(target_url):
                raise ValueError(f"Target {target_url} is out of scope")

            # Create observation store for this session
            observation_store = ObservationStore(session)

            # Execute scan based on type
            if scan_type == "nmap":
                # Create scanner with observation store
                scanner = NmapScanner(observation_store=observation_store)
                
                # Execute scan with observation capture
                result = await scanner.scan(
                    target_url, 
                    config,
                    scan_job_id=scan_id,
                    target_id=target_id
                )

                # Store results
                scan_job.status = ScanStatus.COMPLETED if result.success else ScanStatus.FAILED
                scan_job.completed_at = datetime.utcnow()
                scan_job.raw_output_path = result.metadata.get("xml_path") if result.success else None
                scan_job.summary = {
                    "success": result.success,
                    "ports_found": len(result.findings) if result.success else 0,
                    "error": result.error if not result.success else None,
                    "scan_duration_ms": result.metadata.get("scan_duration_ms") if result.metadata else None,
                    "has_observations": True  # Flag that learning data was captured
                }

                # Create findings if successful
                if result.success:
                    for port_info in result.findings:
                        finding = Finding(
                            scan_job_id=scan_job.id,
                            vulnerability_type="Open Port",
                            title=f"Port {port_info['port']}/{port_info['protocol']} - {port_info['service']}",
                            description=f"Service: {port_info['service']}, Product: {port_info.get('product', 'Unknown')}, Version: {port_info.get('version', 'Unknown')}",
                            url=target_url,
                            severity="info",
                            confidence=0.9,
                            evidence=port_info,
                            tool_name="nmap"
                        )
                        session.add(finding)

            else:
                raise ValueError(f"Unknown scan type: {scan_type}")

            await session.commit()

            return {
                "scan_id": scan_id,
                "status": scan_job.status.value,
                "summary": scan_job.summary
            }

        except Exception as e:
            scan_job.status = ScanStatus.FAILED
            scan_job.completed_at = datetime.utcnow()
            scan_job.summary = {"error": str(e)}
            await session.commit()
            raise


@celery_app.task(name="cleanup_old_scans")
def cleanup_old_scans(days: int = 30):
    """Clean up old scan data."""
    import asyncio
    return asyncio.run(_cleanup_old_scans_async(days))


async def _cleanup_old_scans_async(days: int):
    """Async cleanup implementation."""
    from datetime import timedelta
    
    async with AsyncSessionLocal() as session:
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Note: In production, you'd want to archive observations
        # before deletion for training data preservation
        
        result = await session.execute(
            select(ScanJob).where(ScanJob.created_at < cutoff)
        )
        old_jobs = result.scalars().all()
        
        deleted_count = 0
        for job in old_jobs:
            await session.delete(job)
            deleted_count += 1
        
        await session.commit()
        
        return {"deleted_jobs": deleted_count}