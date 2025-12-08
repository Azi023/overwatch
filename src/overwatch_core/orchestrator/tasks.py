"""
Celery tasks for scan execution.
"""
import logging
from datetime import datetime
from typing import Dict, Any

from celery import Task
from sqlalchemy import select

from src.overwatch_core.orchestrator.celery_app import celery_app
from src.overwatch_core.persistence.database import AsyncSessionLocal
from src.overwatch_core.persistence.models import ScanJob, Target, ScanStatus, Finding
from src.overwatch_core.scanners.nmap_runner import NmapScanner
from src.overwatch_core.orchestrator.scope_enforcer import ScopeEnforcer

logger = logging.getLogger(__name__)


class ScanTask(Task):
    """Custom task class with error handling."""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure."""
        logger.error(f"Task {task_id} failed: {exc}")
        # Update scan status in database
        import asyncio
        asyncio.run(self._update_scan_status(kwargs.get('scan_id'), ScanStatus.FAILED, str(exc)))

    async def _update_scan_status(self, scan_id: int, status: ScanStatus, error: str = None):
        """Update scan status in database."""
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ScanJob).where(ScanJob.id == scan_id)
            )
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = status
                scan.completed_at = datetime.utcnow()
                if error:
                    scan.summary = {"error": error}
                await session.commit()


@celery_app.task(bind=True, base=ScanTask, name="run_scan")
def run_scan_task(self, scan_id: int, scan_type: str, target_id: int, config: Dict[str, Any]):
    """
    Execute a scan asynchronously.

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
    Async implementation of scan execution.
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

            # Execute scan based on type
            if scan_type == "nmap":
                scanner = NmapScanner()
                result = await scanner.scan(target_url, config)

                # Store results
                scan_job.status = ScanStatus.COMPLETED if result.success else ScanStatus.FAILED
                scan_job.completed_at = datetime.utcnow()
                scan_job.raw_output_path = result.metadata.get("xml_path") if result.success else None
                scan_job.summary = {
                    "success": result.success,
                    "ports_found": len(result.findings) if result.success else 0,
                    "error": result.error if not result.success else None
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
                            severity="INFO",
                            confidence=0.9,
                            validated=True,
                            proof_of_concept=f"Port {port_info['port']} is open"
                        )
                        session.add(finding)

            else:
                raise ValueError(f"Unsupported scan type: {scan_type}")

            await session.commit()

            logger.info(f"Scan {scan_id} completed successfully")
            return {
                "scan_id": scan_id,
                "status": "completed",
                "findings_count": len(result.findings) if result.success else 0
            }

        except Exception as e:
            logger.exception(f"Scan {scan_id} failed: {e}")
            scan_job.status = ScanStatus.FAILED
            scan_job.completed_at = datetime.utcnow()
            scan_job.summary = {"error": str(e)}
            await session.commit()
            raise


@celery_app.task(name="cleanup_old_scans")
def cleanup_old_scans():
    """
    Cleanup old scan data (periodic task).
    """
    import asyncio
    return asyncio.run(_cleanup_old_scans_async())


async def _cleanup_old_scans_async():
    """
    Async cleanup of old scans.
    """
    from datetime import timedelta

    async with AsyncSessionLocal() as session:
        # Delete scans older than 90 days
        cutoff_date = datetime.utcnow() - timedelta(days=90)

        result = await session.execute(
            select(ScanJob).where(ScanJob.created_at < cutoff_date)
        )
        old_scans = result.scalars().all()

        for scan in old_scans:
            await session.delete(scan)

        await session.commit()

        logger.info(f"Cleaned up {len(old_scans)} old scans")
        return {"deleted_count": len(old_scans)}
