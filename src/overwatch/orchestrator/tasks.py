"""
Celery task definitions with observation capture.
"""
import asyncio
import logging
from datetime import datetime
from typing import Any, Dict

from sqlalchemy import select

from ..persistence.database import AsyncSessionLocal
from ..persistence.models import Finding, ScanJob, ScanStatus, Target
from ..scanners.nmap_runner import NmapScanner
from ..coordinator.scope_enforcer import ScopeEnforcer
from ..learning.observation_store import ObservationStore
from .celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="run_scan", bind=True, max_retries=3)
def run_scan(
    self,
    scan_id: int,
    scan_type: str,
    target_id: int,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Execute a scan job with observation capture."""
    return asyncio.run(_run_scan_async(scan_id, scan_type, target_id, config))


async def _run_scan_async(
    scan_id: int,
    scan_type: str,
    target_id: int,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    async with AsyncSessionLocal() as session:
        scan_result = await session.execute(
            select(ScanJob).where(ScanJob.id == scan_id)
        )
        scan_job = scan_result.scalar_one()

        target_result = await session.execute(
            select(Target).where(Target.id == target_id)
        )
        target = target_result.scalar_one()

        scan_job.status = ScanStatus.RUNNING
        scan_job.started_at = datetime.utcnow()
        await session.commit()

        try:
            scope_config = {
                "allowed_hosts": target.allowed_hosts or [],
                "allowed_ports": target.allowed_ports or [],
                "scope_rules": target.scope_rules or {},
            }
            scope_enforcer = ScopeEnforcer(scope_config)
            target_url = target.url or target.ip_address

            if not scope_enforcer.is_url_allowed(target_url):
                raise ValueError(f"Target {target_url} is out of scope")

            observation_store = ObservationStore(session)

            if scan_type == "nmap":
                scanner = NmapScanner(observation_store=observation_store)
                result = await scanner.scan(
                    target_url,
                    config,
                    scan_job_id=scan_id,
                    target_id=target_id,
                )

                scan_job.status = ScanStatus.COMPLETED if result.success else ScanStatus.FAILED
                scan_job.completed_at = datetime.utcnow()
                scan_job.raw_output_path = (
                    result.metadata.get("xml_path") if result.success else None
                )
                scan_job.summary = {
                    "success": result.success,
                    "ports_found": len(result.findings) if result.success else 0,
                    "error": result.error if not result.success else None,
                    "scan_duration_ms": (
                        result.metadata.get("scan_duration_ms") if result.metadata else None
                    ),
                    "has_observations": True,
                }

                if result.success:
                    for port_info in result.findings:
                        finding = Finding(
                            scan_job_id=scan_job.id,
                            vulnerability_type="Open Port",
                            title=f"Port {port_info['port']}/{port_info['protocol']} - {port_info.get('service', 'unknown')}",
                            description=(
                                f"Service: {port_info.get('service', 'unknown')}, "
                                f"Product: {port_info.get('product', 'Unknown')}, "
                                f"Version: {port_info.get('version', 'Unknown')}"
                            ),
                            url=target_url,
                            severity="info",
                            confidence=0.9,
                            evidence=port_info,
                            tool_name="nmap",
                        )
                        session.add(finding)
            else:
                raise ValueError(f"Unknown scan type: {scan_type}")

            await session.commit()

            return {
                "scan_id": scan_id,
                "status": scan_job.status.value,
                "summary": scan_job.summary,
            }

        except Exception as exc:
            scan_job.status = ScanStatus.FAILED
            scan_job.completed_at = datetime.utcnow()
            scan_job.summary = {"error": str(exc)}
            await session.commit()
            logger.exception("Scan %d failed: %s", scan_id, exc)
            raise


@celery_app.task(name="cleanup_old_scans")
def cleanup_old_scans(days: int = 30) -> Dict[str, Any]:
    """Clean up old scan data."""
    return asyncio.run(_cleanup_old_scans_async(days))


async def _cleanup_old_scans_async(days: int) -> Dict[str, Any]:
    from datetime import timedelta

    async with AsyncSessionLocal() as session:
        cutoff = datetime.utcnow() - timedelta(days=days)
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
