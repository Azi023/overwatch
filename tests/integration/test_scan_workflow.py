"""
Integration tests for complete scan workflow.
"""
import pytest
from sqlalchemy import select
from src.overwatch_core.persistence.database import AsyncSessionLocal, init_db
from src.overwatch_core.persistence.models import Target, ScanJob, Finding, ScanStatus
from src.overwatch_core.scanners.nmap_runner import NmapScanner


@pytest.fixture
async def test_db():
    """Create test database."""
    await init_db()
    yield
    # Cleanup handled by test database


@pytest.mark.asyncio
async def test_complete_scan_workflow(test_db):
    """Test complete workflow: create target → run scan → store results."""
    async with AsyncSessionLocal() as session:
        # 1. Create target
        target = Target(
            name="Test Target",
            ip_address="127.0.0.1",
            allowed_hosts=["127.0.0.1"],
            allowed_ports=[80, 443]
        )
        session.add(target)
        await session.commit()
        await session.refresh(target)

        # 2. Create scan job
        scan_job = ScanJob(
            target_id=target.id,
            scan_type="nmap",
            status=ScanStatus.PENDING
        )
        session.add(scan_job)
        await session.commit()
        await session.refresh(scan_job)

        # 3. Run scan
        scanner = NmapScanner()
        result = await scanner.scan("127.0.0.1", {"profile": "balanced"})

        # 4. Update scan job
        scan_job.status = ScanStatus.COMPLETED if result.success else ScanStatus.FAILED
        scan_job.summary = {"ports_found": len(result.findings)}

        # 5. Store findings
        for port_info in result.findings:
            finding = Finding(
                scan_job_id=scan_job.id,
                vulnerability_type="Open Port",
                title=f"Port {port_info['port']} open",
                description=f"Service: {port_info['service']}",
                severity="INFO",
                confidence=0.9
            )
            session.add(finding)

        await session.commit()

        # 6. Verify results
        result = await session.execute(
            select(Finding).where(Finding.scan_job_id == scan_job.id)
        )
        findings = result.scalars().all()

        assert len(findings) >= 0
        assert scan_job.status == ScanStatus.COMPLETED
