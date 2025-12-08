"""
Unit tests for database models.
"""
import pytest
from datetime import datetime
from src.overwatch_core.persistence.models import Target, ScanJob, Finding, ScanStatus, SeverityLevel


def test_target_creation():
    """Test Target model creation."""
    target = Target(
        name="Test Target",
        url="http://example.com",
        ip_address="192.168.1.1",
        scope_rules={"max_depth": 3},
        allowed_hosts=["example.com"],
        allowed_ports=[80, 443]
    )

    assert target.name == "Test Target"
    assert target.url == "http://example.com"
    assert len(target.allowed_hosts) == 1
    assert 80 in target.allowed_ports


def test_scan_job_default_status():
    """Test ScanJob has correct default status."""
    scan = ScanJob(
        target_id=1,
        scan_type="nmap"
    )

    assert scan.status == ScanStatus.PENDING
    assert scan.scan_type == "nmap"
    assert scan.started_at is None


def test_finding_severity_enum():
    """Test Finding severity levels."""
    finding = Finding(
        scan_job_id=1,
        vulnerability_type="SQL Injection",
        title="SQL Injection in login",
        description="User input not sanitized",
        severity=SeverityLevel.HIGH,
        confidence=0.95
    )

    assert finding.severity == SeverityLevel.HIGH
    assert finding.confidence == 0.95
