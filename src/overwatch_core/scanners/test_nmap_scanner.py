"""
Tests for Nmap scanner.
"""
import pytest
from src.overwatch_core.scanners.nmap_runner import NmapScanner


@pytest.mark.asyncio
async def test_nmap_scanner_validates_target():
    """Test target validation."""
    scanner = NmapScanner()
    
    # Valid targets
    assert scanner.validate_target("192.168.1.1")
    assert scanner.validate_target("example.com")
    assert scanner.validate_target("10.0.0.0/24")
    
    # Invalid targets (command injection attempts)
    assert not scanner.validate_target("192.168.1.1; rm -rf /")
    assert not scanner.validate_target("example.com && cat /etc/passwd")
    assert not scanner.validate_target("")


@pytest.mark.asyncio
async def test_nmap_scanner_basic_scan():
    """Test basic nmap scan."""
    scanner = NmapScanner()
    
    # Scan localhost (should always work)
    result = await scanner.scan("127.0.0.1", {"profile": "quick"})
    
    assert result.success
    assert result.scanner_name == "nmap"
    assert len(result.findings) >= 0  # May or may not have open ports


@pytest.mark.asyncio
async def test_nmap_scanner_handles_invalid_target():
    """Test scanner handles invalid target gracefully."""
    scanner = NmapScanner()
    
    result = await scanner.scan("999.999.999.999")
    
    # Should fail gracefully, not crash
    assert not result.success
    assert "error" in result.error.lower() or "invalid" in result.error.lower()