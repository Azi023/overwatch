"""
End-to-end tests via API.
"""
import pytest
from httpx import AsyncClient
from src.overwatch_core.api.main import app

@pytest.mark.skip(reason="Scans endpoint not yet implemented")
@pytest.mark.asyncio
async def test_create_target_and_scan():
    """E2E test: Create target via API and run scan."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        # 1. Create target
        response = await client.post(
            "/api/v1/targets/",
            json={
                "name": "E2E Test Target",
                "ip_address": "127.0.0.1",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_ports": [80, 443]
            }
        )
        assert response.status_code == 201
        target = response.json()
        target_id = target["id"]

        # 2. Create scan
        response = await client.post(
            "/api/v1/scans/",
            json={
                "target_id": target_id,
                "scan_type": "nmap",
                "config": {"profile": "quick"}
            }
        )
        assert response.status_code == 201
        scan = response.json()
        scan_id = scan["id"]

        # 3. Wait for scan completion (in real test, poll status)
        import asyncio
        await asyncio.sleep(5)

        # 4. Get scan results
        response = await client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200
        scan_result = response.json()

        # Should be completed (or running)
        assert scan_result["status"] in ["COMPLETED", "RUNNING"]
