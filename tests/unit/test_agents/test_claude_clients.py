"""
Tests for Claude AI client.
"""
import pytest
import os
from src.overwatch_core.agents.claude_client import ClaudeAgent


@pytest.mark.asyncio
@pytest.mark.skipif(not os.getenv("ANTHROPIC_API_KEY"), reason="No API key")
async def test_claude_analyzes_nmap_results():
    """Test Claude can analyze nmap results."""
    agent = ClaudeAgent()
    
    target_info = {
        "url": "http://192.168.1.50/dvwa",
        "name": "DVWA Test Target"
    }
    
    scan_results = [
        {"port": 80, "service": "http", "version": "Apache 2.4.41"},
        {"port": 3306, "service": "mysql", "version": "MySQL 5.7.33"},
        {"port": 22, "service": "ssh", "version": "OpenSSH 7.9"}
    ]
    
    result = await agent.analyze_scan_results(target_info, scan_results)
    
    # Verify response structure
    assert "analysis" in result
    assert "next_actions" in result
    assert "risk_assessment" in result
    assert len(result["next_actions"]) > 0
    
    # Verify next actions have required fields
    action = result["next_actions"][0]
    assert "action" in action
    assert "reasoning" in action