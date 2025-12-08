"""
Claude AI client for autonomous pentesting decisions.
"""
import os
import json
import logging
from typing import Dict, Any, List
from anthropic import AsyncAnthropic

logger = logging.getLogger(__name__)


class ClaudeAgent:
    """
    Claude-powered pentesting agent.
    
    Responsibilities:
    - Analyze scan results
    - Decide next actions
    - Generate exploit POCs
    - Provide remediation advice
    """
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set in environment")
        
        self.client = AsyncAnthropic(api_key=self.api_key)
        self.model = "claude-sonnet-4-20250514"
        self.max_tokens = 4000
    
    async def analyze_scan_results(
        self,
        target_info: Dict[str, Any],
        scan_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze scan results and suggest next actions.
        
        Args:
            target_info: Information about the target
            scan_results: List of scan findings
            
        Returns:
            {
                "analysis": "Summary of findings",
                "next_actions": [
                    {"action": "tool_name", "params": {...}, "reasoning": "..."},
                    ...
                ],
                "risk_assessment": "Overall risk level"
            }
        """
        prompt = f"""You are Overwatch, an autonomous penetration testing AI.

TARGET INFORMATION:
{json.dumps(target_info, indent=2)}

SCAN RESULTS:
{json.dumps(scan_results, indent=2)}

Your task: Analyze these scan results and recommend the next 3 most important actions.

Respond in this JSON format:
{{
  "analysis": "Brief summary of what you found (2-3 sentences)",
  "next_actions": [
    {{
      "priority": 1,
      "action": "tool_name",
      "params": {{"param": "value"}},
      "reasoning": "Why this is important"
    }}
  ],
  "risk_assessment": "Low|Medium|High|Critical"
}}
"""
        
        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Extract JSON from response
            content = response.content[0].text
            
            # Parse JSON (handle markdown code blocks)
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            
            result = json.loads(content)
            return result
            
        except Exception as e:
            logger.exception(f"Failed to analyze scan results: {e}")
            return {
                "analysis": "Error analyzing results",
                "next_actions": [],
                "risk_assessment": "Unknown",
                "error": str(e)
            }
    
    async def generate_exploit_poc(
        self,
        vulnerability: Dict[str, Any]
    ) -> str:
        """
        Generate proof-of-concept exploit code.
        
        Args:
            vulnerability: Vulnerability details
            
        Returns:
            POC code/command
        """
        prompt = f"""Generate a proof-of-concept exploit for this vulnerability:

VULNERABILITY:
{json.dumps(vulnerability, indent=2)}

Provide:
1. A curl command or Python script to exploit this
2. Explanation of what it does
3. Expected output if successful

Keep it ethical - this is for authorized testing only.
"""
        
        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            return response.content[0].text
            
        except Exception as e:
            logger.exception(f"Failed to generate POC: {e}")
            return f"Error generating POC: {str(e)}"