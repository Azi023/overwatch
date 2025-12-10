# src/overwatch_core/brain/claude_agent.py
from anthropic import Anthropic
from typing import Dict, Any, List, Optional
from ..learning.observation import Observation
from ..learning.decision_aggregator import Prediction, PredictorType

class ClaudePentestAgent:
    """
    Claude-powered security analysis agent.
    
    Uses Claude for:
    1. Analyzing complex vulnerability patterns
    2. Understanding business logic flaws
    3. Generating exploitation strategies
    4. Reducing false positives through reasoning
    """
    
    SYSTEM_PROMPT = """You are an expert penetration tester analyzing web application security.

Your task is to analyze observations from automated scans and determine:
1. Whether a vulnerability is likely real (true positive) or a false positive
2. The potential impact and severity
3. Recommended next steps for validation

Be precise and conservative - false positives waste human time.

Output your analysis in JSON format:
{
    "vulnerability_type": "sqli|xss|idor|ssrf|path_traversal|other",
    "confidence": 0.0-1.0,
    "is_false_positive": true|false,
    "reasoning": "explanation",
    "severity": "critical|high|medium|low|info",
    "validation_steps": ["step1", "step2"],
    "exploitation_feasible": true|false
}"""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.client = Anthropic(api_key=api_key)
        self.model = model
        
        # Token limits for cost control
        self.max_input_tokens = 4000
        self.max_output_tokens = 1000
    
    async def analyze_observations(
        self,
        observations: List[Observation],
        context: Dict[str, Any]
    ) -> Prediction:
        """
        Analyze a set of related observations for vulnerabilities.
        """
        # Build analysis prompt
        prompt = self._build_prompt(observations, context)
        
        # Check if worth using Claude (cost optimization)
        if not self._should_use_llm(observations):
            return None
        
        try:
            response = await self._call_claude(prompt)
            analysis = self._parse_response(response)
            
            return Prediction(
                predictor_type=PredictorType.LLM,
                predictor_name="claude_sonnet",
                vulnerability_type=analysis.get("vulnerability_type", "unknown"),
                confidence=analysis.get("confidence", 0.5),
                reasoning=analysis.get("reasoning", ""),
                cost=self._calculate_cost(prompt, response)
            )
        except Exception as e:
            logger.error(f"Claude analysis failed: {e}")
            return None
    
    def _should_use_llm(self, observations: List[Observation]) -> bool:
        """
        Decide if observations warrant expensive LLM analysis.
        
        Use LLM for:
        - Medium confidence rule-based predictions (0.3-0.7)
        - Complex multi-observation patterns
        - Potential business logic issues
        
        Skip LLM for:
        - Very high confidence (clear true positive)
        - Very low confidence (clear false positive)
        - Simple pattern matches
        """
        # Get max rule-based confidence
        max_rule_conf = max(
            (o.predictions.get("rule_based", 0) for o in observations),
            default=0
        )
        
        # Clear cases don't need LLM
        if max_rule_conf > 0.9 or max_rule_conf < 0.1:
            return False
        
        # Uncertain cases benefit from LLM reasoning
        return True
    
    def _build_prompt(
        self, 
        observations: List[Observation],
        context: Dict[str, Any]
    ) -> str:
        """Build analysis prompt from observations."""
        prompt_parts = [
            "## Target Context",
            f"URL: {context.get('url', 'N/A')}",
            f"Technology Stack: {context.get('tech_stack', 'Unknown')}",
            "",
            "## Scan Observations",
        ]
        
        for i, obs in enumerate(observations):
            prompt_parts.append(f"\n### Observation {i+1}: {obs.raw_data.get('test_name', 'Unknown')}")
            prompt_parts.append(f"Type: {obs.observation_type.value}")
            prompt_parts.append(f"Status: {obs.raw_data.get('status_code', 'N/A')}")
            prompt_parts.append(f"Response Time: {obs.raw_data.get('response_time_ms', 'N/A')}ms")
            
            # Include relevant body snippet (not full response)
            body = obs.raw_data.get("body", "")
            if body:
                # Find interesting parts
                interesting = self._extract_interesting_content(body)
                prompt_parts.append(f"Relevant Content: {interesting[:1000]}")
            
            prompt_parts.append(f"Rule-Based Confidence: {obs.predictions.get('rule_based', 'N/A')}")
        
        prompt_parts.append("\n## Your Analysis")
        prompt_parts.append("Analyze these observations and provide your assessment in JSON format.")
        
        return "\n".join(prompt_parts)
    
    def _extract_interesting_content(self, body: str) -> str:
        """Extract security-relevant content from response body."""
        interesting = []
        
        # Look for error messages
        error_patterns = [
            r"error.*?(?:\n|$)",
            r"exception.*?(?:\n|$)",
            r"warning.*?(?:\n|$)",
            r"SQL.*?(?:\n|$)",
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            interesting.extend(matches[:3])  # Max 3 per pattern
        
        return "\n".join(interesting) if interesting else body[:500]
    
    async def _call_claude(self, prompt: str) -> str:
        """Make Claude API call."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_output_tokens,
            system=self.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    
    def _calculate_cost(self, prompt: str, response: str) -> float:
        """Calculate API cost for tracking."""
        # Approximate token counts
        input_tokens = len(prompt) / 4
        output_tokens = len(response) / 4
        
        # Sonnet pricing (as of 2024)
        cost = (input_tokens * 0.003 / 1000) + (output_tokens * 0.015 / 1000)
        return cost