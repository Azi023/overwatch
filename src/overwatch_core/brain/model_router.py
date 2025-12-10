# src/overwatch_core/brain/model_router.py
from enum import Enum
from typing import Dict, Any, List
from dataclasses import dataclass

class ModelTier(str, Enum):
    HAIKU = "haiku"      # Fast, cheap: $0.25/$1.25 per MTok
    SONNET = "sonnet"    # Balanced: $3/$15 per MTok  
    OPUS = "opus"        # Best: $15/$75 per MTok

@dataclass
class TaskClassification:
    tier: ModelTier
    estimated_tokens: int
    estimated_cost: float
    reasoning: str

class ModelRouter:
    """
    Routes tasks to appropriate Claude model based on complexity and cost.
    
    Goal: <$5 per comprehensive scan
    """
    
    # Task complexity heuristics
    TIER_CRITERIA = {
        ModelTier.HAIKU: {
            "max_observations": 5,
            "task_types": ["log_parsing", "simple_classification", "tool_output_summary"],
            "max_tokens": 2000,
        },
        ModelTier.SONNET: {
            "max_observations": 20,
            "task_types": ["vulnerability_analysis", "report_generation", "chain_detection"],
            "max_tokens": 8000,
        },
        ModelTier.OPUS: {
            "max_observations": float("inf"),
            "task_types": ["business_logic_analysis", "novel_attack_chains", "complex_exploitation"],
            "max_tokens": 32000,
        }
    }
    
    # Pricing per million tokens (input/output)
    PRICING = {
        ModelTier.HAIKU: (0.25, 1.25),
        ModelTier.SONNET: (3.0, 15.0),
        ModelTier.OPUS: (15.0, 75.0),
    }
    
    def classify_task(
        self, 
        task_type: str,
        observations: List[Any],
        context: Dict[str, Any]
    ) -> TaskClassification:
        """
        Determine which model tier to use for a task.
        """
        num_obs = len(observations)
        
        # Check task type against tier criteria
        for tier in [ModelTier.HAIKU, ModelTier.SONNET, ModelTier.OPUS]:
            criteria = self.TIER_CRITERIA[tier]
            
            if (task_type in criteria["task_types"] and 
                num_obs <= criteria["max_observations"]):
                
                # Estimate tokens
                tokens = self._estimate_tokens(observations, context)
                if tokens <= criteria["max_tokens"]:
                    cost = self._estimate_cost(tier, tokens)
                    return TaskClassification(
                        tier=tier,
                        estimated_tokens=tokens,
                        estimated_cost=cost,
                        reasoning=f"Task '{task_type}' with {num_obs} observations fits {tier.value}"
                    )
        
        # Default to Sonnet for unknown tasks
        tokens = self._estimate_tokens(observations, context)
        return TaskClassification(
            tier=ModelTier.SONNET,
            estimated_tokens=tokens,
            estimated_cost=self._estimate_cost(ModelTier.SONNET, tokens),
            reasoning="Default to Sonnet for unclassified task"
        )
    
    def _estimate_tokens(
        self, 
        observations: List[Any], 
        context: Dict[str, Any]
    ) -> int:
        """Rough token estimation."""
        # Observations: ~500 tokens each on average
        obs_tokens = len(observations) * 500
        
        # Context: ~200 tokens
        context_tokens = 200
        
        # System prompt: ~300 tokens
        system_tokens = 300
        
        # Expected output: ~400 tokens
        output_tokens = 400
        
        return obs_tokens + context_tokens + system_tokens + output_tokens
    
    def _estimate_cost(self, tier: ModelTier, tokens: int) -> float:
        """Estimate cost in dollars."""
        input_price, output_price = self.PRICING[tier]
        
        # Assume 80% input, 20% output
        input_tokens = tokens * 0.8
        output_tokens = tokens * 0.2
        
        cost = (input_tokens * input_price / 1_000_000 + 
                output_tokens * output_price / 1_000_000)
        
        return round(cost, 4)