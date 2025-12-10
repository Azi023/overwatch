# src/overwatch_core/learning/decision_aggregator.py
from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum
import numpy as np

class PredictorType(str, Enum):
    RULE_BASED = "rule_based"
    ML_MODEL = "ml_model"
    LLM = "llm"

@dataclass
class Prediction:
    predictor_type: PredictorType
    predictor_name: str
    vulnerability_type: str
    confidence: float  # 0.0 to 1.0
    reasoning: Optional[str] = None
    cost: float = 0.0  # API cost if any

class DecisionAggregator:
    """
    Combines predictions from multiple sources using learned weights.
    
    The key innovation: weights are learned from historical accuracy,
    not hardcoded. Better predictors get higher weights over time.
    """
    
    def __init__(self, initial_weights: Dict[str, float] = None):
        # Default weights (will be updated through learning)
        self.weights = initial_weights or {
            "rule_based": 0.3,
            "ml_model": 0.4,
            "llm": 0.3
        }
        
        # Historical accuracy tracking per predictor per vuln type
        self.accuracy_history: Dict[str, Dict[str, List[bool]]] = {}
    
    def aggregate(
        self, 
        predictions: List[Prediction],
        vulnerability_type: str
    ) -> Dict[str, float]:
        """
        Aggregate predictions into final confidence score.
        
        Returns dict with:
        - confidence: weighted average confidence
        - predictor_agreement: how much predictors agree
        - recommended_action: 'report', 'validate', 'ignore'
        """
        if not predictions:
            return {"confidence": 0.0, "predictor_agreement": 0.0, 
                    "recommended_action": "ignore"}
        
        # Filter predictions for this vulnerability type
        relevant = [p for p in predictions 
                   if p.vulnerability_type == vulnerability_type]
        
        if not relevant:
            return {"confidence": 0.0, "predictor_agreement": 0.0,
                    "recommended_action": "ignore"}
        
        # Calculate weighted confidence
        weighted_sum = 0.0
        weight_sum = 0.0
        
        for pred in relevant:
            weight = self._get_dynamic_weight(
                pred.predictor_type.value, 
                vulnerability_type
            )
            weighted_sum += pred.confidence * weight
            weight_sum += weight
        
        final_confidence = weighted_sum / weight_sum if weight_sum > 0 else 0.0
        
        # Calculate predictor agreement (variance-based)
        confidences = [p.confidence for p in relevant]
        agreement = 1.0 - np.std(confidences) if len(confidences) > 1 else 1.0
        
        # Determine recommended action
        if final_confidence >= 0.8 and agreement >= 0.7:
            action = "report"  # High confidence, proceed
        elif final_confidence >= 0.5:
            action = "validate"  # Medium confidence, need exploitation test
        else:
            action = "ignore"  # Low confidence, likely false positive
        
        return {
            "confidence": final_confidence,
            "predictor_agreement": agreement,
            "recommended_action": action,
            "individual_predictions": [
                {"predictor": p.predictor_name, "confidence": p.confidence}
                for p in relevant
            ]
        }
    
    def _get_dynamic_weight(
        self, 
        predictor_type: str, 
        vulnerability_type: str
    ) -> float:
        """
        Get weight adjusted by historical accuracy.
        
        Predictors that are more accurate for specific vulnerability types
        get higher weights for those types.
        """
        base_weight = self.weights.get(predictor_type, 0.33)
        
        # Check if we have accuracy history
        key = f"{predictor_type}:{vulnerability_type}"
        if key in self.accuracy_history:
            history = self.accuracy_history[key]
            if len(history) >= 10:  # Need minimum samples
                recent_accuracy = sum(history[-50:]) / len(history[-50:])
                # Adjust weight based on accuracy (max 2x, min 0.5x)
                adjustment = 0.5 + recent_accuracy * 1.5
                return base_weight * adjustment
        
        return base_weight
    
    def record_outcome(
        self, 
        predictor_type: str, 
        vulnerability_type: str, 
        predicted_confidence: float,
        was_correct: bool
    ):
        """Record outcome for weight learning."""
        key = f"{predictor_type}:{vulnerability_type}"
        if key not in self.accuracy_history:
            self.accuracy_history[key] = []
        
        # Record if prediction was directionally correct
        # (high confidence should be true positive, low should be true negative)
        correct = (predicted_confidence >= 0.5) == was_correct
        self.accuracy_history[key].append(correct)
        
        # Keep only recent history (sliding window)
        if len(self.accuracy_history[key]) > 1000:
            self.accuracy_history[key] = self.accuracy_history[key][-500:]


