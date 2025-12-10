"""
Observation system - captures everything the system sees for learning.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional
from enum import Enum as PyEnum
import hashlib
import json


class ObservationType(str, PyEnum):
    """Types of observations the system can make."""
    HTTP_RESPONSE = "http_response"
    PORT_SCAN = "port_scan"
    DNS_RECORD = "dns_record"
    TIMING = "timing"
    ERROR_MESSAGE = "error_message"
    HEADER_ANALYSIS = "header_analysis"
    PAYLOAD_RESPONSE = "payload_response"
    TOOL_OUTPUT = "tool_output"


@dataclass
class Observation:
    """
    Immutable record of something the system observed.
    This is the foundation for ALL learning.
    
    Every scan creates observations. Every observation can be:
    1. Used immediately for detection
    2. Stored for training future models
    3. Validated to create ground truth
    """
    id: str  # Unique hash of observation content
    observation_type: ObservationType
    timestamp: datetime
    target_id: int
    scan_job_id: int
    
    # The raw observation data (what we actually saw)
    raw_data: Dict[str, Any]
    
    # Extracted features (learnable numerical representations)
    features: Dict[str, float] = field(default_factory=dict)
    
    # Context from other observations in the same scan
    context_ids: List[str] = field(default_factory=list)
    
    # What different predictors thought about this observation
    predictions: Dict[str, float] = field(default_factory=dict)
    
    # Ground truth (filled in later via validation or human feedback)
    ground_truth: Optional[Dict[str, Any]] = None
    ground_truth_source: Optional[str] = None  # 'exploitation', 'human', 'verified'
    ground_truth_timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        """Generate deterministic ID from content."""
        if not self.id:
            content = json.dumps(
                {
                    "type": self.observation_type.value,
                    "target": self.target_id,
                    "scan": self.scan_job_id,
                    "data": self.raw_data
                }, 
                sort_keys=True
            )
            self.id = hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def to_training_example(self) -> Optional[Dict]:
        """
        Convert to ML training format if ground truth exists.
        
        Returns:
            Dict with features, predictions, and ground_truth
            None if no ground truth available
        """
        if self.ground_truth is None:
            return None
        
        return {
            "observation_id": self.id,
            "observation_type": self.observation_type.value,
            "features": self.features,
            "predictions": self.predictions,
            "ground_truth": self.ground_truth,
            "timestamp": self.timestamp.isoformat()
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "id": self.id,
            "observation_type": self.observation_type.value,
            "timestamp": self.timestamp.isoformat(),
            "target_id": self.target_id,
            "scan_job_id": self.scan_job_id,
            "raw_data": self.raw_data,
            "features": self.features,
            "context_ids": self.context_ids,
            "predictions": self.predictions,
            "ground_truth": self.ground_truth,
            "ground_truth_source": self.ground_truth_source,
            "ground_truth_timestamp": self.ground_truth_timestamp.isoformat() if self.ground_truth_timestamp else None
        }