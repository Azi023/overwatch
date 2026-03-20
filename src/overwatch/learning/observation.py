"""
Observation system — captures everything the system sees for learning.
"""
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum as PyEnum
from typing import Any, Dict, List, Optional


class ObservationType(str, PyEnum):
    HTTP_RESPONSE = "http_response"
    PORT_SCAN = "port_scan"
    DNS_RECORD = "dns_record"
    TIMING = "timing"
    ERROR_MESSAGE = "error_message"
    HEADER_ANALYSIS = "header_analysis"
    PAYLOAD_RESPONSE = "payload_response"
    TOOL_OUTPUT = "tool_output"
    AGENT_ACTION = "agent_action"


@dataclass
class Observation:
    """Immutable record of something the system observed."""

    id: str
    observation_type: ObservationType
    timestamp: datetime
    target_id: int
    scan_job_id: int
    raw_data: Dict[str, Any]
    features: Dict[str, float] = field(default_factory=dict)
    context_ids: List[str] = field(default_factory=list)
    predictions: Dict[str, float] = field(default_factory=dict)
    ground_truth: Optional[Dict[str, Any]] = None
    ground_truth_source: Optional[str] = None
    ground_truth_timestamp: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.id:
            content = json.dumps(
                {
                    "type": self.observation_type.value,
                    "target": self.target_id,
                    "scan": self.scan_job_id,
                    "data": self.raw_data,
                },
                sort_keys=True,
                default=str,
            )
            self.id = hashlib.sha256(content.encode()).hexdigest()[:16]

    def to_training_example(self) -> Optional[Dict]:
        if self.ground_truth is None:
            return None
        return {
            "observation_id": self.id,
            "observation_type": self.observation_type.value,
            "features": self.features,
            "predictions": self.predictions,
            "ground_truth": self.ground_truth,
            "timestamp": self.timestamp.isoformat(),
        }

    def to_dict(self) -> Dict[str, Any]:
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
            "ground_truth_timestamp": (
                self.ground_truth_timestamp.isoformat()
                if self.ground_truth_timestamp
                else None
            ),
        }
