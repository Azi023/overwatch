"""
Abstract base class for all scanners.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ScannerType(str, Enum):
    NETWORK = "network"
    WEB = "web"
    VULNERABILITY = "vulnerability"
    DISCOVERY = "discovery"


@dataclass
class ScanResult:
    scanner_type: ScannerType
    scanner_name: str
    target: str
    findings: List[Dict[str, Any]]
    raw_output: str
    success: bool
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class AbstractScanner(ABC):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    @abstractmethod
    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """Execute the scan and return results."""

    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """Validate that target is safe to scan."""

    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """Return list of scanner capabilities."""
