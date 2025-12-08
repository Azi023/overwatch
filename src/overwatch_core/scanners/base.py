"""
Base scanner interface that all scanners must implement.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum


class ScannerType(str, Enum):
    """Types of scanners."""
    NETWORK = "network"
    WEB = "web"
    API = "api"
    ACTIVE_DIRECTORY = "active_directory"
    CLOUD = "cloud"
    IOT = "iot"


@dataclass
class ScanResult:
    """Standardized scan result format."""
    scanner_type: ScannerType
    scanner_name: str
    target: str
    findings: List[Dict[str, Any]]
    raw_output: str
    success: bool
    error: str = ""
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class AbstractScanner(ABC):
    """
    Base class for all scanners.
    
    All scanners must:
    1. Implement async scan() method
    2. Return standardized ScanResult
    3. Handle errors gracefully
    4. Log all actions
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.scanner_type = ScannerType.NETWORK  # Override in subclass
        self.scanner_name = self.__class__.__name__
    
    @abstractmethod
    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """
        Execute the scan.
        
        Args:
            target: Target to scan (IP, URL, etc.)
            options: Scanner-specific options
            
        Returns:
            ScanResult with findings
        """
        pass
    
    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """
        Validate target is in correct format.
        
        Args:
            target: Target to validate
            
        Returns:
            True if valid, False otherwise
        """
        pass
    
    def get_capabilities(self) -> List[str]:
        """
        Return list of what this scanner can detect.
        
        Returns:
            List of capability strings
        """
        return []