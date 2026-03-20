"""
Nmap scanner implementation with observation capture for learning.
Properly handles async execution, error handling, logging, and learning data collection.
"""
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from .base import AbstractScanner, ScanResult, ScannerType

# Learning imports
from ..learning.observation import Observation, ObservationType
from ..learning.observation_store import ObservationStore
from ..learning.feature_extraction import PortScanFeatureExtractor

logger = logging.getLogger(__name__)


class NmapScanner(AbstractScanner):
    """
    Nmap network scanner implementation with learning capabilities.
    
    Capabilities:
    - Port scanning
    - Service detection
    - Version detection
    - OS fingerprinting (with -O flag)
    
    Learning Features:
    - Creates observations for every scan
    - Extracts features for ML training
    - Stores predictions for validation
    """
    
    def __init__(
        self, 
        config: Dict[str, Any] = None,
        observation_store: Optional[ObservationStore] = None
    ):
        super().__init__(config)
        self.scanner_type = ScannerType.NETWORK
        self.scanner_name = "nmap"
        self.observation_store = observation_store
        self.feature_extractor = PortScanFeatureExtractor()
        
        # Scan profiles
        self.profiles = {
            "safe": "-sV -T2",
            "balanced": "-sV -sC -T3",
            "aggressive": "-A -T4",
            "quick": "-sV -T4 -F",  # Fast scan, common ports only
        }
    
    def validate_target(self, target: str) -> bool:
        """
        Validate target is valid IP or hostname.
        
        Args:
            target: IP address or hostname
            
        Returns:
            True if valid
        """
        if not target or len(target) == 0:
            return False
        
        # Check for command injection attempts
        dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r"]
        if any(char in target for char in dangerous_chars):
            logger.warning(f"Potential command injection in target: {target}")
            return False
        
        return True
    
    async def scan(
        self, 
        target: str, 
        options: Dict[str, Any] = None,
        scan_job_id: Optional[int] = None,
        target_id: Optional[int] = None
    ) -> ScanResult:
        """
        Execute nmap scan with observation capture.
        
        Args:
            target: Target IP or hostname
            options: {
                "profile": "safe" | "balanced" | "aggressive" | "quick",
                "ports": "80,443" or "1-1000" (optional),
                "output_dir": Path to save results (optional)
            }
            scan_job_id: ID for associating observations (for learning)
            target_id: Target ID for associating observations (for learning)
            
        Returns:
            ScanResult with ports and services found
        """
        options = options or {}
        profile = options.get("profile", "balanced")
        ports = options.get("ports")
        output_dir = options.get("output_dir", "/tmp/overwatch/scans")
        
        scan_start_time = datetime.utcnow()
        
        # Validate target
        if not self.validate_target(target):
            result = ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                raw_output="",
                success=False,
                error="Invalid target format"
            )
            
            # Still capture observation for failed validation (learning from failures)
            if self.observation_store and scan_job_id and target_id:
                await self._capture_observation(
                    target=target,
                    scan_job_id=scan_job_id,
                    target_id=target_id,
                    raw_data={
                        "error": "Invalid target format",
                        "target": target,
                        "validation_failed": True
                    },
                    success=False,
                    scan_duration_ms=0
                )
            
            return result
        
        # Build nmap command
        flags = self.profiles.get(profile, self.profiles["balanced"])
        
        # Add port specification if provided (and not using quick profile)
        if ports and "-F" not in flags:
            flags += f" -p {ports}"
        
        # Create output directory
        output_path = Path(output_dir) / target.replace("/", "_").replace(":", "_")
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_file = output_path / f"{timestamp}_nmap.xml"
        
        # Build command (using list to prevent shell injection)
        cmd = [
            "nmap",
            *flags.split(),
            "-oX", str(xml_file),
            target
        ]
        
        logger.info(f"Running nmap scan: {' '.join(cmd)}")
        
        try:
            # Execute nmap asynchronously
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=600  # 10 minutes max
            )
            
            scan_end_time = datetime.utcnow()
            scan_duration_ms = int((scan_end_time - scan_start_time).total_seconds() * 1000)
            
            # Check return code
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore')
                logger.error(f"Nmap scan failed: {error_msg}")
                
                result = ScanResult(
                    scanner_type=self.scanner_type,
                    scanner_name=self.scanner_name,
                    target=target,
                    findings=[],
                    raw_output=error_msg,
                    success=False,
                    error=f"Nmap exited with code {process.returncode}"
                )
                
                # Capture failed scan observation
                if self.observation_store and scan_job_id and target_id:
                    await self._capture_observation(
                        target=target,
                        scan_job_id=scan_job_id,
                        target_id=target_id,
                        raw_data={
                            "command": " ".join(cmd),
                            "exit_code": process.returncode,
                            "stderr": error_msg,
                            "profile": profile
                        },
                        success=False,
                        scan_duration_ms=scan_duration_ms
                    )
                
                return result
            
            # Parse results
            from .nmap_parser import parse_nmap_xml
            scan_data = parse_nmap_xml(str(xml_file))
            
            stdout_str = stdout.decode('utf-8', errors='ignore')
            
            logger.info(f"Nmap scan completed. Found {len(scan_data.get('ports', []))} ports")
            
            result = ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=scan_data.get("ports", []),
                raw_output=stdout_str,
                success=True,
                metadata={
                    "xml_path": str(xml_file),
                    "profile": profile,
                    "scan_duration_ms": scan_duration_ms
                }
            )
            
            # Capture successful scan observation for learning
            if self.observation_store and scan_job_id and target_id:
                await self._capture_observation(
                    target=target,
                    scan_job_id=scan_job_id,
                    target_id=target_id,
                    raw_data={
                        "command": " ".join(cmd),
                        "exit_code": 0,
                        "stdout": stdout_str[:10000],  # Limit size
                        "profile": profile,
                        "ports_found": scan_data.get("ports", []),
                        "target_info": scan_data.get("target", {}),
                        "xml_path": str(xml_file)
                    },
                    success=True,
                    scan_duration_ms=scan_duration_ms,
                    findings=scan_data.get("ports", [])
                )
            
            return result
            
        except asyncio.TimeoutError:
            logger.error(f"Nmap scan timed out after 600 seconds")
            
            result = ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                raw_output="",
                success=False,
                error="Scan timed out after 10 minutes"
            )
            
            # Capture timeout observation
            if self.observation_store and scan_job_id and target_id:
                await self._capture_observation(
                    target=target,
                    scan_job_id=scan_job_id,
                    target_id=target_id,
                    raw_data={
                        "command": " ".join(cmd),
                        "error": "timeout",
                        "timeout_seconds": 600,
                        "profile": profile
                    },
                    success=False,
                    scan_duration_ms=600000
                )
            
            return result
            
        except Exception as e:
            logger.exception(f"Nmap scan failed with exception: {e}")
            
            result = ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                raw_output="",
                success=False,
                error=str(e)
            )
            
            # Capture exception observation
            if self.observation_store and scan_job_id and target_id:
                await self._capture_observation(
                    target=target,
                    scan_job_id=scan_job_id,
                    target_id=target_id,
                    raw_data={
                        "error": str(e),
                        "error_type": type(e).__name__,
                        "profile": profile
                    },
                    success=False,
                    scan_duration_ms=0
                )
            
            return result
    
    async def _capture_observation(
        self,
        target: str,
        scan_job_id: int,
        target_id: int,
        raw_data: Dict[str, Any],
        success: bool,
        scan_duration_ms: int,
        findings: List[Dict] = None
    ) -> Observation:
        """
        Capture scan observation for learning.
        
        This is the key integration point - every scan creates
        an observation that can be used for training.
        """
        findings = findings or []
        
        # Extract features for ML
        features = self.feature_extractor.extract({
            "ports_found": findings,
            "scan_duration_ms": scan_duration_ms,
            "success": success,
            "target": target
        })
        
        # Generate rule-based predictions
        predictions = self._generate_predictions(findings, features)
        
        observation = Observation(
            id="",  # Will be auto-generated
            observation_type=ObservationType.PORT_SCAN,
            timestamp=datetime.utcnow(),
            target_id=target_id,
            scan_job_id=scan_job_id,
            raw_data=raw_data,
            features=features,
            context_ids=[],
            predictions=predictions
        )
        
        try:
            await self.observation_store.save(observation)
            logger.debug(f"Saved observation {observation.id} for scan job {scan_job_id}")
        except Exception as e:
            logger.error(f"Failed to save observation: {e}")
        
        return observation
    
    def _generate_predictions(
        self, 
        findings: List[Dict], 
        features: Dict[str, float]
    ) -> Dict[str, float]:
        """
        Generate rule-based predictions from scan results.
        
        These predictions can be compared against ML/LLM predictions
        and validated with ground truth.
        """
        predictions = {}
        
        # High-risk port detection
        high_risk_ports = {21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}
        found_ports = {f.get("port") for f in findings if f.get("port")}
        
        high_risk_found = found_ports & high_risk_ports
        predictions["high_risk_ports"] = len(high_risk_found) / max(len(high_risk_ports), 1)
        
        # Service exposure risk
        risky_services = {"telnet", "ftp", "rsh", "rlogin", "vnc"}
        found_services = {f.get("service", "").lower() for f in findings}
        predictions["risky_services"] = 1.0 if found_services & risky_services else 0.0
        
        # Version detection (old versions = higher risk)
        predictions["has_version_info"] = 1.0 if any(f.get("version") for f in findings) else 0.0
        
        # Overall risk score (simple weighted average)
        predictions["overall_risk"] = (
            predictions["high_risk_ports"] * 0.4 +
            predictions["risky_services"] * 0.4 +
            predictions["has_version_info"] * 0.2
        )
        
        return predictions
    
    def get_capabilities(self) -> List[str]:
        """Return scanner capabilities."""
        return [
            "port_scanning",
            "service_detection",
            "version_detection",
            "os_fingerprinting",
            "script_scanning"
        ]