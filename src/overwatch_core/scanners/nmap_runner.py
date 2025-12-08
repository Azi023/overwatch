"""
Nmap scanner implementation.
Properly handles async execution, error handling, and logging.
"""
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
from .base import AbstractScanner, ScanResult, ScannerType

logger = logging.getLogger(__name__)


class NmapScanner(AbstractScanner):
    """
    Nmap network scanner implementation.
    
    Capabilities:
    - Port scanning
    - Service detection
    - Version detection
    - OS fingerprinting (with -O flag)
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.scanner_type = ScannerType.NETWORK
        self.scanner_name = "nmap"
        
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
        # Basic validation (can be enhanced)
        if not target or len(target) == 0:
            return False
        
        # Check for command injection attempts
        dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">"]
        if any(char in target for char in dangerous_chars):
            logger.warning(f"Potential command injection in target: {target}")
            return False
        
        return True
    
    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """
        Execute nmap scan.
        
        Args:
            target: Target IP or hostname
            options: {
                "profile": "safe" | "balanced" | "aggressive" | "quick",
                "ports": "80,443" or "1-1000" (optional),
                "output_dir": Path to save results (optional)
            }
            
        Returns:
            ScanResult with ports and services found
        """
        options = options or {}
        profile = options.get("profile", "balanced")
        ports = options.get("ports")
        output_dir = options.get("output_dir", "/tmp/overwatch/scans")
        
        # Validate target
        if not self.validate_target(target):
            return ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                raw_output="",
                success=False,
                error="Invalid target format"
            )
        
        # Build nmap command
        flags = self.profiles.get(profile, self.profiles["balanced"])
        
        # Add port specification if provided
        if ports:
            flags += f" -p {ports}"
        
        # Create output directory
        output_path = Path(output_dir) / target.replace("/", "_")
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
            
            # Check return code
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore')
                logger.error(f"Nmap scan failed: {error_msg}")
                return ScanResult(
                    scanner_type=self.scanner_type,
                    scanner_name=self.scanner_name,
                    target=target,
                    findings=[],
                    raw_output=error_msg,
                    success=False,
                    error=f"Nmap exited with code {process.returncode}"
                )
            
            # Parse results
            from .nmap_parser import parse_nmap_xml
            scan_data = parse_nmap_xml(str(xml_file))
            
            logger.info(f"Nmap scan completed. Found {len(scan_data.get('ports', []))} ports")
            
            return ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=scan_data.get("ports", []),
                raw_output=stdout.decode('utf-8', errors='ignore'),
                success=True,
                metadata={
                    "xml_path": str(xml_file),
                    "profile": profile,
                    "scan_duration_seconds": (datetime.now() - datetime.fromtimestamp(xml_file.stat().st_mtime)).seconds
                }
            )
            
        except asyncio.TimeoutError:
            logger.error(f"Nmap scan timed out after 600 seconds")
            return ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                raw_output="",
                success=False,
                error="Scan timed out after 10 minutes"
            )
        except Exception as e:
            logger.exception(f"Nmap scan failed with exception: {e}")
            return ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                raw_output="",
                success=False,
                error=str(e)
            )
    
    def get_capabilities(self) -> List[str]:
        """Return scanner capabilities."""
        return [
            "port_scanning",
            "service_detection",
            "version_detection",
            "os_fingerprinting",
            "script_scanning"
        ]
