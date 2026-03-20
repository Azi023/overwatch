"""
Nmap scanner implementation with learning observation capture.
"""
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import AbstractScanner, ScanResult, ScannerType
from ..learning.observation import Observation, ObservationType
from ..learning.observation_store import ObservationStore
from ..learning.feature_extraction import PortScanFeatureExtractor

logger = logging.getLogger(__name__)

_DANGEROUS_CHARS = {";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r", "\\"}

SCAN_PROFILES: Dict[str, str] = {
    "safe": "-sV -T2",
    "balanced": "-sV -sC -T3",
    "aggressive": "-A -T4",
    "quick": "-sV -T4 -F",
}


class NmapScanner(AbstractScanner):
    """Nmap scanner with integrated learning observation capture."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        observation_store: Optional[ObservationStore] = None,
    ) -> None:
        super().__init__(config)
        self.scanner_type = ScannerType.NETWORK
        self.scanner_name = "nmap"
        self.observation_store = observation_store
        self.feature_extractor = PortScanFeatureExtractor()

    def validate_target(self, target: str) -> bool:
        if not target:
            return False
        if any(c in target for c in _DANGEROUS_CHARS):
            logger.warning("Potential injection in nmap target: %r", target)
            return False
        return True

    def get_capabilities(self) -> List[str]:
        return ["port_scanning", "service_detection", "version_detection", "os_fingerprinting"]

    async def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        scan_job_id: Optional[int] = None,
        target_id: Optional[int] = None,
    ) -> ScanResult:
        options = options or {}
        profile = options.get("profile", "balanced")
        ports = options.get("ports")
        output_dir = options.get("output_dir", "/tmp/overwatch/scans")
        scan_start = datetime.utcnow()

        if not self.validate_target(target):
            result = ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                raw_output="",
                success=False,
                error="Invalid target format",
            )
            if self.observation_store and scan_job_id and target_id:
                await self._capture_observation(
                    target, scan_job_id, target_id,
                    {"error": "Invalid target", "validation_failed": True},
                    False, 0,
                )
            return result

        flags = SCAN_PROFILES.get(profile, SCAN_PROFILES["balanced"])
        if ports and "-F" not in flags:
            flags += f" -p {ports}"

        out_path = Path(output_dir) / target.replace("/", "_").replace(":", "_")
        out_path.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_file = out_path / f"{ts}_nmap.xml"

        cmd = ["nmap", *flags.split(), "-oX", str(xml_file), target]
        logger.info("Running: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
            duration_ms = int((datetime.utcnow() - scan_start).total_seconds() * 1000)

            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="ignore")
                logger.error("Nmap failed (rc=%d): %s", proc.returncode, err)
                result = ScanResult(
                    scanner_type=self.scanner_type,
                    scanner_name=self.scanner_name,
                    target=target,
                    findings=[],
                    raw_output=err,
                    success=False,
                    error=f"Nmap exited with code {proc.returncode}",
                )
                if self.observation_store and scan_job_id and target_id:
                    await self._capture_observation(
                        target, scan_job_id, target_id,
                        {"command": " ".join(cmd), "exit_code": proc.returncode, "stderr": err, "profile": profile},
                        False, duration_ms,
                    )
                return result

            from .nmap_parser import parse_nmap_xml
            scan_data = parse_nmap_xml(str(xml_file))
            stdout_str = stdout.decode("utf-8", errors="ignore")
            ports_found = scan_data.get("ports", [])
            logger.info("Nmap completed — %d ports found", len(ports_found))

            result = ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=ports_found,
                raw_output=stdout_str,
                success=True,
                metadata={"xml_path": str(xml_file), "profile": profile, "scan_duration_ms": duration_ms},
            )

            if self.observation_store and scan_job_id and target_id:
                await self._capture_observation(
                    target, scan_job_id, target_id,
                    {
                        "command": " ".join(cmd),
                        "exit_code": 0,
                        "stdout": stdout_str[:10000],
                        "profile": profile,
                        "ports_found": ports_found,
                        "target_info": scan_data.get("target", {}),
                        "xml_path": str(xml_file),
                    },
                    True, duration_ms,
                    findings=ports_found,
                )

            return result

        except asyncio.TimeoutError:
            logger.error("Nmap scan timed out after 600s")
            result = ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                raw_output="",
                success=False,
                error="Scan timed out after 10 minutes",
            )
            if self.observation_store and scan_job_id and target_id:
                await self._capture_observation(
                    target, scan_job_id, target_id,
                    {"command": " ".join(cmd), "error": "timeout", "profile": profile},
                    False, 600000,
                )
            return result

        except Exception as exc:
            logger.exception("Nmap scan exception: %s", exc)
            result = ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                raw_output="",
                success=False,
                error=str(exc),
            )
            if self.observation_store and scan_job_id and target_id:
                await self._capture_observation(
                    target, scan_job_id, target_id,
                    {"error": str(exc), "error_type": type(exc).__name__, "profile": profile},
                    False, 0,
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
        findings: Optional[List[Dict]] = None,
    ) -> None:
        findings = findings or []
        features = self.feature_extractor.extract({
            "ports_found": findings,
            "scan_duration_ms": scan_duration_ms,
            "success": success,
            "target": target,
        })
        predictions = self._generate_predictions(findings, features)

        obs = Observation(
            id="",
            observation_type=ObservationType.PORT_SCAN,
            timestamp=datetime.utcnow(),
            target_id=target_id,
            scan_job_id=scan_job_id,
            raw_data=raw_data,
            features=features,
            context_ids=[],
            predictions=predictions,
        )
        try:
            await self.observation_store.save(obs)
        except Exception as exc:
            logger.error("Failed to save observation: %s", exc)

    @staticmethod
    def _generate_predictions(findings: List[Dict], features: Dict[str, float]) -> Dict[str, float]:
        high_risk = {21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}
        found_ports = {f.get("port") for f in findings if f.get("port")}
        risky_services = {"telnet", "ftp", "rsh", "rlogin", "vnc"}
        found_services = {f.get("service", "").lower() for f in findings}

        hr_ratio = len(found_ports & high_risk) / max(len(high_risk), 1)
        risky_svc = 1.0 if found_services & risky_services else 0.0
        has_ver = 1.0 if any(f.get("version") for f in findings) else 0.0

        return {
            "high_risk_ports": hr_ratio,
            "risky_services": risky_svc,
            "has_version_info": has_ver,
            "overall_risk": hr_ratio * 0.4 + risky_svc * 0.4 + has_ver * 0.2,
        }
