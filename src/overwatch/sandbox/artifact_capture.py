"""
Captures evidence artifacts from agent actions.
Screenshots, HTTP pairs, tool outputs, timestamps — organized by engagement/finding.
"""
import asyncio
import json
import logging
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ArtifactCapture:
    """Captures and organises evidence from pentesting agent actions."""

    def __init__(
        self,
        base_dir: str = "/tmp/overwatch/artifacts",
        engagement_id: Optional[int] = None,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.engagement_id = engagement_id
        self._engagement_dir = (
            self.base_dir / f"engagement_{engagement_id}"
            if engagement_id
            else self.base_dir / "general"
        )
        self._engagement_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _finding_dir(self, finding_id: str) -> Path:
        d = self._engagement_dir / f"finding_{finding_id}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    async def capture_http_pair(
        self,
        finding_id: str,
        request: Dict[str, Any],
        response: Dict[str, Any],
        label: str = "request",
    ) -> str:
        """Store a raw HTTP request/response pair as JSON."""
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        path = self._finding_dir(finding_id) / f"{label}_{ts}.json"
        data = {
            "timestamp": ts,
            "request": request,
            "response": response,
        }
        path.write_text(json.dumps(data, indent=2, default=str))
        logger.debug("Captured HTTP pair: %s", path)
        return str(path)

    async def capture_tool_output(
        self,
        finding_id: str,
        tool_name: str,
        command: str,
        output: str,
    ) -> str:
        """Store raw tool command + output."""
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        path = self._finding_dir(finding_id) / f"{tool_name}_{ts}.txt"
        path.write_text(f"# Command: {command}\n\n{output}")
        logger.debug("Captured tool output: %s", path)
        return str(path)

    async def capture_screenshot(
        self,
        finding_id: str,
        url: str,
        screenshot_bytes: bytes,
    ) -> str:
        """Store a screenshot as PNG."""
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        path = self._finding_dir(finding_id) / f"screenshot_{ts}.png"
        path.write_bytes(screenshot_bytes)
        logger.debug("Captured screenshot for %s: %s", url, path)
        return str(path)

    async def capture_poc_script(
        self,
        finding_id: str,
        poc_content: str,
        format: str = "sh",
    ) -> str:
        """Store a PoC script."""
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        path = self._finding_dir(finding_id) / f"poc_{ts}.{format}"
        path.write_text(poc_content)
        if format != "json":
            path.chmod(0o700)
        logger.debug("Captured PoC script: %s", path)
        return str(path)

    async def package_evidence(self, output_path: Optional[str] = None) -> str:
        """Create a ZIP archive of all evidence for this engagement."""
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        zip_name = f"evidence_engagement_{self.engagement_id}_{ts}.zip"
        zip_path = Path(output_path or "/tmp/overwatch") / zip_name

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in self._engagement_dir.rglob("*"):
                if file.is_file():
                    zf.write(file, file.relative_to(self._engagement_dir))

        logger.info("Packaged evidence to %s", zip_path)
        return str(zip_path)

    def list_artifacts(self, finding_id: Optional[str] = None) -> List[str]:
        """List all captured artifact paths."""
        search_dir = self._finding_dir(finding_id) if finding_id else self._engagement_dir
        return [str(p) for p in search_dir.rglob("*") if p.is_file()]
