"""
Evidence packager — creates ZIP archives of all finding evidence.
"""
from __future__ import annotations

import json
import logging
import zipfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


class EvidencePackager:
    """Creates ZIP packages with all evidence organized by finding."""

    def __init__(self, artifacts_base_dir: str = "/tmp/overwatch/artifacts") -> None:
        self.base_dir = Path(artifacts_base_dir)

    async def package_engagement(
        self,
        engagement_id: int,
        findings: List[dict],
        output_dir: str = "/tmp/overwatch/reports",
    ) -> str:
        """
        Package all evidence for an engagement into a ZIP.
        Returns path to the ZIP file.
        """
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        zip_name = f"evidence_engagement_{engagement_id}_{ts}.zip"
        zip_path = Path(output_dir) / zip_name
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Write findings index
            index = json.dumps(
                {"engagement_id": engagement_id, "findings_count": len(findings), "exported_at": ts},
                indent=2,
            )
            zf.writestr("index.json", index)

            # Write each finding
            for finding in findings:
                fid = finding.get("id", "unknown")
                finding_json = json.dumps(finding, indent=2, default=str)
                zf.writestr(f"findings/finding_{fid}.json", finding_json)

                # Include any artifact files (skip symlinks to prevent traversal)
                artifact_dir = self.base_dir / f"engagement_{engagement_id}" / f"finding_{fid}"
                if artifact_dir.exists():
                    for artifact in artifact_dir.rglob("*"):
                        if artifact.is_symlink():
                            logger.warning("Skipping symlink in evidence: %s", artifact)
                            continue
                        if artifact.is_file():
                            # Ensure artifact is within the expected directory
                            try:
                                artifact.resolve().relative_to(artifact_dir.resolve())
                            except ValueError:
                                logger.warning("Skipping out-of-directory artifact: %s", artifact)
                                continue
                            arcname = f"artifacts/finding_{fid}/{artifact.relative_to(artifact_dir)}"
                            zf.write(artifact, arcname)

        logger.info("Packaged evidence to %s", zip_path)
        return str(zip_path)
