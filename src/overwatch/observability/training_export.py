"""
Training data export — exports engagement data as JSONL for model fine-tuning.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import ObservationModel

logger = logging.getLogger(__name__)


class TrainingExporter:
    """Exports observations with ground truth as JSONL training data."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def export_jsonl(
        self,
        output_path: str,
        observation_type: Optional[str] = None,
        min_confidence: float = 0.0,
    ) -> int:
        """
        Export all observations with ground truth to a JSONL file.

        Returns number of records exported.
        """
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        query = select(ObservationModel).where(ObservationModel.ground_truth.isnot(None))
        if observation_type:
            query = query.where(ObservationModel.observation_type == observation_type)

        count = 0
        with output.open("w") as f:
            result = await self.session.stream(query)
            async for (model,) in result:
                record = {
                    "observation_id": model.id,
                    "observation_type": model.observation_type,
                    "timestamp": model.timestamp.isoformat() if model.timestamp else None,
                    "features": model.features or {},
                    "predictions": model.predictions or {},
                    "ground_truth": model.ground_truth,
                    "ground_truth_source": model.ground_truth_source,
                    "exported_at": datetime.utcnow().isoformat(),
                }
                f.write(json.dumps(record) + "\n")
                count += 1

        logger.info("Exported %d training records to %s", count, output_path)
        return count

    async def export_findings_jsonl(
        self,
        engagement_id: int,
        output_path: str,
    ) -> int:
        """Export confirmed and false-positive findings as labelled training data."""
        from ..persistence.models import Finding

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        query = select(Finding).where(
            Finding.engagement_id == engagement_id,
            Finding.validated == True,  # noqa: E712
        )

        count = 0
        with output.open("w") as f:
            result = await self.session.stream(query)
            async for (finding,) in result:
                record = {
                    "finding_id": finding.id,
                    "vulnerability_type": finding.vulnerability_type,
                    "url": finding.url,
                    "parameter": finding.parameter,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "label": "false_positive" if finding.false_positive else "true_positive",
                    "evidence": finding.evidence,
                    "exported_at": datetime.utcnow().isoformat(),
                }
                f.write(json.dumps(record, default=str) + "\n")
                count += 1

        logger.info("Exported %d findings for engagement %d to %s", count, engagement_id, output_path)
        return count
