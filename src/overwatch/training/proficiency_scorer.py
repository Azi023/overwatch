"""
Measures agent performance against known-vulnerable training targets.
"""
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import ToolProficiencyScore
from .scenarios import get_expected_findings

logger = logging.getLogger(__name__)


@dataclass
class ProficiencyReport:
    agent_type: str
    target_name: str
    evaluated_at: datetime
    total_expected: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float  # TP / (TP + FP)
    recall: float     # TP / (TP + FN)
    f1_score: float   # 2 * P * R / (P + R)
    overall_score: float  # Weighted: 60% recall, 40% precision
    pass_threshold: float = 0.6


class ProficiencyScorer:
    """Scores agent performance against known-vulnerable training scenarios."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def score_run(
        self,
        agent_type: str,
        target_name: str,
        actual_findings: List[Dict[str, Any]],
    ) -> ProficiencyReport:
        """Compare actual findings against expected and compute proficiency metrics."""
        expected = get_expected_findings(target_name)

        # Match findings by vuln_type + location (fuzzy)
        tp = 0
        matched_expected = set()
        for actual in actual_findings:
            a_type = actual.get("vulnerability_type", actual.get("vuln_type", "")).lower()
            a_loc = actual.get("url", actual.get("location", "")).lower()

            for idx, exp in enumerate(expected):
                if idx in matched_expected:
                    continue
                e_type = exp.get("vuln_type", "").lower()
                e_loc = exp.get("location", "").lower()

                type_match = a_type in e_type or e_type in a_type
                loc_match = not e_loc or e_loc in a_loc or a_loc in e_loc

                if type_match and loc_match:
                    tp += 1
                    matched_expected.add(idx)
                    break

        fp = len(actual_findings) - tp
        fn = len(expected) - len(matched_expected)

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 0.001)
        overall = 0.6 * recall + 0.4 * precision

        report = ProficiencyReport(
            agent_type=agent_type,
            target_name=target_name,
            evaluated_at=datetime.utcnow(),
            total_expected=len(expected),
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            overall_score=overall,
        )

        await self._update_db_score(agent_type, target_name, report)

        if overall < report.pass_threshold:
            logger.warning(
                "Agent %s scored %.2f on %s — below threshold %.2f. Needs retraining.",
                agent_type, overall, target_name, report.pass_threshold,
            )

        return report

    async def _update_db_score(
        self,
        agent_type: str,
        target_name: str,
        report: ProficiencyReport,
    ) -> None:
        from sqlalchemy import select

        result = await self.session.execute(
            select(ToolProficiencyScore).where(
                ToolProficiencyScore.agent_type == agent_type,
                ToolProficiencyScore.tool_name == target_name,
            )
        )
        record = result.scalar_one_or_none()

        if record is None:
            record = ToolProficiencyScore(
                agent_type=agent_type,
                tool_name=target_name,
                total_attempts=0,
                successful_findings=0,
                false_positives=0,
                proficiency_score=0.5,
            )
            self.session.add(record)

        record.total_attempts += 1
        record.successful_findings += report.true_positives
        record.false_positives += report.false_positives
        # Exponential moving average
        record.proficiency_score = 0.7 * record.proficiency_score + 0.3 * report.overall_score
        await self.session.flush()
