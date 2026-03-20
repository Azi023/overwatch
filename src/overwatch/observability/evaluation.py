"""
Engagement evaluation metrics for Overwatch V2.

Computes quality indicators (TP rate, FP rate, coverage, efficiency,
per-agent performance) from the findings and agent-run data stored
in the database.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import AgentRun, AttackGraphNode, Engagement, Finding

logger = logging.getLogger(__name__)


# ──────────────────────────── Report dataclass ────────────────────────────

@dataclass
class AgentPerformance:
    agent_type: str
    findings_count: int
    tokens_used: int
    cost_usd: float
    success_rate: float          # completed / total spawns


@dataclass
class EvaluationReport:
    engagement_id: int
    timestamp: datetime

    # Core quality metrics
    true_positive_rate: float    # validated & not FP / total findings
    false_positive_rate: float   # false_positives / total findings
    coverage_score: float        # nodes tested / total nodes in attack graph
    efficiency: float            # findings per dollar spent

    # Totals
    total_findings: int
    validated_findings: int
    false_positives: int
    total_cost_usd: float
    total_tokens: int

    # Per-agent breakdown
    agent_performance: List[AgentPerformance] = field(default_factory=list)

    # Optional raw data for downstream use
    raw: Dict[str, Any] = field(default_factory=dict)


# ──────────────────────────── Evaluator ────────────────────────────

class EngagementEvaluator:
    """
    Compute evaluation metrics for a completed or in-progress engagement.

    Usage::

        evaluator = EngagementEvaluator(session_factory=AsyncSessionLocal)
        report = await evaluator.compute_metrics(engagement_id=7)
        print(report.true_positive_rate)
    """

    def __init__(self, session_factory: Callable[..., Any]) -> None:
        """
        Args:
            session_factory: Async session factory (e.g. ``AsyncSessionLocal``).
        """
        self._session_factory = session_factory

    async def compute_metrics(self, engagement_id: int) -> EvaluationReport:
        """
        Compute all metrics for the given engagement.

        Returns:
            EvaluationReport populated with the computed values.

        Raises:
            ValueError: If the engagement does not exist.
        """
        async with self._session_factory() as session:
            engagement = await session.get(Engagement, engagement_id)
            if engagement is None:
                raise ValueError(f"Engagement {engagement_id} not found")

            findings = await self._load_findings(session, engagement_id)
            agent_runs = await self._load_agent_runs(session, engagement_id)
            attack_surface_size = await self._count_attack_graph_nodes(session, engagement_id)

        # ── Finding metrics ──────────────────────────────────────
        total_findings = len(findings)
        validated_findings = sum(1 for f in findings if f.validated and not f.false_positive)
        false_positives = sum(1 for f in findings if f.false_positive)

        true_positive_rate = (
            validated_findings / total_findings if total_findings > 0 else 0.0
        )
        false_positive_rate = (
            false_positives / total_findings if total_findings > 0 else 0.0
        )

        # ── Coverage ─────────────────────────────────────────────
        # Count unique targets tested (from Finding.url / agent runs)
        tested_nodes = len({f.url for f in findings if f.url})
        coverage_score = (
            tested_nodes / attack_surface_size
            if attack_surface_size > 0
            else 0.0
        )
        coverage_score = min(coverage_score, 1.0)

        # ── Cost / efficiency ────────────────────────────────────
        total_cost_usd: float = engagement.cost_usd or 0.0
        total_tokens: int = engagement.tokens_used or 0

        # Fallback: sum agent runs if engagement totals not updated yet
        if total_cost_usd == 0.0 and agent_runs:
            total_cost_usd = sum(a.cost_usd for a in agent_runs)
        if total_tokens == 0 and agent_runs:
            total_tokens = sum(a.tokens_used for a in agent_runs)

        efficiency = (
            validated_findings / total_cost_usd if total_cost_usd > 0.0 else 0.0
        )

        # ── Per-agent performance ────────────────────────────────
        agent_perf = self._compute_agent_performance(agent_runs)

        return EvaluationReport(
            engagement_id=engagement_id,
            timestamp=datetime.now(tz=timezone.utc),
            true_positive_rate=round(true_positive_rate, 4),
            false_positive_rate=round(false_positive_rate, 4),
            coverage_score=round(coverage_score, 4),
            efficiency=round(efficiency, 4),
            total_findings=total_findings,
            validated_findings=validated_findings,
            false_positives=false_positives,
            total_cost_usd=round(total_cost_usd, 6),
            total_tokens=total_tokens,
            agent_performance=agent_perf,
            raw={
                "attack_surface_size": attack_surface_size,
                "tested_nodes": tested_nodes,
            },
        )

    # ── Private helpers ───────────────────────────────────────────

    @staticmethod
    async def _load_findings(
        session: AsyncSession, engagement_id: int
    ) -> List[Finding]:
        result = await session.execute(
            select(Finding).where(Finding.engagement_id == engagement_id)
        )
        return list(result.scalars().all())

    @staticmethod
    async def _load_agent_runs(
        session: AsyncSession, engagement_id: int
    ) -> List[AgentRun]:
        result = await session.execute(
            select(AgentRun).where(AgentRun.engagement_id == engagement_id)
        )
        return list(result.scalars().all())

    @staticmethod
    async def _count_attack_graph_nodes(
        session: AsyncSession, engagement_id: int
    ) -> int:
        result = await session.execute(
            select(func.count(AttackGraphNode.id)).where(
                AttackGraphNode.engagement_id == engagement_id
            )
        )
        return result.scalar_one() or 0

    @staticmethod
    def _compute_agent_performance(
        agent_runs: List[AgentRun],
    ) -> List[AgentPerformance]:
        """Aggregate per-agent-type statistics."""
        buckets: Dict[str, Dict[str, Any]] = {}

        for run in agent_runs:
            atype = run.agent_type
            if atype not in buckets:
                buckets[atype] = {
                    "findings_count": 0,
                    "tokens_used": 0,
                    "cost_usd": 0.0,
                    "total_runs": 0,
                    "completed_runs": 0,
                }
            bucket = buckets[atype]
            bucket["findings_count"] += run.findings_count
            bucket["tokens_used"] += run.tokens_used
            bucket["cost_usd"] += run.cost_usd
            bucket["total_runs"] += 1
            if run.status.value in ("completed",):
                bucket["completed_runs"] += 1

        performance: List[AgentPerformance] = []
        for atype, stats in buckets.items():
            total = stats["total_runs"]
            performance.append(
                AgentPerformance(
                    agent_type=atype,
                    findings_count=stats["findings_count"],
                    tokens_used=stats["tokens_used"],
                    cost_usd=round(stats["cost_usd"], 6),
                    success_rate=round(stats["completed_runs"] / total, 4) if total > 0 else 0.0,
                )
            )
        return performance
