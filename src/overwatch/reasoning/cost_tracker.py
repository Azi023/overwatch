"""
Cost tracker for Claude API usage within Overwatch engagements.

Records per-call token usage and costs to the AIUsageLog table,
and provides budget-check helpers used by the BudgetManager.
"""
from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import AIUsageLog, Engagement

logger = logging.getLogger(__name__)


class CostTracker:
    """
    Persists Claude API token/cost data and provides budget-check utilities.

    All methods are async and accept an AsyncSession that the caller manages
    (typically injected from a FastAPI dependency or the Coordinator).
    """

    async def record_usage(
        self,
        engagement_id: Optional[int],
        agent_run_id: Optional[int],
        model: str,
        task_type: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        session: AsyncSession,
        duration_ms: Optional[int] = None,
        cached_tokens: int = 0,
    ) -> AIUsageLog:
        """
        Persist one API call's usage data.

        Also atomically increments the Engagement's cumulative tokens_used
        and cost_usd so budget checks stay up to date.

        Returns:
            The newly created AIUsageLog row.
        """
        log_entry = AIUsageLog(
            engagement_id=engagement_id,
            agent_run_id=agent_run_id,
            model=model,
            task_type=task_type,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_tokens=cached_tokens,
            cost=cost_usd,
            duration_ms=duration_ms,
        )
        session.add(log_entry)

        # Propagate usage totals to the Engagement row if linked
        if engagement_id is not None:
            result = await session.get(Engagement, engagement_id)
            if result is not None:
                result.tokens_used = (result.tokens_used or 0) + input_tokens + output_tokens
                result.cost_usd = (result.cost_usd or 0.0) + cost_usd

        await session.flush()

        logger.info(
            "Usage recorded: engagement=%s agent_run=%s model=%s tokens=%d cost=$%.6f",
            engagement_id,
            agent_run_id,
            model,
            input_tokens + output_tokens,
            cost_usd,
        )
        return log_entry

    async def get_engagement_cost(
        self,
        engagement_id: int,
        session: AsyncSession,
    ) -> float:
        """
        Return the total cost in USD spent so far for the given engagement.

        Reads from the Engagement row (kept up to date by record_usage).
        Falls back to a direct SUM query if the row is missing.
        """
        engagement = await session.get(Engagement, engagement_id)
        if engagement is not None:
            return float(engagement.cost_usd or 0.0)

        # Fallback: aggregate directly from the log table
        stmt = select(func.coalesce(func.sum(AIUsageLog.cost), 0.0)).where(
            AIUsageLog.engagement_id == engagement_id
        )
        result = await session.execute(stmt)
        return float(result.scalar_one())

    async def get_engagement_tokens(
        self,
        engagement_id: int,
        session: AsyncSession,
    ) -> int:
        """Return total tokens used for the given engagement."""
        engagement = await session.get(Engagement, engagement_id)
        if engagement is not None:
            return int(engagement.tokens_used or 0)

        stmt = select(
            func.coalesce(
                func.sum(AIUsageLog.input_tokens + AIUsageLog.output_tokens), 0
            )
        ).where(AIUsageLog.engagement_id == engagement_id)
        result = await session.execute(stmt)
        return int(result.scalar_one())

    async def check_budget(
        self,
        engagement_id: int,
        estimated_cost: float,
        session: AsyncSession,
    ) -> bool:
        """
        Return True if spending estimated_cost more stays within budget.

        Returns False (budget exceeded) if:
        - The engagement has a cost_budget_usd set AND
        - current_cost + estimated_cost > cost_budget_usd

        Returns True (allowed) if no budget is configured.
        """
        engagement = await session.get(Engagement, engagement_id)
        if engagement is None:
            logger.warning("check_budget: engagement %d not found — DENYING.", engagement_id)
            return False

        budget = engagement.cost_budget_usd
        if budget is None:
            return True  # No budget configured

        current_cost = float(engagement.cost_usd or 0.0)
        projected = current_cost + estimated_cost

        if projected > budget:
            logger.warning(
                "Budget check FAILED: engagement=%d current=$%.4f estimated=$%.4f budget=$%.4f",
                engagement_id,
                current_cost,
                estimated_cost,
                budget,
            )
            return False

        # Warn at 80%
        if projected >= budget * 0.80:
            logger.warning(
                "Budget warning: engagement=%d at %.0f%% of budget ($%.4f / $%.4f)",
                engagement_id,
                (projected / budget) * 100,
                projected,
                budget,
            )

        return True
