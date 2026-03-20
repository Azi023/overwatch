"""
Budget manager for Overwatch engagements.

Enforces token, wall-clock time, and cost budgets.
Issues warnings at 80% utilisation and blocks at 95%.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import Engagement

logger = logging.getLogger(__name__)

# Threshold fractions for warnings and hard stops
_WARN_THRESHOLD = 0.80
_BLOCK_THRESHOLD = 0.95


def _usage_fraction(used: float, budget: float) -> float:
    if budget <= 0:
        return 1.0
    return used / budget


class BudgetManager:
    """
    Tracks and enforces three budget dimensions for an engagement:

    - **token_budget**        Maximum total tokens (input + output) across all API calls.
    - **time_budget_seconds** Maximum wall-clock seconds from the first check.
    - **cost_budget_usd**     Maximum spend in USD.

    Usage is tracked in memory (for speed) and persisted to the Engagement row
    via the session on record_usage().

    Args:
        engagement_id:      The engagement this manager is bound to.
        session:            SQLAlchemy async session.
        token_budget:       Hard token ceiling (None = unlimited).
        time_budget_seconds: Hard time ceiling in seconds (None = unlimited).
        cost_budget_usd:    Hard cost ceiling in USD (None = unlimited).
    """

    def __init__(
        self,
        engagement_id: int,
        session: AsyncSession,
        token_budget: Optional[int] = None,
        time_budget_seconds: Optional[int] = None,
        cost_budget_usd: Optional[float] = None,
    ) -> None:
        self._engagement_id = engagement_id
        self._session = session

        self._token_budget = token_budget
        self._time_budget = time_budget_seconds
        self._cost_budget = cost_budget_usd

        # In-memory accumulators (seeded from DB on first use)
        self._tokens_used: int = 0
        self._cost_used: float = 0.0
        self._start_time: float = time.monotonic()
        self._seeded: bool = False

    # ── Seed from DB ───────────────────────────────────────────────────────

    async def _ensure_seeded(self) -> None:
        """Load existing usage from the Engagement row on the first call."""
        if self._seeded:
            return

        engagement = await self._session.get(Engagement, self._engagement_id)
        if engagement is not None:
            self._tokens_used = int(engagement.tokens_used or 0)
            self._cost_used = float(engagement.cost_usd or 0.0)

            # Override budgets from DB if not provided explicitly
            if self._token_budget is None and engagement.token_budget is not None:
                self._token_budget = engagement.token_budget
            if self._time_budget is None and engagement.time_budget_seconds is not None:
                self._time_budget = engagement.time_budget_seconds
            if self._cost_budget is None and engagement.cost_budget_usd is not None:
                self._cost_budget = engagement.cost_budget_usd

        self._seeded = True

    # ── Token budget ───────────────────────────────────────────────────────

    async def check_token_budget(self, estimated_tokens: int) -> bool:
        """
        Return True if spending estimated_tokens more stays within budget.

        Logs a warning at 80%, returns False at 95%.
        """
        await self._ensure_seeded()

        if self._token_budget is None:
            return True

        projected = self._tokens_used + estimated_tokens
        fraction = _usage_fraction(projected, self._token_budget)

        if fraction >= _BLOCK_THRESHOLD:
            logger.warning(
                "Token budget BLOCKED: engagement=%d projected=%d budget=%d (%.0f%%)",
                self._engagement_id, projected, self._token_budget, fraction * 100,
            )
            return False

        if fraction >= _WARN_THRESHOLD:
            logger.warning(
                "Token budget WARNING: engagement=%d at %.0f%% (%d/%d tokens)",
                self._engagement_id, fraction * 100, projected, self._token_budget,
            )

        return True

    # ── Cost budget ────────────────────────────────────────────────────────

    async def check_cost_budget(self, estimated_cost: float) -> bool:
        """
        Return True if spending estimated_cost more stays within budget.

        Logs a warning at 80%, returns False at 95%.
        """
        await self._ensure_seeded()

        if self._cost_budget is None:
            return True

        projected = self._cost_used + estimated_cost
        fraction = _usage_fraction(projected, self._cost_budget)

        if fraction >= _BLOCK_THRESHOLD:
            logger.warning(
                "Cost budget BLOCKED: engagement=%d projected=$%.4f budget=$%.4f (%.0f%%)",
                self._engagement_id, projected, self._cost_budget, fraction * 100,
            )
            return False

        if fraction >= _WARN_THRESHOLD:
            logger.warning(
                "Cost budget WARNING: engagement=%d at %.0f%% ($%.4f / $%.4f)",
                self._engagement_id, fraction * 100, projected, self._cost_budget,
            )

        return True

    # ── Time budget ────────────────────────────────────────────────────────

    async def check_time_budget(self) -> bool:
        """
        Return True if the engagement is still within its time window.

        Logs a warning at 80%, returns False at 95%.
        """
        await self._ensure_seeded()

        if self._time_budget is None:
            return True

        elapsed = time.monotonic() - self._start_time
        fraction = _usage_fraction(elapsed, self._time_budget)

        if fraction >= _BLOCK_THRESHOLD:
            logger.warning(
                "Time budget BLOCKED: engagement=%d elapsed=%.0fs budget=%ds (%.0f%%)",
                self._engagement_id, elapsed, self._time_budget, fraction * 100,
            )
            return False

        if fraction >= _WARN_THRESHOLD:
            logger.warning(
                "Time budget WARNING: engagement=%d at %.0f%% (%.0fs / %ds)",
                self._engagement_id, fraction * 100, elapsed, self._time_budget,
            )

        return True

    # ── Record usage ───────────────────────────────────────────────────────

    async def record_usage(self, tokens_used: int, cost_usd: float) -> None:
        """
        Update in-memory accumulators and persist to the Engagement row.

        Call this after every successful Claude API call.
        """
        await self._ensure_seeded()

        self._tokens_used += tokens_used
        self._cost_used += cost_usd

        engagement = await self._session.get(Engagement, self._engagement_id)
        if engagement is not None:
            engagement.tokens_used = self._tokens_used
            engagement.cost_usd = self._cost_used
            await self._session.flush()

        logger.debug(
            "Budget usage updated: engagement=%d tokens=%d cost=$%.6f",
            self._engagement_id, self._tokens_used, self._cost_used,
        )

    # ── Remaining budgets ──────────────────────────────────────────────────

    async def get_remaining_budgets(self) -> dict:
        """
        Return a dict of remaining budget capacity across all three dimensions.

        Values are None when no budget is configured for that dimension.
        """
        await self._ensure_seeded()

        elapsed = time.monotonic() - self._start_time

        remaining_tokens: Optional[int] = (
            max(0, self._token_budget - self._tokens_used) if self._token_budget else None
        )
        remaining_time: Optional[float] = (
            max(0.0, self._time_budget - elapsed) if self._time_budget else None
        )
        remaining_cost: Optional[float] = (
            max(0.0, self._cost_budget - self._cost_used) if self._cost_budget else None
        )

        return {
            "tokens_used": self._tokens_used,
            "tokens_remaining": remaining_tokens,
            "token_budget": self._token_budget,
            "elapsed_seconds": round(elapsed, 1),
            "time_remaining_seconds": remaining_time,
            "time_budget_seconds": self._time_budget,
            "cost_used_usd": round(self._cost_used, 6),
            "cost_remaining_usd": remaining_cost,
            "cost_budget_usd": self._cost_budget,
        }

    # ── Convenience all-check ──────────────────────────────────────────────

    async def can_proceed(
        self,
        estimated_tokens: int = 0,
        estimated_cost: float = 0.0,
    ) -> bool:
        """
        Return True only if ALL active budgets allow the estimated usage.

        Checks tokens, cost, and time in parallel.
        """
        token_ok = await self.check_token_budget(estimated_tokens)
        cost_ok = await self.check_cost_budget(estimated_cost)
        time_ok = await self.check_time_budget()
        return token_ok and cost_ok and time_ok
