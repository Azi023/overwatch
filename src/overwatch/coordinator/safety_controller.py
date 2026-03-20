"""
Safety controller for Overwatch engagements.

Classifies actions by risk level, manages human approval gates,
and provides the kill-switch mechanism that halts an engagement immediately.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import ActionCategory, AIDecision, Engagement

logger = logging.getLogger(__name__)

# ──────────────────────────── Approval dataclass ────────────────────────────

@dataclass
class ApprovalRequest:
    """Represents a pending approval gate for a high-risk action."""

    approval_id: int          # AI decision row ID used as the approval record
    action_type: str
    target: str
    params: Dict[str, Any]
    category: ActionCategory
    reasoning: str
    approved: bool = False
    approved_by: Optional[str] = None


# ──────────────────────────── Classification maps ────────────────────────────

# action_type strings → ActionCategory
_ACTION_CLASSIFICATION: Dict[str, ActionCategory] = {
    # Passive — read-only, no network interaction with target
    "dns_lookup":           ActionCategory.PASSIVE,
    "subdomain_enum":       ActionCategory.PASSIVE,
    "whois":                ActionCategory.PASSIVE,
    "certificate_search":   ActionCategory.PASSIVE,
    "shodan_lookup":        ActionCategory.PASSIVE,
    "osint_gather":         ActionCategory.PASSIVE,

    # Active — non-destructive probes that touch the target
    "port_scan":            ActionCategory.ACTIVE,
    "http_request":         ActionCategory.ACTIVE,
    "banner_grab":          ActionCategory.ACTIVE,
    "vulnerability_scan":   ActionCategory.ACTIVE,
    "service_probe":        ActionCategory.ACTIVE,
    "screenshot":           ActionCategory.ACTIVE,
    "tech_detect":          ActionCategory.ACTIVE,

    # Invasive — may be logged / cause side effects
    "auth_brute_force":     ActionCategory.INVASIVE,
    "fuzzing":              ActionCategory.INVASIVE,
    "sqli_probe":           ActionCategory.INVASIVE,
    "xss_probe":            ActionCategory.INVASIVE,
    "ssrf_probe":           ActionCategory.INVASIVE,
    "file_upload_test":     ActionCategory.INVASIVE,
    "idor_test":            ActionCategory.INVASIVE,
    "payload_injection":    ActionCategory.INVASIVE,

    # Destructive — may alter or destroy data / crash services
    "exploit":              ActionCategory.DESTRUCTIVE,
    "rce":                  ActionCategory.DESTRUCTIVE,
    "file_write":           ActionCategory.DESTRUCTIVE,
    "database_write":       ActionCategory.DESTRUCTIVE,
    "account_modification": ActionCategory.DESTRUCTIVE,
    "dos_test":             ActionCategory.DESTRUCTIVE,
    "data_deletion":        ActionCategory.DESTRUCTIVE,
}

_DEFAULT_REQUIRE_APPROVAL: List[str] = [
    ActionCategory.INVASIVE,
    ActionCategory.DESTRUCTIVE,
]


# ──────────────────────────── SafetyController ────────────────────────────

class SafetyController:
    """
    Manages action risk classification, approval gates, and the kill switch.

    Args:
        engagement_id:        The engagement this controller is bound to.
        session:              SQLAlchemy async session.
        require_approval_for: List of ActionCategory values that need human sign-off.
                              Defaults to INVASIVE and DESTRUCTIVE.
    """

    def __init__(
        self,
        engagement_id: int,
        session: AsyncSession,
        require_approval_for: Optional[List[ActionCategory]] = None,
    ) -> None:
        self._engagement_id = engagement_id
        self._session = session
        self._require_approval_for: List[ActionCategory] = (
            require_approval_for
            if require_approval_for is not None
            else [ActionCategory.INVASIVE, ActionCategory.DESTRUCTIVE]
        )

    # ── Classification ─────────────────────────────────────────────────────

    async def classify_action(
        self,
        action_type: str,
        target: str,
        params: Dict[str, Any],
    ) -> ActionCategory:
        """
        Return the ActionCategory for a planned action.

        Uses the static lookup table; falls back to ACTIVE for unknown types.
        """
        category = _ACTION_CLASSIFICATION.get(action_type.lower(), ActionCategory.ACTIVE)
        logger.debug(
            "classify_action: type=%s target=%s → %s", action_type, target, category.value
        )
        return category

    # ── Approval gate ──────────────────────────────────────────────────────

    async def request_approval(
        self,
        action_type: str,
        target: str,
        params: Dict[str, Any],
        reasoning: str,
    ) -> ApprovalRequest:
        """
        Create an AIDecision row representing a pending approval request.

        The row is persisted immediately with required_approval=True and
        approved=False. An operator must later call approve_action() or
        check_approval() after an out-of-band approval step.

        Returns:
            An ApprovalRequest dataclass with the DB row ID.
        """
        category = await self.classify_action(action_type, target, params)

        decision = AIDecision(
            scan_job_id=self._engagement_id,  # reusing field as engagement ref
            decision_type="approval_request",
            action=action_type,
            reasoning=reasoning,
            parameters={"target": target, **params},
            outcome={},
            success=False,
            confidence=0.0,
            risk_level=category.value,
            action_category=category.value,
            required_approval=True,
            approved=False,
        )
        self._session.add(decision)
        await self._session.flush()

        logger.info(
            "Approval requested: id=%d action=%s target=%s category=%s",
            decision.id,
            action_type,
            target,
            category.value,
        )

        return ApprovalRequest(
            approval_id=decision.id,
            action_type=action_type,
            target=target,
            params=params,
            category=category,
            reasoning=reasoning,
        )

    async def check_approval(self, approval_id: int) -> bool:
        """
        Return True if the approval request with the given ID has been approved.

        Reads directly from the database so it always reflects the latest state.
        """
        decision = await self._session.get(AIDecision, approval_id)
        if decision is None:
            logger.warning("check_approval: no record found for id=%d", approval_id)
            return False
        return bool(decision.approved)

    async def approve_action(
        self,
        approval_id: int,
        approved_by: str = "operator",
    ) -> bool:
        """
        Mark an approval request as approved.

        Returns True on success, False if the record was not found.
        """
        decision = await self._session.get(AIDecision, approval_id)
        if decision is None:
            logger.warning("approve_action: no record found for id=%d", approval_id)
            return False
        decision.approved = True
        decision.approved_by = approved_by
        await self._session.flush()
        logger.info("Action approved: id=%d by=%s", approval_id, approved_by)
        return True

    async def requires_approval(
        self,
        action_type: str,
        target: str,
        params: Dict[str, Any],
    ) -> bool:
        """
        Return True if the action needs a human approval gate before execution.
        """
        category = await self.classify_action(action_type, target, params)
        return category in self._require_approval_for

    # ── Kill switch ────────────────────────────────────────────────────────

    async def activate_kill_switch(
        self,
        engagement_id: int,
        reason: str,
    ) -> None:
        """
        Immediately halt the engagement by setting the kill switch flag in DB.

        After this call, all coordinators / agents that check is_kill_switch_active()
        will stop accepting new tasks.
        """
        engagement = await self._session.get(Engagement, engagement_id)
        if engagement is None:
            logger.error(
                "activate_kill_switch: engagement %d not found — cannot activate.", engagement_id
            )
            return

        from ..persistence.models import EngagementStatus  # local import to avoid circular
        engagement.kill_switch_activated = True
        engagement.kill_switch_reason = reason
        engagement.status = EngagementStatus.STOPPED
        engagement.completed_at = datetime.utcnow()

        await self._session.flush()
        logger.critical(
            "KILL SWITCH ACTIVATED: engagement=%d reason=%s", engagement_id, reason
        )

    async def is_kill_switch_active(self, engagement_id: int) -> bool:
        """
        Return True if the engagement's kill switch has been activated.

        Always queries the database to get the latest state.
        """
        engagement = await self._session.get(Engagement, engagement_id)
        if engagement is None:
            return False
        return bool(engagement.kill_switch_activated)
