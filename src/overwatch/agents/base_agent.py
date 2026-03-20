"""
BaseAgent - abstract base class for all Overwatch agents.

Implements the ORIENT → OBSERVE → HYPOTHESIZE → EXECUTE reasoning loop.
Agents are short-lived, focused, and retired after their objective completes
or their budget is exhausted (XBOW model).
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..memory.working_memory import WorkingMemory

logger = logging.getLogger(__name__)


# ──────────────────────────── Data Classes ────────────────────────────

@dataclass
class Hypothesis:
    """A testable prediction about a target."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str = ""
    confidence: float = 0.5          # 0.0 – 1.0
    target: str = ""                 # host:port, URL, parameter name, etc.
    action: str = ""                 # what to do (e.g., "run_nmap", "test_sqli")
    parameters: Dict[str, Any] = field(default_factory=dict)
    vuln_type: Optional[str] = None  # maps to knowledge_base pattern


@dataclass
class HypothesisResult:
    """The outcome of testing a single hypothesis."""
    hypothesis: Hypothesis
    outcome: str = "unknown"         # confirmed, refuted, inconclusive, error
    evidence: Dict[str, Any] = field(default_factory=dict)
    updated_confidence: float = 0.0
    finding: Optional[dict] = None   # populated when outcome == "confirmed"


@dataclass
class AgentState:
    """Snapshot of agent state at a point in time."""
    agent_id: str
    agent_type: str
    objective: str
    status: str                       # running, completed, failed, stopped
    loop_count: int
    confidence: float
    working_memory_snapshot: Dict[str, Any]
    findings: List[dict]


@dataclass
class AgentResult:
    """Final output of an agent's run, returned to the coordinator."""
    agent_id: str
    agent_type: str
    objective: str
    findings: List[dict] = field(default_factory=list)
    discoveries: List[dict] = field(default_factory=list)
    loop_count: int = 0
    tokens_used: int = 0
    cost_usd: float = 0.0
    status: str = "completed"        # completed, failed, stopped, budget_exhausted


# ──────────────────────────── Base Agent ────────────────────────────

class BaseAgent(ABC):
    """
    Abstract base for all Overwatch agent types.

    Subclasses implement the four abstract methods that form the reasoning loop:
        orient()              – understand the environment
        observe()             – gather information via tools
        hypothesize()         – generate testable predictions
        execute_hypothesis()  – test one hypothesis and return a result

    The run() method orchestrates these in order, terminating when:
        - No hypotheses remain
        - Confidence falls below 0.2
        - Budget is exhausted
        - Objective is marked as met (set working_memory.set("objective_met", True))
        - Max loop count is reached (default 20)
    """

    MAX_LOOPS: int = 20
    MIN_CONFIDENCE: float = 0.2

    def __init__(
        self,
        agent_type: str,
        objective: str,
        scope_subset: Optional[dict],
        engagement_id: int,
        session: Any,
        claude_client: Any,
        scope_enforcer: Any,
        budget_manager: Any,
        engagement_memory: Any,
        knowledge_base: Any,
        tools: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.agent_id: str = str(uuid.uuid4())
        self.agent_type: str = agent_type
        self.objective: str = objective
        self.scope_subset: dict = scope_subset or {}
        self.engagement_id: int = engagement_id
        self.session: Any = session
        self.claude_client: Any = claude_client
        self.scope_enforcer: Any = scope_enforcer
        self.budget_manager: Any = budget_manager
        self.engagement_memory: Any = engagement_memory
        self.knowledge_base: Any = knowledge_base
        self.tools: Dict[str, Any] = tools or {}

        self.working_memory: WorkingMemory = WorkingMemory(self.agent_id)
        self._findings: List[dict] = []
        self._discoveries: List[dict] = []
        self._loop_count: int = 0
        self._tokens_used: int = 0
        self._cost_usd: float = 0.0
        self._confidence: float = 1.0
        self._started_at: datetime = datetime.utcnow()

        logger.info(
            "Agent spawned: id=%s type=%s engagement=%d objective='%s'",
            self.agent_id,
            self.agent_type,
            self.engagement_id,
            self.objective[:80],
        )

    # ─────────────────────── Abstract Interface ───────────────────────

    @abstractmethod
    async def orient(self) -> None:
        """
        Orient the agent to its environment.

        Query working memory and engagement memory for relevant prior context.
        Set up initial hypotheses seeds. Called once at the start of run().
        """

    @abstractmethod
    async def observe(self) -> List[dict]:
        """
        Gather fresh information from the environment via tools.

        Returns a list of observation dicts. Each observation should contain
        at minimum {'type': str, 'data': dict}. Results are stored in
        working memory by the caller (run()).
        """

    @abstractmethod
    async def hypothesize(self) -> List[Hypothesis]:
        """
        Generate testable hypotheses based on current observations.

        Uses working_memory and knowledge_base to produce a prioritised list
        of Hypothesis objects. The list may be empty when no more tests apply.
        """

    @abstractmethod
    async def execute_hypothesis(self, hypothesis: Hypothesis) -> HypothesisResult:
        """
        Test a single hypothesis and return the result.

        Should NOT raise exceptions for tool failures — capture errors in the
        HypothesisResult with outcome="error" and evidence containing the error.
        """

    # ─────────────────────── Main Loop ───────────────────────────

    async def run(self) -> AgentResult:
        """
        Execute the ORIENT → OBSERVE → HYPOTHESIZE → EXECUTE loop.

        Returns an AgentResult containing all findings and metadata.
        """
        status = "completed"
        try:
            await self.orient()

            while self._loop_count < self.MAX_LOOPS:
                self._loop_count += 1
                logger.debug(
                    "Agent %s loop %d/%d confidence=%.2f",
                    self.agent_id,
                    self._loop_count,
                    self.MAX_LOOPS,
                    self._confidence,
                )

                # OBSERVE
                observations = await self.observe()
                for obs in observations:
                    self.working_memory.append_to_list("observations", obs)

                # Check objective
                if self.working_memory.get("objective_met", False):
                    logger.info(
                        "Agent %s: objective met after %d loops.",
                        self.agent_id,
                        self._loop_count,
                    )
                    break

                # HYPOTHESIZE
                hypotheses = await self.hypothesize()
                if not hypotheses:
                    logger.info(
                        "Agent %s: no hypotheses generated, terminating.",
                        self.agent_id,
                    )
                    break

                # EXECUTE each hypothesis
                for hypothesis in hypotheses:
                    if self._confidence < self.MIN_CONFIDENCE:
                        logger.info(
                            "Agent %s: confidence %.2f below threshold %.2f, stopping.",
                            self.agent_id,
                            self._confidence,
                            self.MIN_CONFIDENCE,
                        )
                        status = "stopped"
                        break

                    if not self._budget_ok():
                        logger.warning(
                            "Agent %s: budget exhausted, stopping.", self.agent_id
                        )
                        status = "budget_exhausted"
                        break

                    result = await self.execute_hypothesis(hypothesis)
                    await self._process_result(result)

                else:
                    # Loop completed without a break — continue outer loop
                    continue
                # Inner loop broke — propagate the stop signal
                break

        except Exception as exc:
            logger.exception(
                "Agent %s: unhandled error in run loop: %s", self.agent_id, exc
            )
            status = "failed"
            self.working_memory.set("error", str(exc))

        elapsed = (datetime.utcnow() - self._started_at).total_seconds()
        logger.info(
            "Agent %s finished: status=%s loops=%d findings=%d elapsed=%.1fs",
            self.agent_id,
            status,
            self._loop_count,
            len(self._findings),
            elapsed,
        )

        return AgentResult(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            objective=self.objective,
            findings=list(self._findings),
            discoveries=list(self._discoveries),
            loop_count=self._loop_count,
            tokens_used=self._tokens_used,
            cost_usd=self._cost_usd,
            status=status,
        )

    # ─────────────────────── Public Helpers ──────────────────────

    def check_scope(self, target: str) -> bool:
        """
        Return True if target is within the allowed scope.

        Delegates to scope_enforcer if available, otherwise allows all.
        """
        if self.scope_enforcer is None:
            return True
        try:
            return self.scope_enforcer.is_in_scope(target)
        except Exception as exc:
            logger.warning(
                "Agent %s: scope check error for '%s': %s",
                self.agent_id,
                target,
                exc,
            )
            return False

    async def record_finding(self, finding_data: dict) -> None:
        """
        Record a validated finding.

        Adds to the in-memory findings list. Subclasses may override to also
        persist to the database.
        """
        finding = {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "engagement_id": self.engagement_id,
            "discovered_at": datetime.utcnow().isoformat(),
            **finding_data,
        }
        self._findings.append(finding)
        logger.info(
            "Agent %s: finding recorded — type='%s' severity='%s'",
            self.agent_id,
            finding_data.get("vulnerability_type", "unknown"),
            finding_data.get("severity", "unknown"),
        )

    def get_state(self) -> AgentState:
        """Return a snapshot of the current agent state."""
        return AgentState(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            objective=self.objective,
            status="running",
            loop_count=self._loop_count,
            confidence=self._confidence,
            working_memory_snapshot=self.working_memory.snapshot(),
            findings=list(self._findings),
        )

    def add_discovery(self, discovery: dict) -> None:
        """Record a non-finding discovery (open port, service, subdomain, etc.)."""
        self._discoveries.append(
            {
                "agent_id": self.agent_id,
                "discovered_at": datetime.utcnow().isoformat(),
                **discovery,
            }
        )

    def track_tokens(self, input_tokens: int, output_tokens: int, cost: float) -> None:
        """Update token usage and cost tracking."""
        self._tokens_used += input_tokens + output_tokens
        self._cost_usd += cost

    # ─────────────────────── Private Helpers ─────────────────────

    async def _process_result(self, result: HypothesisResult) -> None:
        """Update state based on a hypothesis result."""
        # Update confidence as weighted average
        self._confidence = (
            self._confidence * 0.7 + result.updated_confidence * 0.3
        )

        # Store the result in working memory
        self.working_memory.append_to_list(
            "hypothesis_results",
            {
                "hypothesis_id": result.hypothesis.id,
                "hypothesis": result.hypothesis.description,
                "outcome": result.outcome,
                "confidence": result.updated_confidence,
                "has_finding": result.finding is not None,
            },
        )

        # Record confirmed findings
        if result.outcome == "confirmed" and result.finding is not None:
            await self.record_finding(result.finding)

        # Store discoveries from evidence
        evidence_discoveries = result.evidence.get("discoveries", [])
        for disc in evidence_discoveries:
            self.add_discovery(disc)

    def _budget_ok(self) -> bool:
        """Return True if the budget manager allows continued operation."""
        if self.budget_manager is None:
            return True
        try:
            return self.budget_manager.has_budget(
                tokens_used=self._tokens_used,
                cost_usd=self._cost_usd,
            )
        except Exception:
            return True  # fail open to avoid blocking agents unnecessarily
