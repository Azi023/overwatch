"""
Central deterministic orchestration engine for Overwatch engagements.

The Coordinator is NOT LLM-based. It uses LLM outputs (via ClaudeClient)
as structured data to make deterministic planning decisions. It never lets
the LLM choose what to do without a hard validation step.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import (
    AttackGraphNode,
    Engagement,
    EngagementStatus,
)
from ..reasoning.claude_client import ClaudeClient
from ..reasoning.prompt_templates import SYSTEM_COORDINATOR
from .scope_enforcer import ScopeEnforcer
from .target_map import TargetMap

logger = logging.getLogger(__name__)


# ──────────────────────────── AgentTask dataclass ────────────────────────────

@dataclass
class AgentTask:
    """A unit of work to be dispatched to an agent."""

    agent_type: str                    # recon, webapp, auth, network, triage, pivot, report
    objective: str                     # Single-sentence goal
    scope_subset: Dict[str, Any]       # Allowed hosts/ports/paths for this task
    priority: int = 5                  # 1 (highest) to 10 (lowest)
    metadata: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)   # agent_run_ids to wait for


# ──────────────────────────── Follow-up spawn rules ──────────────────────────

# discovery_type → agent types to spawn as follow-ups
_FOLLOWUP_RULES: Dict[str, List[str]] = {
    "web_service":       ["webapp", "auth"],
    "http_service":      ["webapp", "auth"],
    "https_service":     ["webapp", "auth"],
    "admin_panel":       ["auth", "webapp"],
    "api_endpoint":      ["webapp", "auth"],
    "login_page":        ["auth"],
    "database_service":  ["network"],
    "ssh_service":       ["network"],
    "new_host":          ["recon"],
    "finding_confirmed": ["triage"],
    "credentials_found": ["pivot"],
}

# Agent types that are always low-priority cleanup at the end
_TERMINAL_AGENTS = frozenset({"triage", "report"})


# ──────────────────────────── Coordinator ────────────────────────────────────

class Coordinator:
    """
    Central orchestration engine for a single engagement.

    Responsibilities:
    - Build and maintain the TargetMap from agent discoveries.
    - Maintain the AttackGraph in the database.
    - Use LLM analysis to produce prioritised AgentTask lists.
    - Enforce scope and safety on every planned task.
    - Activate kill switch when required.

    Args:
        engagement_id:  Database ID of the Engagement row.
        session:        SQLAlchemy async session (caller-managed).
        claude_client:  Configured ClaudeClient instance.
        scope_enforcer: ScopeEnforcer initialised with engagement scope.
    """

    def __init__(
        self,
        engagement_id: int,
        session: AsyncSession,
        claude_client: ClaudeClient,
        scope_enforcer: ScopeEnforcer,
    ) -> None:
        self._engagement_id = engagement_id
        self._session = session
        self._claude = claude_client
        self._scope = scope_enforcer
        self._target_map: TargetMap = TargetMap(engagement_id=engagement_id)
        self._completed_agent_run_ids: List[str] = []
        self._kill_switch_active: bool = False

    # ── Initialisation ─────────────────────────────────────────────────────

    async def initialize(self, target_info: Dict[str, Any]) -> None:
        """
        Seed the TargetMap with initial target information.

        target_info schema::

            {
              "ip": "<IP or None>",
              "hostname": "<hostname or None>",
              "url": "<base URL or None>",
              "ports": [80, 443, ...],
              "services": [{"port": 80, "protocol": "tcp", "service": "http"}],
              "properties": {}
            }
        """
        ip = target_info.get("ip", "")
        hostname = target_info.get("hostname")

        if ip:
            self._target_map = self._target_map.add_host(
                ip=ip,
                hostname=hostname,
                properties=target_info.get("properties", {}),
            )

        for svc in target_info.get("services", []):
            host_key = ip or hostname or "unknown"
            self._target_map = self._target_map.add_service(
                host=host_key,
                port=int(svc["port"]),
                protocol=svc.get("protocol", "tcp"),
                service_name=svc.get("service", "unknown"),
                version=svc.get("version"),
            )

        if target_info.get("url"):
            self._target_map = self._target_map.add_endpoint(
                url=target_info["url"],
                method="GET",
            )

        # Persist initial host node to attack graph
        if ip:
            await self.update_attack_graph(
                node_type="host",
                node_id=ip,
                label=hostname or ip,
                properties=target_info.get("properties", {}),
                confidence=1.0,
            )

        logger.info(
            "Coordinator initialised: engagement=%d target_map=%s",
            self._engagement_id,
            self._target_map,
        )

    # ── Strategy planning ──────────────────────────────────────────────────

    async def plan_strategy(self) -> List[AgentTask]:
        """
        Determine the initial set of agents to spawn for this engagement.

        Uses the attack surface summary + LLM planning to produce a
        prioritised, scope-checked task list.

        Returns:
            List of AgentTask objects ready to dispatch.
        """
        if self._kill_switch_active:
            logger.warning("plan_strategy called but kill switch is active — returning empty.")
            return []

        surface = self._target_map.get_attack_surface_summary()
        engagement = await self._session.get(Engagement, self._engagement_id)
        objectives = getattr(engagement, "objectives", []) if engagement else []

        prompt_content = (
            f"Target attack surface:\n{surface}\n\n"
            f"Engagement objectives: {objectives}\n\n"
            "Plan the initial set of agent tasks to maximise coverage within scope."
        )

        response, parsed = await self._claude.complete_with_json(
            task_type="strategic_planning",
            messages=[{"role": "user", "content": prompt_content}],
            system_prompt=SYSTEM_COORDINATOR,
            max_tokens=2048,
        )

        tasks = self._parse_recommended_tasks(parsed)

        # Enforce scope on every task
        scope_checked: List[AgentTask] = []
        for task in tasks:
            if self._is_task_in_scope(task):
                scope_checked.append(task)
            else:
                logger.warning(
                    "Dropping out-of-scope task: type=%s objective=%s",
                    task.agent_type, task.objective,
                )

        # Always start with recon if no host information yet
        if not self._target_map.get_all_hosts() and not any(
            t.agent_type == "recon" for t in scope_checked
        ):
            scope_checked.insert(0, AgentTask(
                agent_type="recon",
                objective="Perform initial reconnaissance of the target.",
                scope_subset=self._get_full_scope_subset(),
                priority=1,
            ))

        scope_checked.sort(key=lambda t: t.priority)
        logger.info(
            "plan_strategy: %d tasks planned for engagement=%d",
            len(scope_checked), self._engagement_id,
        )
        return scope_checked

    # ── Result processing ──────────────────────────────────────────────────

    async def process_agent_result(
        self,
        agent_run_id: str,
        result: Dict[str, Any],
    ) -> List[AgentTask]:
        """
        Ingest a completed agent's result and decide what to do next.

        Updates the TargetMap and AttackGraph, then asks the LLM coordinator
        what follow-up tasks (if any) are warranted.

        Args:
            agent_run_id: The string UUID / DB ID of the completed AgentRun.
            result:       The agent's JSON output (structure varies by agent type).

        Returns:
            List of new AgentTask objects to dispatch (may be empty).
        """
        if self._kill_switch_active:
            return []

        self._completed_agent_run_ids.append(agent_run_id)

        # Integrate discoveries into target map
        await self._integrate_discoveries(result)

        # Ask LLM what to do next
        surface = self._target_map.get_attack_surface_summary()
        prompt_content = (
            f"Updated attack surface after agent {agent_run_id} completed:\n{surface}\n\n"
            f"Agent result summary: {result.get('summary', 'No summary provided')}\n\n"
            f"Completed agents so far: {self._completed_agent_run_ids}\n\n"
            "What follow-up tasks should be dispatched? "
            "If the engagement objectives are met, set stop_condition_met to true."
        )

        response, parsed = await self._claude.complete_with_json(
            task_type="strategic_planning",
            messages=[{"role": "user", "content": prompt_content}],
            system_prompt=SYSTEM_COORDINATOR,
            max_tokens=2048,
        )

        if parsed and parsed.get("stop_condition_met"):
            reason = parsed.get("stop_reason", "Engagement objectives met.")
            logger.info("Stop condition met: %s", reason)
            return []

        tasks = self._parse_recommended_tasks(parsed)
        scope_checked = [t for t in tasks if self._is_task_in_scope(t)]
        scope_checked.sort(key=lambda t: t.priority)
        return scope_checked

    # ── Follow-up spawning ─────────────────────────────────────────────────

    async def should_spawn_followup(
        self,
        discovery: Dict[str, Any],
    ) -> List[str]:
        """
        Given a specific discovery dict, return a list of agent types to spawn.

        Uses the static _FOLLOWUP_RULES table — no LLM call needed.

        discovery schema::

            {
              "type": "web_service | new_host | credentials_found | ...",
              "host": "<IP or hostname>",
              "port": <int>,
              "details": {}
            }
        """
        discovery_type = discovery.get("type", "").lower()
        agent_types = _FOLLOWUP_RULES.get(discovery_type, [])

        # Scope-check the target before recommending agents
        host = discovery.get("host", "")
        if host and not self._scope.is_host_allowed(host):
            logger.warning(
                "should_spawn_followup: host %s is out of scope — skipping.", host
            )
            return []

        logger.info(
            "should_spawn_followup: type=%s → agents=%s", discovery_type, agent_types
        )
        return agent_types

    # ── Attack graph ───────────────────────────────────────────────────────

    async def update_attack_graph(
        self,
        node_type: str,
        node_id: str,
        label: str,
        properties: Dict[str, Any],
        confidence: float = 1.0,
    ) -> None:
        """
        Upsert a node in the attack graph.

        If a node with (engagement_id, node_id) already exists its properties
        and confidence are merged/updated. Otherwise a new row is inserted.
        """
        stmt = select(AttackGraphNode).where(
            AttackGraphNode.engagement_id == self._engagement_id,
            AttackGraphNode.node_id == node_id,
        )
        result = await self._session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            merged_props = {**existing.properties, **properties}
            existing.properties = merged_props
            existing.confidence = max(existing.confidence, confidence)
            existing.label = label
        else:
            node = AttackGraphNode(
                engagement_id=self._engagement_id,
                node_type=node_type,
                node_id=node_id,
                label=label,
                properties=properties,
                confidence=confidence,
            )
            self._session.add(node)

        await self._session.flush()
        logger.debug(
            "AttackGraph updated: type=%s id=%s label=%s", node_type, node_id, label
        )

    # ── Kill switch ────────────────────────────────────────────────────────

    async def activate_kill_switch(self, reason: str) -> None:
        """
        Halt the engagement immediately.

        Sets the in-memory flag (immediate effect) and persists to DB.
        """
        self._kill_switch_active = True

        engagement = await self._session.get(Engagement, self._engagement_id)
        if engagement:
            engagement.kill_switch_activated = True
            engagement.kill_switch_reason = reason
            engagement.status = EngagementStatus.STOPPED
            engagement.completed_at = datetime.utcnow()
            await self._session.flush()

        logger.critical(
            "Coordinator KILL SWITCH: engagement=%d reason=%s",
            self._engagement_id, reason,
        )

    # ── Internal helpers ───────────────────────────────────────────────────

    def _parse_recommended_tasks(
        self,
        parsed: Optional[Dict[str, Any]],
    ) -> List[AgentTask]:
        """Convert LLM JSON output into AgentTask objects."""
        if not parsed:
            return []

        tasks: List[AgentTask] = []
        for rec in parsed.get("recommended_tasks", []):
            try:
                task = AgentTask(
                    agent_type=str(rec["agent_type"]).lower(),
                    objective=str(rec["objective"]),
                    scope_subset=self._get_full_scope_subset(),
                    priority=int(rec.get("priority", 5)),
                    depends_on=list(rec.get("depends_on") or []),
                    metadata={"rationale": rec.get("rationale", "")},
                )
                tasks.append(task)
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("Skipping malformed task recommendation: %s — %s", rec, exc)

        return tasks

    def _is_task_in_scope(self, task: AgentTask) -> bool:
        """
        Return True if the task's scope_subset is valid within the engagement scope.

        For now, validates that any explicit hosts in the subset are allowed.
        """
        allowed_hosts = task.scope_subset.get("allowed_hosts", [])
        if not allowed_hosts:
            return True  # No explicit restriction — defer to runtime scope checks

        for host in allowed_hosts:
            if self._scope.is_host_allowed(host):
                return True

        return False

    def _get_full_scope_subset(self) -> Dict[str, Any]:
        """
        Return a scope_subset dict derived from the ScopeEnforcer's config.

        Used when we want an agent to operate on the full allowed scope.
        """
        return {
            "allowed_hosts": self._scope._allowed_hosts,
            "allowed_ports": self._scope._allowed_ports,
        }

    async def _integrate_discoveries(self, result: Dict[str, Any]) -> None:
        """
        Parse an agent result and update the TargetMap and AttackGraph.

        Handles the standard JSON schemas from recon, webapp, and auth agents.
        """
        # Recon agent: "hosts" array
        for host_data in result.get("hosts", []):
            ip = host_data.get("ip", "")
            hostname = host_data.get("hostname")
            if ip:
                self._target_map = self._target_map.add_host(ip, hostname)
                await self.update_attack_graph(
                    node_type="host",
                    node_id=ip,
                    label=hostname or ip,
                    properties={"os_guess": host_data.get("os_guess")},
                    confidence=0.8,
                )

            for svc in host_data.get("services", []):
                host_key = ip or hostname or "unknown"
                self._target_map = self._target_map.add_service(
                    host=host_key,
                    port=int(svc.get("port", 0)),
                    protocol=svc.get("protocol", "tcp"),
                    service_name=svc.get("service", "unknown"),
                    version=svc.get("version"),
                )
                svc_node_id = f"{host_key}:{svc.get('port')}"
                await self.update_attack_graph(
                    node_type="service",
                    node_id=svc_node_id,
                    label=f"{svc.get('service', 'unknown')} on {svc_node_id}",
                    properties=dict(svc),
                    confidence=0.9,
                )

        # Web endpoints from recon agent
        for ep in result.get("web_endpoints", []):
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            if url:
                self._target_map = self._target_map.add_endpoint(url, method)

        # Technology tags from recon agent
        for tech_entry in result.get("technologies", []):
            host = tech_entry.get("host", "")
            tech = tech_entry.get("name", "")
            version = tech_entry.get("version")
            if host and tech:
                self._target_map = self._target_map.add_technology(host, tech, version)

        # Findings → attack graph nodes
        for finding in result.get("findings", []):
            url = finding.get("url") or finding.get("tested_endpoint", "")
            vuln_type = finding.get("vuln_type", "unknown")
            if url:
                await self.update_attack_graph(
                    node_type="vulnerability",
                    node_id=f"vuln:{url}:{vuln_type}",
                    label=f"{vuln_type} @ {url}",
                    properties=dict(finding),
                    confidence=float(finding.get("confidence", 0.5)),
                )

    # ── Main engagement loop ───────────────────────────────────────────────

    async def run(self) -> None:
        """
        Execute the full engagement lifecycle.

        Orchestration loop:
          1. plan_strategy()       → initial AgentTask list
          2. spawn agents in parallel via AgentFactory
          3. process_agent_result() → follow-up AgentTask list
          4. Repeat until no more tasks, budget exhausted, or kill switch active

        Requires ANTHROPIC_API_KEY to be set in the environment.
        """
        from ..agents.factory import AgentFactory
        from ..coordinator.budget_manager import BudgetManager
        from ..memory.engagement_memory import EngagementMemory
        from ..memory.knowledge_base import KnowledgeBase
        from ..persistence.database import AsyncSessionLocal

        engagement = await self._session.get(Engagement, self._engagement_id)
        if engagement is None:
            logger.error("Coordinator.run: engagement %d not found", self._engagement_id)
            return

        budget_manager = BudgetManager(
            engagement_id=self._engagement_id,
            session=self._session,
            token_budget=engagement.token_budget,
            time_budget_seconds=engagement.time_budget_seconds,
            cost_budget_usd=engagement.cost_budget_usd,
        )

        engagement_memory = EngagementMemory(
            engagement_id=self._engagement_id,
            session_factory=AsyncSessionLocal,
        )
        knowledge_base = KnowledgeBase()

        factory = AgentFactory(
            engagement_id=self._engagement_id,
            session=self._session,
            claude_client=self._claude,
            scope_enforcer=self._scope,
            budget_manager=budget_manager,
            engagement_memory=engagement_memory,
            knowledge_base=knowledge_base,
        )

        MAX_ITERATIONS = 10
        iteration = 0

        try:
            pending_tasks = await self.plan_strategy()
        except Exception as exc:
            logger.exception("Coordinator.run: plan_strategy failed: %s", exc)
            return

        seen_objectives: set = set()

        while pending_tasks and iteration < MAX_ITERATIONS:
            if self._kill_switch_active:
                logger.info("Coordinator.run: kill switch active — halting engagement %d", self._engagement_id)
                break

            if not await budget_manager.can_proceed():
                logger.info("Coordinator.run: budget exhausted — halting engagement %d", self._engagement_id)
                break

            iteration += 1
            logger.info(
                "Coordinator iteration %d/%d: %d tasks for engagement=%d",
                iteration,
                MAX_ITERATIONS,
                len(pending_tasks),
                self._engagement_id,
            )

            agent_task_specs = [
                {
                    "agent_type": task.agent_type,
                    "objective": task.objective,
                    "scope_subset": task.scope_subset,
                }
                for task in pending_tasks
            ]

            try:
                results = await factory.spawn_parallel(agent_task_specs)
            except Exception as exc:
                logger.exception("Coordinator.run: spawn_parallel failed: %s", exc)
                break

            next_tasks: List[AgentTask] = []
            for result in results:
                try:
                    follow_ups = await self.process_agent_result(
                        agent_run_id=result.agent_id,
                        result={
                            "summary": (
                                f"Agent {result.agent_type} finished in {result.loop_count} loops "
                                f"with {len(result.findings)} finding(s)"
                            ),
                            "findings": result.findings,
                            "discoveries": result.discoveries,
                            "hosts": [],
                            "web_endpoints": [],
                            "technologies": [],
                        },
                    )
                    next_tasks.extend(follow_ups)
                except Exception as exc:
                    logger.warning(
                        "Coordinator.run: process_agent_result failed for agent %s: %s",
                        result.agent_id,
                        exc,
                    )

            # Deduplicate follow-up tasks by (type, objective prefix)
            unique_next: List[AgentTask] = []
            for task in next_tasks:
                key = (task.agent_type, task.objective[:60])
                if key not in seen_objectives:
                    seen_objectives.add(key)
                    unique_next.append(task)

            pending_tasks = unique_next

        logger.info(
            "Coordinator.run: engagement %d finished after %d iteration(s)",
            self._engagement_id,
            iteration,
        )

    @property
    def target_map(self) -> TargetMap:
        """Read-only access to the current TargetMap snapshot."""
        return self._target_map

    @property
    def kill_switch_active(self) -> bool:
        return self._kill_switch_active
