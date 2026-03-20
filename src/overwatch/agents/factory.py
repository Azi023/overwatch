"""
AgentFactory - spawning and lifecycle management for Overwatch agents.

The factory maps agent type strings to concrete agent classes, injects all
required dependencies, and supports parallel multi-agent execution.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Type

from .base_agent import AgentResult, BaseAgent
from .types.recon_agent import ReconAgent
from .types.triage_agent import TriageAgent

logger = logging.getLogger(__name__)

# Registry mapping type name → concrete class.
# Add new agent types here as they are implemented.
_AGENT_REGISTRY: Dict[str, Type[BaseAgent]] = {
    "recon": ReconAgent,
    "triage": TriageAgent,
}


class AgentFactory:
    """
    Factory for creating and managing agent instances.

    All agents spawned by this factory share the same engagement context
    (session, claude_client, scope_enforcer, engagement_memory, knowledge_base).
    Per-agent state (working_memory, findings) is isolated.
    """

    def __init__(
        self,
        engagement_id: int,
        session: Any,
        claude_client: Any,
        scope_enforcer: Any,
        budget_manager: Any,
        engagement_memory: Any,
        knowledge_base: Any,
        tool_registry: Optional[Any] = None,
    ) -> None:
        self._engagement_id = engagement_id
        self._session = session
        self._claude_client = claude_client
        self._scope_enforcer = scope_enforcer
        self._budget_manager = budget_manager
        self._engagement_memory = engagement_memory
        self._knowledge_base = knowledge_base
        self._tool_registry = tool_registry
        self._spawned_agents: List[str] = []

    # ─────────────────────── Public API ──────────────────────────

    async def spawn_agent(
        self,
        agent_type: str,
        objective: str,
        scope_subset: Optional[dict] = None,
    ) -> BaseAgent:
        """
        Instantiate and return an agent of the specified type.

        The agent is configured with all shared dependencies but has its own
        isolated working_memory and findings list. The agent has NOT been
        started (run() has not been called).

        Raises ValueError for unknown agent_type strings.
        """
        agent_class = _AGENT_REGISTRY.get(agent_type.lower())
        if agent_class is None:
            available = ", ".join(sorted(_AGENT_REGISTRY.keys()))
            raise ValueError(
                f"Unknown agent type '{agent_type}'. "
                f"Available types: {available}"
            )

        tools = self._resolve_tools(agent_type)

        agent = agent_class(
            agent_type=agent_type,
            objective=objective,
            scope_subset=scope_subset,
            engagement_id=self._engagement_id,
            session=self._session,
            claude_client=self._claude_client,
            scope_enforcer=self._scope_enforcer,
            budget_manager=self._budget_manager,
            engagement_memory=self._engagement_memory,
            knowledge_base=self._knowledge_base,
            tools=tools,
        )

        self._spawned_agents.append(agent.agent_id)
        logger.info(
            "AgentFactory: spawned %s agent id=%s objective='%s'",
            agent_type,
            agent.agent_id,
            objective[:80],
        )
        return agent

    async def spawn_parallel(
        self, agent_tasks: List[dict]
    ) -> List[AgentResult]:
        """
        Spawn multiple agents and run them concurrently.

        Each element of agent_tasks must be a dict with keys:
            - agent_type (str): the type of agent to spawn
            - objective (str): the agent's objective
            - scope_subset (dict, optional): scope restriction

        Returns a list of AgentResult objects in the same order as agent_tasks.
        Exceptions from individual agents are caught and represented as a
        failed AgentResult so one failure doesn't abort the others.
        """
        if not agent_tasks:
            return []

        logger.info(
            "AgentFactory: spawning %d agents in parallel for engagement %d",
            len(agent_tasks),
            self._engagement_id,
        )

        coroutines = []
        for task_spec in agent_tasks:
            agent_type = task_spec["agent_type"]
            objective = task_spec["objective"]
            scope_subset = task_spec.get("scope_subset")
            coroutines.append(
                self._spawn_and_run(agent_type, objective, scope_subset)
            )

        results: List[AgentResult] = await asyncio.gather(
            *coroutines, return_exceptions=False
        )
        return results

    def get_available_agent_types(self) -> List[str]:
        """Return the sorted list of registered agent type strings."""
        return sorted(_AGENT_REGISTRY.keys())

    @property
    def spawned_agent_ids(self) -> List[str]:
        """Return all agent IDs spawned by this factory in this session."""
        return list(self._spawned_agents)

    # ─────────────────────── Private Helpers ─────────────────────

    async def _spawn_and_run(
        self,
        agent_type: str,
        objective: str,
        scope_subset: Optional[dict],
    ) -> AgentResult:
        """Spawn an agent and immediately execute its run loop."""
        try:
            agent = await self.spawn_agent(agent_type, objective, scope_subset)
            return await agent.run()
        except Exception as exc:
            logger.exception(
                "AgentFactory: agent type='%s' objective='%s' raised: %s",
                agent_type,
                objective[:80],
                exc,
            )
            return AgentResult(
                agent_id="unknown",
                agent_type=agent_type,
                objective=objective,
                status="failed",
                findings=[],
                discoveries=[],
            )

    def _resolve_tools(self, agent_type: str) -> Dict[str, Any]:
        """
        Build the tool dict for the given agent type.

        If a tool_registry is available, queries it for each tool the agent
        type requires. Falls back to an empty dict if the registry is absent.
        """
        if self._tool_registry is None:
            return {}

        # Tool requirements per agent type
        required_tools: Dict[str, List[str]] = {
            "recon": ["nmap", "subfinder", "httpx"],
            "triage": ["httpx"],
        }

        needed = required_tools.get(agent_type.lower(), [])
        tools: Dict[str, Any] = {}
        for tool_name in needed:
            try:
                tool = self._tool_registry.get_tool(tool_name)
                if tool is not None:
                    tools[tool_name] = tool
            except Exception as exc:
                logger.warning(
                    "AgentFactory: could not resolve tool '%s' for agent type '%s': %s",
                    tool_name,
                    agent_type,
                    exc,
                )
        return tools
