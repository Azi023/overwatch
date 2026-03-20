"""
Central registry for all tool integrations.

Tools register themselves (or are auto-registered via create_default()).
Callers retrieve tools by name and query which ones are actually installed.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

from .base_tool import BaseTool

logger = logging.getLogger(__name__)


class ToolRegistry:
    """
    Manages discovery, registration, and retrieval of BaseTool instances.

    Usage::

        registry = ToolRegistry.create_default(scope_enforcer=enforcer)
        nmap = registry.get("nmap")
        if nmap:
            result = await nmap.execute("192.168.1.1")
    """

    def __init__(self, scope_enforcer=None) -> None:
        self._scope_enforcer = scope_enforcer
        self._tools: Dict[str, BaseTool] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, tool: BaseTool) -> None:
        """
        Add *tool* to the registry.

        If a tool with the same name is already registered it is replaced
        and a warning is emitted.
        """
        if tool.name in self._tools:
            logger.warning(
                "Tool %r is already registered — replacing with %s",
                tool.name,
                type(tool).__name__,
            )
        self._tools[tool.name] = tool
        logger.debug("Registered tool: %s", tool.name)

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get(self, name: str) -> Optional[BaseTool]:
        """Return the tool registered under *name*, or None."""
        return self._tools.get(name)

    def get_available(self) -> List[BaseTool]:
        """
        Return every registered tool whose required binary is present.

        Tools that are registered but whose binary cannot be found on PATH
        are silently excluded from the list.
        """
        return [t for t in self._tools.values() if t.is_available()]

    def get_all_names(self) -> List[str]:
        """Return the names of all registered tools (available or not)."""
        return list(self._tools.keys())

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create_default(cls, scope_enforcer=None) -> "ToolRegistry":
        """
        Build a registry pre-loaded with all built-in tool integrations.

        Tools whose binary is missing are still registered so callers can
        inspect availability via is_available().
        """
        registry = cls(scope_enforcer=scope_enforcer)

        # Discovery tools
        try:
            from .discovery.nmap_tool import NmapTool
            registry.register(NmapTool(scope_enforcer=scope_enforcer))
        except ImportError as exc:
            logger.warning("Could not load NmapTool: %s", exc)

        try:
            from .discovery.httpx_tool import HttpxTool
            registry.register(HttpxTool(scope_enforcer=scope_enforcer))
        except ImportError as exc:
            logger.warning("Could not load HttpxTool: %s", exc)

        try:
            from .discovery.nuclei_tool import NucleiTool
            registry.register(NucleiTool(scope_enforcer=scope_enforcer))
        except ImportError as exc:
            logger.warning("Could not load NucleiTool: %s", exc)

        available = [t.name for t in registry.get_available()]
        all_names = registry.get_all_names()
        logger.info(
            "ToolRegistry initialised — %d registered, %d available: %s",
            len(all_names),
            len(available),
            available,
        )

        return registry
