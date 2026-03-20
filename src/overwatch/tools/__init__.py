"""
Overwatch tool layer.

Exposes BaseTool, ToolResult, and ToolRegistry as the primary public API.
Individual tool implementations live in the discovery/, exploitation/, and
detection/ sub-packages.
"""
from .base_tool import BaseTool, ToolResult
from .tool_registry import ToolRegistry

__all__ = ["BaseTool", "ToolResult", "ToolRegistry"]
