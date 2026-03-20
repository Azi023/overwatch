"""
WorkingMemory - ephemeral per-agent in-memory store.

Each agent gets its own WorkingMemory instance that lives only for the duration
of the agent's run. Data is not persisted to the database.
"""
import asyncio
import copy
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class WorkingMemory:
    """
    Thread-safe ephemeral in-memory store for a single agent's working state.

    Stores arbitrary key-value pairs and list accumulators. All state is lost
    when the agent completes. Use EngagementMemory for data that must survive.
    """

    def __init__(self, agent_id: str, max_items: int = 1000) -> None:
        self._agent_id = agent_id
        self._max_items = max_items
        self._store: Dict[str, Any] = {}
        self._lock = asyncio.Lock()

    # ──────────────────────── Public API ────────────────────────

    def set(self, key: str, value: Any) -> None:
        """
        Store a value under the given key.

        Raises ValueError if the item limit has been reached and the key is new.
        """
        if key not in self._store and len(self._store) >= self._max_items:
            raise ValueError(
                f"WorkingMemory for agent {self._agent_id} is full "
                f"({self._max_items} items). Cannot store key '{key}'."
            )
        self._store[key] = value
        logger.debug("WorkingMemory[%s] set '%s'", self._agent_id, key)

    def get(self, key: str, default: Any = None) -> Any:
        """Return the value for key, or default if key is absent."""
        return self._store.get(key, default)

    def append_to_list(self, key: str, item: Any) -> None:
        """
        Append item to the list stored at key.

        Creates the list if key does not yet exist.
        Raises ValueError if the total item count would exceed max_items.
        """
        if key not in self._store:
            if len(self._store) >= self._max_items:
                raise ValueError(
                    f"WorkingMemory for agent {self._agent_id} is full. "
                    f"Cannot create list key '{key}'."
                )
            self._store[key] = []

        existing = self._store[key]
        if not isinstance(existing, list):
            raise TypeError(
                f"Key '{key}' already holds a non-list value "
                f"({type(existing).__name__}). Cannot append."
            )
        self._store[key] = existing + [item]  # immutable pattern: new list each time

    def get_list(self, key: str) -> List[Any]:
        """Return the list stored at key, or an empty list if absent."""
        value = self._store.get(key, [])
        if not isinstance(value, list):
            raise TypeError(
                f"Key '{key}' holds a non-list value ({type(value).__name__})."
            )
        return list(value)  # return a copy to prevent external mutation

    def clear(self) -> None:
        """Remove all entries from this working memory instance."""
        self._store = {}
        logger.debug("WorkingMemory[%s] cleared", self._agent_id)

    def snapshot(self) -> Dict[str, Any]:
        """
        Return a deep copy of all stored data.

        The caller receives an independent copy; mutations do not affect the store.
        """
        return copy.deepcopy(self._store)

    # ──────────────────────── Properties ────────────────────────

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def item_count(self) -> int:
        return len(self._store)

    def __contains__(self, key: str) -> bool:
        return key in self._store

    def __repr__(self) -> str:
        return (
            f"WorkingMemory(agent_id={self._agent_id!r}, "
            f"items={len(self._store)}/{self._max_items})"
        )
