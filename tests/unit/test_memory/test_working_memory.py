"""
Unit tests for WorkingMemory.
"""
import pytest
from src.overwatch.memory.working_memory import WorkingMemory


class TestWorkingMemoryBasic:
    def setup_method(self):
        self.mem = WorkingMemory(agent_id="test-agent-001")

    def test_set_and_get(self):
        self.mem.set("key", "value")
        assert self.mem.get("key") == "value"

    def test_get_missing_key_returns_default(self):
        assert self.mem.get("missing") is None
        assert self.mem.get("missing", "fallback") == "fallback"

    def test_overwrite_existing_key(self):
        self.mem.set("x", 1)
        self.mem.set("x", 99)
        assert self.mem.get("x") == 99

    def test_append_to_list_creates_list(self):
        self.mem.append_to_list("findings", {"vuln": "sqli"})
        assert self.mem.get_list("findings") == [{"vuln": "sqli"}]

    def test_append_multiple_items(self):
        self.mem.append_to_list("urls", "http://a.com")
        self.mem.append_to_list("urls", "http://b.com")
        assert len(self.mem.get_list("urls")) == 2

    def test_get_list_returns_copy(self):
        self.mem.append_to_list("items", 1)
        lst = self.mem.get_list("items")
        lst.append(2)  # mutate returned list
        assert len(self.mem.get_list("items")) == 1  # original unchanged

    def test_get_list_missing_key_returns_empty(self):
        assert self.mem.get_list("nonexistent") == []

    def test_clear_removes_all(self):
        self.mem.set("a", 1)
        self.mem.set("b", 2)
        self.mem.clear()
        assert self.mem.get("a") is None
        assert self.mem.get("b") is None

    def test_snapshot_is_copy(self):
        self.mem.set("x", 42)
        snap = self.mem.snapshot()
        snap["x"] = 999
        assert self.mem.get("x") == 42  # original unchanged


class TestWorkingMemoryLimits:
    def test_item_limit_raises_on_new_key(self):
        mem = WorkingMemory(agent_id="tiny", max_items=2)
        mem.set("a", 1)
        mem.set("b", 2)
        with pytest.raises(ValueError, match="full"):
            mem.set("c", 3)

    def test_overwrite_existing_does_not_raise(self):
        mem = WorkingMemory(agent_id="tiny", max_items=1)
        mem.set("a", 1)
        mem.set("a", 2)  # should not raise
        assert mem.get("a") == 2
