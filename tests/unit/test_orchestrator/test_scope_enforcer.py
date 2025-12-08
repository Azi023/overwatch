"""
Unit tests for scope enforcer.
"""
import pytest
from src.overwatch_core.orchestrator.scope_enforcer import ScopeEnforcer
from src.overwatch_core.persistence.models import Target


def test_scope_enforcer_exact_match():
    """Test scope enforcer with exact hostname match."""
    target = Target(
        name="Test",
        allowed_hosts=["example.com", "192.168.1.1"]
    )
    enforcer = ScopeEnforcer(target)

    assert enforcer.is_in_scope("http://example.com")
    assert enforcer.is_in_scope("192.168.1.1")
    assert not enforcer.is_in_scope("http://evil.com")


def test_scope_enforcer_wildcard():
    """Test scope enforcer with wildcard domains."""
    target = Target(
        name="Test",
        allowed_hosts=["*.example.com"]
    )
    enforcer = ScopeEnforcer(target)

    assert enforcer.is_in_scope("http://api.example.com")
    assert enforcer.is_in_scope("http://www.example.com")
    assert not enforcer.is_in_scope("http://example.com")  # Wildcard doesn't match root


def test_scope_enforcer_cidr():
    """Test scope enforcer with CIDR notation."""
    target = Target(
        name="Test",
        allowed_hosts=["192.168.1.0/24"]
    )
    enforcer = ScopeEnforcer(target)

    assert enforcer.is_in_scope("192.168.1.50")
    assert enforcer.is_in_scope("192.168.1.1")
    assert not enforcer.is_in_scope("10.0.0.1")


def test_scope_enforcer_ports():
    """Test scope enforcer with port restrictions."""
    target = Target(
        name="Test",
        allowed_hosts=["example.com"],
        allowed_ports=[80, 443]
    )
    enforcer = ScopeEnforcer(target)

    assert enforcer.is_in_scope("http://example.com:80")
    assert enforcer.is_in_scope("https://example.com:443")
    assert not enforcer.is_in_scope("http://example.com:8080")
