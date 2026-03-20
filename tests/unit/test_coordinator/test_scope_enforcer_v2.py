"""
Unit tests for V2 ScopeEnforcer.
"""
import pytest
from src.overwatch.coordinator.scope_enforcer import (
    ScopeEnforcer,
    ScopeCheckResult,
    _hostname_matches,
    _ip_in_cidr,
)


class TestHostnameMatching:
    def test_exact_match(self):
        assert _hostname_matches("api.example.com", "api.example.com") is True

    def test_exact_mismatch(self):
        assert _hostname_matches("api.example.com", "other.example.com") is False

    def test_wildcard_one_level(self):
        assert _hostname_matches("api.example.com", "*.example.com") is True

    def test_wildcard_rejects_subdomain(self):
        # *.example.com should NOT match deep.api.example.com
        assert _hostname_matches("deep.api.example.com", "*.example.com") is False

    def test_double_wildcard_matches_deep(self):
        assert _hostname_matches("deep.api.example.com", "**.example.com") is True

    def test_case_insensitive(self):
        assert _hostname_matches("API.EXAMPLE.COM", "api.example.com") is True


class TestCidrCheck:
    def test_ip_in_range(self):
        assert _ip_in_cidr("192.168.1.50", "192.168.1.0/24") is True

    def test_ip_outside_range(self):
        assert _ip_in_cidr("10.0.0.1", "192.168.1.0/24") is False

    def test_invalid_ip(self):
        assert _ip_in_cidr("not-an-ip", "192.168.1.0/24") is False

    def test_host_boundary(self):
        assert _ip_in_cidr("192.168.1.255", "192.168.1.0/24") is True


class TestScopeEnforcerBasic:
    def setup_method(self):
        self.scope = {
            "allowed_hosts": ["dvwa.local", "*.dvwa.local", "192.168.1.0/24"],
            "allowed_ports": [80, 443, 8080],
        }
        self.enforcer = ScopeEnforcer(self.scope)

    def test_allowed_host(self):
        result = self.enforcer.is_host_allowed("dvwa.local")
        assert result is True

    def test_disallowed_host(self):
        result = self.enforcer.is_host_allowed("evil.com")
        assert result is False

    def test_wildcard_subdomain_allowed(self):
        assert self.enforcer.is_host_allowed("app.dvwa.local") is True

    def test_ip_in_allowed_cidr(self):
        assert self.enforcer.is_host_allowed("192.168.1.100") is True

    def test_ip_outside_cidr(self):
        assert self.enforcer.is_host_allowed("10.0.0.1") is False

    def test_allowed_port(self):
        assert self.enforcer.is_port_allowed(80) is True

    def test_disallowed_port(self):
        assert self.enforcer.is_port_allowed(22) is False

    def test_empty_port_list_allows_non_blocked(self):
        # Empty allowed_ports means no restriction EXCEPT always-blocked ports
        enforcer = ScopeEnforcer({"allowed_hosts": ["dvwa.local"], "allowed_ports": []})
        assert enforcer.is_port_allowed(8080) is True

    def test_url_allowed(self):
        result = self.enforcer.is_url_allowed("http://dvwa.local:80/login")
        assert result is True

    def test_url_disallowed_host(self):
        result = self.enforcer.is_url_allowed("http://evil.com/attack")
        assert result is False

    def test_url_disallowed_port(self):
        result = self.enforcer.is_url_allowed("http://dvwa.local:22/")
        assert result is False

    def test_check_action_returns_result(self):
        result = self.enforcer.check_action("http_request", "http://dvwa.local:80/login")
        assert isinstance(result, ScopeCheckResult)
        assert result.allowed is True

    def test_check_action_denied(self):
        result = self.enforcer.check_action("port_scan", "evil.com", ports=[80])
        assert result.allowed is False
        assert result.reason  # non-empty reason string


class TestScopeEnforcerEdgeCases:
    def test_no_config_blocks_all(self):
        enforcer = ScopeEnforcer({})
        assert enforcer.is_host_allowed("anything.com") is False

    def test_check_without_port(self):
        enforcer = ScopeEnforcer({"allowed_hosts": ["dvwa.local"], "allowed_ports": [80]})
        result = enforcer.check_action("host_connect", "dvwa.local")
        assert result.allowed is True
