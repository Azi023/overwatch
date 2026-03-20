"""
Unit tests for Overwatch V2 persistence models.
"""
import pytest
from datetime import datetime
from src.overwatch.persistence.models import (
    Target, ScanJob, Finding, AIDecision, ObservationModel,
    FeedbackModel, Engagement, AgentRun, AttackGraphNode,
    Credential, Memory, ToolProficiencyScore, AIUsageLog,
    ScanStatus, SeverityLevel, EngagementStatus, AgentStatus,
)


class TestEnums:
    def test_scan_status_values(self):
        assert ScanStatus.PENDING == "pending"
        assert ScanStatus.RUNNING == "running"
        assert ScanStatus.COMPLETED == "completed"
        assert ScanStatus.FAILED == "failed"

    def test_severity_level_values(self):
        assert SeverityLevel.CRITICAL == "critical"
        assert SeverityLevel.HIGH == "high"
        assert SeverityLevel.MEDIUM == "medium"
        assert SeverityLevel.LOW == "low"
        assert SeverityLevel.INFO == "info"

    def test_engagement_status_values(self):
        assert EngagementStatus.CREATED == "created"
        assert EngagementStatus.RUNNING == "running"
        assert EngagementStatus.STOPPED == "stopped"

    def test_agent_status_values(self):
        assert AgentStatus.SPAWNED == "spawned"
        assert AgentStatus.RUNNING == "running"
        assert AgentStatus.COMPLETED == "completed"
        assert AgentStatus.KILLED == "killed"


class TestTargetModel:
    def test_creation(self):
        t = Target(
            name="DVWA",
            url="http://dvwa.local",
            ip_address="192.168.1.100",
            scope_rules={},
            allowed_hosts=["dvwa.local", "192.168.1.100"],
            allowed_ports=[80, 443, 8080],
        )
        assert t.name == "DVWA"
        assert 80 in t.allowed_ports
        assert "dvwa.local" in t.allowed_hosts

    def test_minimal_creation(self):
        t = Target(name="Minimal Target")
        assert t.name == "Minimal Target"
        assert t.url is None
        assert t.ip_address is None


class TestEngagementModel:
    def test_creation(self):
        e = Engagement(
            target_id=1,
            name="DVWA Engagement",
            status=EngagementStatus.CREATED,
            objectives=["Find SQLi", "Find XSS"],
            scope_config={"max_depth": 3},
            token_budget=50000,
            cost_budget_usd=5.0,
        )
        assert e.name == "DVWA Engagement"
        assert e.objectives == ["Find SQLi", "Find XSS"]
        assert e.kill_switch_activated is False
        assert e.tokens_used == 0
        assert e.cost_usd == 0.0


class TestFindingModel:
    def test_creation_with_all_fields(self):
        f = Finding(
            vulnerability_type="SQL Injection",
            title="SQLi in login form",
            description="Error-based SQLi detected",
            url="http://example.com/login",
            parameter="username",
            severity=SeverityLevel.HIGH,
            confidence=0.92,
            validated=True,
            false_positive=False,
            evidence={"payload": "' OR 1=1--", "response_code": 500},
            tool_name="webapp_agent",
            agent_type="webapp",
            cvss_score=8.8,
            mitre_techniques=["T1190"],
        )
        assert f.confidence == 0.92
        assert f.evidence["payload"] == "' OR 1=1--"
        assert f.mitre_techniques == ["T1190"]
        assert f.tool_name == "webapp_agent"

    def test_defaults(self):
        f = Finding(
            vulnerability_type="XSS",
            title="XSS",
            description="desc",
            severity=SeverityLevel.MEDIUM,
            confidence=0.7,
        )
        assert f.validated is False
        assert f.false_positive is False
        assert f.cve_ids == []
        assert f.cwe_ids == []


class TestAgentRunModel:
    def test_creation(self):
        run = AgentRun(
            engagement_id=1,
            agent_type="recon",
            agent_id="abc-123",
            objective="Map attack surface of 192.168.1.0/24",
            status=AgentStatus.SPAWNED,
            spawned_at=datetime.utcnow(),
        )
        assert run.agent_type == "recon"
        assert run.loop_iterations == 0
        assert run.tokens_used == 0
        assert run.cost_usd == 0.0


class TestAIUsageLog:
    def test_creation(self):
        log = AIUsageLog(
            model="claude-haiku-4-5-20251001",
            task_type="log_parsing",
            input_tokens=800,
            output_tokens=200,
            cost=0.00088,
        )
        assert log.model == "claude-haiku-4-5-20251001"
        assert log.input_tokens == 800
        assert log.cost == 0.00088


class TestMemoryModel:
    def test_creation(self):
        m = Memory(
            memory_type="vulnerability_pattern",
            title="PHP MySQL error-based SQLi",
            content="Error pattern: You have an error in your SQL syntax",
            tech_stack=["php", "mysql"],
            vuln_types=["sqli"],
        )
        assert m.tech_stack == ["php", "mysql"]
        assert m.times_recalled == 0
        assert m.success_rate == 0.0


class TestToolProficiency:
    def test_creation(self):
        s = ToolProficiencyScore(
            agent_type="webapp",
            tool_name="sqlmap",
            vuln_type="sqli",
            total_attempts=20,
            successful_findings=15,
            false_positives=2,
            proficiency_score=0.78,
        )
        assert s.proficiency_score == 0.78
        assert s.successful_findings == 15
