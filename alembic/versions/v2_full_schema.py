"""V2 full schema — Overwatch V2 complete models

Revision ID: v2_full_schema
Revises:
Create Date: 2026-03-20

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

# revision identifiers
revision = "v2_full_schema"
down_revision = None  # Start fresh
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── targets ──────────────────────────────────────────────
    op.create_table(
        "targets",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("url", sa.String(512), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("scope_rules", JSON, nullable=True),
        sa.Column("allowed_hosts", JSON, nullable=True),
        sa.Column("allowed_ports", JSON, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )

    # ── engagements ───────────────────────────────────────────
    op.create_table(
        "engagements",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="created"),
        sa.Column("objectives", JSON, nullable=True),
        sa.Column("scope_config", JSON, nullable=True),
        sa.Column("token_budget", sa.Integer, nullable=True),
        sa.Column("time_budget_seconds", sa.Integer, nullable=True),
        sa.Column("cost_budget_usd", sa.Float, nullable=True),
        sa.Column("tokens_used", sa.Integer, nullable=False, server_default="0"),
        sa.Column("cost_usd", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("kill_switch_activated", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("kill_switch_reason", sa.Text, nullable=True),
    )

    # ── scan_jobs ─────────────────────────────────────────────
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("engagement_id", sa.Integer, sa.ForeignKey("engagements.id"), nullable=True),
        sa.Column("scan_type", sa.String(100), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("raw_output_path", sa.String(512), nullable=True),
        sa.Column("summary", JSON, nullable=True),
    )

    # ── findings ──────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("scan_job_id", sa.Integer, sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("engagement_id", sa.Integer, sa.ForeignKey("engagements.id"), nullable=True),
        sa.Column("vulnerability_type", sa.String(255), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("url", sa.String(512), nullable=True),
        sa.Column("parameter", sa.String(255), nullable=True),
        sa.Column("severity", sa.String(50), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("validated", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("false_positive", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("validation_result", sa.String(50), nullable=True),
        sa.Column("proof_of_concept", sa.Text, nullable=True),
        sa.Column("screenshot_path", sa.String(512), nullable=True),
        sa.Column("evidence", JSON, nullable=True),
        sa.Column("remediation_advice", sa.Text, nullable=True),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("cvss_vector", sa.String(255), nullable=True),
        sa.Column("cve_ids", JSON, nullable=True),
        sa.Column("cwe_ids", JSON, nullable=True),
        sa.Column("mitre_techniques", JSON, nullable=True),
        sa.Column("tool_name", sa.String(100), nullable=True),
        sa.Column("agent_type", sa.String(100), nullable=True),
        sa.Column("observation_id", sa.String(16), nullable=True),
        sa.Column("discovered_at", sa.DateTime, nullable=False),
    )

    # ── ai_decisions ──────────────────────────────────────────
    op.create_table(
        "ai_decisions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("scan_job_id", sa.Integer, sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("decision_type", sa.String(100), nullable=False),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("reasoning", sa.Text, nullable=False),
        sa.Column("parameters", JSON, nullable=True),
        sa.Column("outcome", JSON, nullable=True),
        sa.Column("success", sa.Boolean, nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("risk_level", sa.String(50), nullable=True),
        sa.Column("action_category", sa.String(50), nullable=True),
        sa.Column("required_approval", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("approved", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("timestamp", sa.DateTime, nullable=False),
        sa.Column("agent_model", sa.String(100), nullable=False),
    )

    # ── observations ──────────────────────────────────────────
    op.create_table(
        "observations",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("observation_type", sa.String(50), nullable=False, index=True),
        sa.Column("timestamp", sa.DateTime, nullable=False),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scan_job_id", sa.Integer, sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("raw_data", JSON, nullable=False),
        sa.Column("features", JSON, nullable=True),
        sa.Column("context_ids", JSON, nullable=True),
        sa.Column("predictions", JSON, nullable=True),
        sa.Column("ground_truth", JSON, nullable=True),
        sa.Column("ground_truth_source", sa.String(50), nullable=True),
        sa.Column("ground_truth_timestamp", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    # ── feedback ──────────────────────────────────────────────
    op.create_table(
        "feedback",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("observation_id", sa.String(16), sa.ForeignKey("observations.id", ondelete="CASCADE"), nullable=True, index=True),
        sa.Column("finding_id", sa.Integer, sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True),
        sa.Column("feedback_type", sa.String(50), nullable=False, index=True),
        sa.Column("feedback_value", JSON, nullable=False),
        sa.Column("source", sa.String(50), nullable=False, server_default="api"),
        sa.Column("user_id", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    # ── agent_runs ────────────────────────────────────────────
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("engagement_id", sa.Integer, sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("agent_type", sa.String(100), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("objective", sa.Text, nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="spawned"),
        sa.Column("loop_iterations", sa.Integer, nullable=False, server_default="0"),
        sa.Column("hypotheses_tested", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("tokens_used", sa.Integer, nullable=False, server_default="0"),
        sa.Column("cost_usd", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("system_prompt_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("current_system_prompt", sa.Text, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("spawned_at", sa.DateTime, nullable=False),
        sa.Column("completed_at", sa.DateTime, nullable=True),
    )

    # ── attack_graph_nodes ────────────────────────────────────
    op.create_table(
        "attack_graph_nodes",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("engagement_id", sa.Integer, sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("node_type", sa.String(50), nullable=False),
        sa.Column("node_id", sa.String(255), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("properties", JSON, nullable=True),
        sa.Column("confidence", sa.Float, nullable=False, server_default="1.0"),
        sa.Column("discovered_at", sa.DateTime, nullable=False),
        sa.Column("discovered_by", sa.String(100), nullable=True),
    )

    # ── attack_graph_edges ────────────────────────────────────
    op.create_table(
        "attack_graph_edges",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("source_node_id", sa.Integer, sa.ForeignKey("attack_graph_nodes.id"), nullable=False),
        sa.Column("target_node_id", sa.Integer, sa.ForeignKey("attack_graph_nodes.id"), nullable=False),
        sa.Column("edge_type", sa.String(50), nullable=False),
        sa.Column("properties", JSON, nullable=True),
        sa.Column("confidence", sa.Float, nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    # ── credentials ───────────────────────────────────────────
    op.create_table(
        "credentials",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("engagement_id", sa.Integer, sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("credential_type", sa.String(50), nullable=False),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("service", sa.String(255), nullable=True),
        sa.Column("scope", sa.String(255), nullable=False, server_default="engagement"),
        sa.Column("encrypted_value", sa.Text, nullable=False),
        sa.Column("discovered_at", sa.DateTime, nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column("is_valid", sa.Boolean, nullable=False, server_default="true"),
    )

    # ── memories ──────────────────────────────────────────────
    op.create_table(
        "memories",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("memory_type", sa.String(50), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("metadata", JSON, nullable=True),
        sa.Column("tech_stack", JSON, nullable=True),
        sa.Column("vuln_types", JSON, nullable=True),
        sa.Column("times_recalled", sa.Integer, nullable=False, server_default="0"),
        sa.Column("times_useful", sa.Integer, nullable=False, server_default="0"),
        sa.Column("success_rate", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("embedding", JSON, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
        sa.Column("source_engagement_id", sa.Integer, sa.ForeignKey("engagements.id"), nullable=True),
    )

    # ── tool_proficiency_scores ───────────────────────────────
    op.create_table(
        "tool_proficiency_scores",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("agent_type", sa.String(100), nullable=False),
        sa.Column("tool_name", sa.String(100), nullable=False),
        sa.Column("vuln_type", sa.String(100), nullable=True),
        sa.Column("total_attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("successful_findings", sa.Integer, nullable=False, server_default="0"),
        sa.Column("false_positives", sa.Integer, nullable=False, server_default="0"),
        sa.Column("proficiency_score", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )

    # ── ai_usage_logs ─────────────────────────────────────────
    op.create_table(
        "ai_usage_logs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("engagement_id", sa.Integer, sa.ForeignKey("engagements.id"), nullable=True),
        sa.Column("agent_run_id", sa.Integer, sa.ForeignKey("agent_runs.id"), nullable=True),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("task_type", sa.String(100), nullable=False),
        sa.Column("input_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("cached_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("cost", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("timestamp", sa.DateTime, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("ai_usage_logs")
    op.drop_table("tool_proficiency_scores")
    op.drop_table("memories")
    op.drop_table("credentials")
    op.drop_table("attack_graph_edges")
    op.drop_table("attack_graph_nodes")
    op.drop_table("agent_runs")
    op.drop_table("feedback")
    op.drop_table("observations")
    op.drop_table("ai_decisions")
    op.drop_table("findings")
    op.drop_table("scan_jobs")
    op.drop_table("engagements")
    op.drop_table("targets")
