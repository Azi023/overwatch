"""
Report generation engine for Overwatch V2.

Produces structured JSON reports and Markdown executive summaries from
engagement data stored in the database. Uses Jinja2 for Markdown templates
and optionally invokes the Claude API for narrative summaries.
"""
from __future__ import annotations

import logging
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import AgentRun, Engagement, Finding, ScanJob, Target
from .cvss_scorer import CVSSScorer
from .mitre_mapper import MITREMapper

logger = logging.getLogger(__name__)

_DEFAULT_TEMPLATE_DIR = Path(__file__).parent / "templates"


# ──────────────────────────── Helpers ────────────────────────────

def _severity_order(severity: str) -> int:
    """Lower number = more severe, for stable sort."""
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        severity.lower(), 5
    )


def _finding_to_dict(finding: Finding, mapper: MITREMapper) -> Dict[str, Any]:
    """Serialise a Finding ORM object to a plain dict for report output."""
    finding_dict = {
        "vulnerability_type": finding.vulnerability_type,
        "cwe_ids": finding.cwe_ids or [],
        "mitre_techniques": finding.mitre_techniques or [],
    }
    techniques = mapper.map_finding(finding_dict)

    return {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "vulnerability_type": finding.vulnerability_type,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "confidence": finding.confidence,
        "validated": finding.validated,
        "false_positive": finding.false_positive,
        "url": finding.url,
        "parameter": finding.parameter,
        "proof_of_concept": finding.proof_of_concept,
        "remediation_advice": finding.remediation_advice,
        "cve_ids": finding.cve_ids or [],
        "cwe_ids": finding.cwe_ids or [],
        "mitre_techniques": techniques,
        "tool_name": finding.tool_name,
        "agent_type": finding.agent_type,
        "discovered_at": finding.discovered_at.isoformat() if finding.discovered_at else None,
    }


# ──────────────────────────── Engine ────────────────────────────

class ReportEngine:
    """
    Generate pentest reports from engagement data.

    Usage::

        engine = ReportEngine(
            session_factory=AsyncSessionLocal,
            claude_client=client,         # optional
        )
        report = await engine.generate_report(engagement_id=3)
        markdown = await engine.generate_markdown_report(engagement_id=3)
    """

    def __init__(
        self,
        session_factory: Callable[..., Any],
        claude_client: Optional[Any] = None,
        template_dir: Optional[str] = None,
    ) -> None:
        self._session_factory = session_factory
        self._claude_client = claude_client
        self._template_dir = Path(template_dir) if template_dir else _DEFAULT_TEMPLATE_DIR
        self._cvss = CVSSScorer()
        self._mitre = MITREMapper()

    # ── Public API ────────────────────────────────────────────────

    async def generate_report(
        self, engagement_id: int, format: str = "json"
    ) -> Dict[str, Any]:
        """
        Generate a full structured report for the engagement.

        Args:
            engagement_id: Database ID of the engagement.
            format:        Currently always ``"json"``; reserved for future formats.

        Returns:
            Report dict suitable for JSON serialisation.

        Raises:
            ValueError: If the engagement does not exist.
        """
        async with self._session_factory() as session:
            engagement, target, findings, agent_runs = await self._load_data(
                session, engagement_id
            )

        finding_dicts = [_finding_to_dict(f, self._mitre) for f in findings]

        # Sort: false-positives last, then by severity
        finding_dicts.sort(
            key=lambda f: (
                int(f["false_positive"]),
                _severity_order(f["severity"]),
            )
        )

        stats = self._compute_statistics(findings, agent_runs, engagement)
        executive_summary = await self._build_executive_summary(
            engagement, target, stats
        )

        return {
            "report_version": "2.0",
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "engagement": {
                "id": engagement.id,
                "name": engagement.name,
                "description": engagement.description,
                "status": engagement.status.value if hasattr(engagement.status, "value") else engagement.status,
                "started_at": engagement.started_at.isoformat() if engagement.started_at else None,
                "completed_at": engagement.completed_at.isoformat() if engagement.completed_at else None,
                "tokens_used": engagement.tokens_used,
                "cost_usd": engagement.cost_usd,
            },
            "target": {
                "id": target.id,
                "name": target.name,
                "url": target.url,
                "ip_address": target.ip_address,
                "scope_rules": target.scope_rules,
                "allowed_hosts": target.allowed_hosts,
            },
            "statistics": stats,
            "executive_summary": executive_summary,
            "findings": finding_dicts,
            "agent_runs": [
                {
                    "agent_id": r.agent_id,
                    "agent_type": r.agent_type,
                    "objective": r.objective,
                    "status": r.status.value if hasattr(r.status, "value") else r.status,
                    "findings_count": r.findings_count,
                    "tokens_used": r.tokens_used,
                    "cost_usd": r.cost_usd,
                    "loop_iterations": r.loop_iterations,
                    "spawned_at": r.spawned_at.isoformat() if r.spawned_at else None,
                    "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                }
                for r in agent_runs
            ],
        }

    async def generate_markdown_report(self, engagement_id: int) -> str:
        """
        Generate a Markdown-formatted report.

        Uses a Jinja2 template if available; falls back to a programmatic
        Markdown builder.
        """
        report = await self.generate_report(engagement_id)

        template = self._load_template("report.md.j2")
        if template is not None:
            try:
                return template.render(report=report)
            except Exception as exc:
                logger.warning("Jinja2 template rendering failed: %s — using fallback", exc)

        return self._render_markdown_fallback(report)

    # ── Private helpers ───────────────────────────────────────────

    @staticmethod
    async def _load_data(
        session: AsyncSession, engagement_id: int
    ):
        """Load all entities needed for report generation."""
        engagement = await session.get(Engagement, engagement_id)
        if engagement is None:
            raise ValueError(f"Engagement {engagement_id} not found")

        target = await session.get(Target, engagement.target_id)
        if target is None:
            raise ValueError(f"Target {engagement.target_id} not found")

        findings_result = await session.execute(
            select(Finding).where(Finding.engagement_id == engagement_id)
        )
        findings: List[Finding] = list(findings_result.scalars().all())

        agents_result = await session.execute(
            select(AgentRun).where(AgentRun.engagement_id == engagement_id)
        )
        agent_runs: List[AgentRun] = list(agents_result.scalars().all())

        return engagement, target, findings, agent_runs

    def _compute_statistics(
        self,
        findings: List[Finding],
        agent_runs: List[AgentRun],
        engagement: Engagement,
    ) -> Dict[str, Any]:
        """Compute summary statistics from raw data."""
        total = len(findings)
        non_fp = [f for f in findings if not f.false_positive]
        validated = [f for f in non_fp if f.validated]
        false_positives = [f for f in findings if f.false_positive]

        severity_counts: Dict[str, int] = Counter()
        for f in non_fp:
            sev = f.severity.value if hasattr(f.severity, "value") else f.severity
            severity_counts[sev] += 1

        cvss_scores = [f.cvss_score for f in findings if f.cvss_score is not None]
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else None
        max_cvss = max(cvss_scores) if cvss_scores else None

        all_techniques: List[str] = []
        for f in findings:
            all_techniques.extend(f.mitre_techniques or [])
        technique_counts = Counter(all_techniques)

        return {
            "total_findings": total,
            "confirmed_findings": len(validated),
            "false_positives": len(false_positives),
            "findings_by_severity": dict(severity_counts),
            "average_cvss": avg_cvss,
            "max_cvss": max_cvss,
            "total_agents_spawned": len(agent_runs),
            "total_tokens_used": engagement.tokens_used,
            "total_cost_usd": round(engagement.cost_usd, 4),
            "top_mitre_techniques": technique_counts.most_common(10),
        }

    async def _build_executive_summary(
        self,
        engagement: Engagement,
        target: Target,
        stats: Dict[str, Any],
    ) -> str:
        """Build the executive summary using Claude if available, else a template."""
        if self._claude_client is not None:
            try:
                return await self._llm_executive_summary(engagement, target, stats)
            except Exception as exc:
                logger.warning("LLM executive summary failed: %s — using template", exc)

        return self._template_executive_summary(engagement, target, stats)

    async def _llm_executive_summary(
        self,
        engagement: Engagement,
        target: Target,
        stats: Dict[str, Any],
    ) -> str:
        """Generate executive summary via Claude API."""
        sev = stats.get("findings_by_severity", {})
        prompt = (
            f"You are a professional penetration tester writing an executive summary.\n\n"
            f"Engagement: {engagement.name}\n"
            f"Target: {target.name} ({target.url or target.ip_address})\n"
            f"Total findings: {stats['total_findings']} "
            f"(Critical: {sev.get('critical', 0)}, High: {sev.get('high', 0)}, "
            f"Medium: {sev.get('medium', 0)}, Low: {sev.get('low', 0)})\n"
            f"False positive rate: "
            f"{round(stats['false_positives'] / max(stats['total_findings'], 1) * 100, 1)}%\n"
            f"Total cost: ${stats['total_cost_usd']}\n\n"
            "Write a concise 3-4 paragraph executive summary suitable for senior management. "
            "Include overall risk posture, key findings, and top recommendations."
        )
        response = await self._claude_client.complete(
            task_type="analysis",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800,
        )
        return response.content

    @staticmethod
    def _template_executive_summary(
        engagement: Engagement,
        target: Target,
        stats: Dict[str, Any],
    ) -> str:
        """Programmatic executive summary when LLM is unavailable."""
        sev = stats.get("findings_by_severity", {})
        critical = sev.get("critical", 0)
        high = sev.get("high", 0)
        total = stats["total_findings"]
        confirmed = stats["confirmed_findings"]

        risk_level = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM" if total > 0 else "LOW"

        lines = [
            f"## Executive Summary",
            f"",
            f"A penetration test was conducted against **{target.name}** "
            f"({target.url or target.ip_address or 'N/A'}) as part of engagement "
            f"**{engagement.name}**.",
            f"",
            f"**Overall Risk: {risk_level}**",
            f"",
            f"The assessment identified {total} potential findings, of which "
            f"{confirmed} were validated. Severity breakdown:",
            f"",
        ]
        for sev_label in ("critical", "high", "medium", "low", "info"):
            count = sev.get(sev_label, 0)
            if count:
                lines.append(f"- **{sev_label.capitalize()}**: {count}")

        lines += [
            f"",
            f"**Cost:** ${stats['total_cost_usd']} | "
            f"**Tokens used:** {stats['total_tokens_used']:,}",
        ]
        return "\n".join(lines)

    def _load_template(self, template_name: str) -> Optional[Any]:
        """Load a Jinja2 template; return None if Jinja2 is not installed."""
        template_path = self._template_dir / template_name
        if not template_path.exists():
            return None
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
            env = Environment(
                loader=FileSystemLoader(str(self._template_dir)),
                autoescape=select_autoescape(["html", "xml"]),
                trim_blocks=True,
                lstrip_blocks=True,
            )
            return env.get_template(template_name)
        except ImportError:
            logger.debug("Jinja2 not installed; skipping template rendering")
            return None

    @staticmethod
    def _render_markdown_fallback(report: Dict[str, Any]) -> str:
        """Fallback Markdown renderer when Jinja2 template is unavailable."""
        lines: List[str] = [
            f"# Penetration Test Report",
            f"",
            f"**Engagement:** {report['engagement']['name']}",
            f"**Target:** {report['target']['name']} ({report['target'].get('url') or report['target'].get('ip_address') or 'N/A'})",
            f"**Generated:** {report['generated_at']}",
            f"**Status:** {report['engagement']['status']}",
            f"",
            report.get("executive_summary", ""),
            f"",
            f"---",
            f"",
            f"## Statistics",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
        ]
        stats = report.get("statistics", {})
        lines += [
            f"| Total Findings | {stats.get('total_findings', 0)} |",
            f"| Confirmed | {stats.get('confirmed_findings', 0)} |",
            f"| False Positives | {stats.get('false_positives', 0)} |",
            f"| Agents Spawned | {stats.get('total_agents_spawned', 0)} |",
            f"| Tokens Used | {stats.get('total_tokens_used', 0):,} |",
            f"| Total Cost | ${stats.get('total_cost_usd', 0.0)} |",
            f"",
            f"---",
            f"",
            f"## Findings",
            f"",
        ]

        for finding in report.get("findings", []):
            if finding.get("false_positive"):
                continue
            sev = finding.get("severity", "info").upper()
            cvss = f" (CVSS: {finding['cvss_score']})" if finding.get("cvss_score") else ""
            lines += [
                f"### [{sev}] {finding['title']}{cvss}",
                f"",
                f"**Type:** {finding.get('vulnerability_type', 'N/A')}",
            ]
            if finding.get("url"):
                lines.append(f"**URL:** `{finding['url']}`")
            lines += [
                f"",
                finding.get("description", ""),
                f"",
            ]
            if finding.get("proof_of_concept"):
                lines += [
                    f"**Proof of Concept:**",
                    f"```",
                    finding["proof_of_concept"],
                    f"```",
                    f"",
                ]
            if finding.get("remediation_advice"):
                lines += [
                    f"**Remediation:** {finding['remediation_advice']}",
                    f"",
                ]
            mitre = finding.get("mitre_techniques", [])
            if mitre:
                lines.append(f"**MITRE ATT&CK:** {', '.join(mitre)}")
                lines.append(f"")
            lines.append(f"---")
            lines.append(f"")

        return "\n".join(lines)
