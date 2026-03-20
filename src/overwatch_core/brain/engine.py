# src/overwatch_core/brain/engine.py

import logging
from typing import Dict, List, Any
from dataclasses import dataclass, field

from .rules import HeuristicRules
from overwatch_core.scanners.base import ScanResult

logger = logging.getLogger(__name__)

@dataclass
class AnalyzedFinding:
    """Enriched finding with Brain analysis."""
    original_finding: Dict[str, Any]
    risk_score: int
    priority: str # Critical, High, Medium, Low
    next_steps: List[str]

@dataclass
class AnalysisReport:
    """Full analysis of a scan."""
    target: str
    total_risk_score: int
    top_findings: List[AnalyzedFinding]
    summary: str

class BrainEngine:
    """
    The Intelligence Layer of Overwatch.
    Currently uses Heuristics (Rule-Based), upgradeable to LLM.
    """
    
    def __init__(self):
        self.rules = HeuristicRules()
        
    def analyze(self, scan_result: ScanResult) -> AnalysisReport:
        """
        Analyze a scan result and return actionable intelligence.
        """
        logger.info(f"Brain analyzing scan for {scan_result.target}...")
        
        analyzed_findings = []
        total_risk = 0
        
        for finding in scan_result.findings:
            # 1. Calculate Risk
            score = self.rules.calculate_risk_score(finding)
            total_risk += score
            
            # 2. Determine Priority
            if score >= 90: priority = "CRITICAL"
            elif score >= 70: priority = "HIGH"
            elif score >= 40: priority = "MEDIUM"
            else: priority = "LOW"
            
            # 3. Suggest Steps
            steps = self.rules.suggest_next_steps(finding)
            
            analyzed_findings.append(AnalyzedFinding(
                original_finding=finding,
                risk_score=score,
                priority=priority,
                next_steps=steps
            ))
            
        # Sort by risk (descending)
        analyzed_findings.sort(key=lambda x: x.risk_score, reverse=True)
        
        # Generate Summary
        count = len(analyzed_findings)
        critical_count = len([f for f in analyzed_findings if f.priority == "CRITICAL"])
        summary = f"Analysis complete. Found {count} issues. {critical_count} are CRITICAL."
        
        return AnalysisReport(
            target=scan_result.target,
            total_risk_score=total_risk,
            top_findings=analyzed_findings,
            summary=summary
        )
