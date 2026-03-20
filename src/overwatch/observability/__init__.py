"""
Observability layer for Overwatch V2.
Provides structured tracing and engagement quality evaluation.
"""
from .evaluation import EngagementEvaluator, EvaluationReport
from .tracer import Tracer

__all__ = ["Tracer", "EngagementEvaluator", "EvaluationReport"]
