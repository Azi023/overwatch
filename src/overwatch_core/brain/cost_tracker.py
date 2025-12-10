# src/overwatch_core/brain/cost_tracker.py
from datetime import datetime, timedelta
from typing import Dict, Optional
from sqlalchemy import select, func
from ..persistence.models import AIUsageLog

class CostTracker:
    """
    Tracks AI API costs to stay within budget.
    """
    
    def __init__(self, session_factory, daily_budget: float = 5.0):
        self.session_factory = session_factory
        self.daily_budget = daily_budget
    
    async def can_make_request(self, estimated_cost: float) -> bool:
        """Check if request is within daily budget."""
        today_spend = await self.get_daily_spend()
        return (today_spend + estimated_cost) <= self.daily_budget
    
    async def get_daily_spend(self) -> float:
        """Get total spend for today."""
        async with self.session_factory() as session:
            today = datetime.utcnow().date()
            result = await session.execute(
                select(func.sum(AIUsageLog.cost))
                .where(func.date(AIUsageLog.timestamp) == today)
            )
            return result.scalar() or 0.0
    
    async def record_usage(
        self, 
        model: str, 
        input_tokens: int, 
        output_tokens: int,
        cost: float,
        task_type: str
    ):
        """Record API usage."""
        async with self.session_factory() as session:
            log = AIUsageLog(
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost=cost,
                task_type=task_type,
                timestamp=datetime.utcnow()
            )
            session.add(log)
            await session.commit()
    
    async def get_usage_report(self, days: int = 30) -> Dict:
        """Get usage statistics."""
        async with self.session_factory() as session:
            since = datetime.utcnow() - timedelta(days=days)
            
            # Total cost
            total_result = await session.execute(
                select(func.sum(AIUsageLog.cost))
                .where(AIUsageLog.timestamp >= since)
            )
            total_cost = total_result.scalar() or 0.0
            
            # By model
            by_model = {}
            model_result = await session.execute(
                select(AIUsageLog.model, func.sum(AIUsageLog.cost))
                .where(AIUsageLog.timestamp >= since)
                .group_by(AIUsageLog.model)
            )
            for model, cost in model_result:
                by_model[model] = cost
            
            # By task type
            by_task = {}
            task_result = await session.execute(
                select(AIUsageLog.task_type, func.sum(AIUsageLog.cost))
                .where(AIUsageLog.timestamp >= since)
                .group_by(AIUsageLog.task_type)
            )
            for task, cost in task_result:
                by_task[task] = cost
            
            return {
                "period_days": days,
                "total_cost": total_cost,
                "average_daily": total_cost / days,
                "by_model": by_model,
                "by_task": by_task,
                "daily_budget": self.daily_budget,
                "budget_utilization": (total_cost / days) / self.daily_budget
            }
