"""
LongTermMemory - cross-engagement persistent memory with keyword search.

Stores insights, vulnerability patterns, and attack chains across engagements.
Supports simple keyword search and tech-stack filtering. A Bayesian advisory
layer provides probability estimates for vulnerability types based on historical
success rates against similar technology stacks.
"""
import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import Memory

logger = logging.getLogger(__name__)


class LongTermMemory:
    """
    Cross-engagement memory backed by the Memory database table.

    Each stored memory has:
      - A type (vulnerability_pattern, attack_chain, tool_insight, etc.)
      - A title and free-text content
      - Optional tech_stack and vuln_types tags for filtering
      - A success_rate that improves over time via record_outcome()

    The get_advisory() method returns Bayesian-style probability estimates for
    vulnerability types given a tech stack, computed from historical success rates.
    """

    def __init__(self, session_factory: Any) -> None:
        self._session_factory = session_factory

    # ─────────────────────── Storage API ─────────────────────────

    async def store(
        self,
        memory_type: str,
        title: str,
        content: str,
        metadata: Optional[dict] = None,
        tech_stack: Optional[List[str]] = None,
        vuln_types: Optional[List[str]] = None,
        engagement_id: Optional[int] = None,
    ) -> int:
        """
        Persist a new memory record.

        Returns the database ID of the created Memory row.
        """
        async with self._session_factory() as session:
            memory = Memory(
                memory_type=memory_type,
                title=title,
                content=content,
                metadata=metadata or {},
                tech_stack=tech_stack or [],
                vuln_types=vuln_types or [],
                times_recalled=0,
                times_useful=0,
                success_rate=0.0,
                source_engagement_id=engagement_id,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            session.add(memory)
            await session.flush()
            memory_id: int = memory.id
            await session.commit()

        logger.info(
            "LongTermMemory: stored memory id=%d type='%s' title='%s'",
            memory_id,
            memory_type,
            title,
        )
        return memory_id

    # ─────────────────────── Search API ──────────────────────────

    async def search_by_text(
        self,
        query: str,
        memory_type: Optional[str] = None,
        limit: int = 10,
    ) -> List[dict]:
        """
        Keyword search across title and content fields.

        Splits the query on whitespace and filters rows that contain ALL tokens
        (case-insensitive substring match). Returns up to limit results,
        ordered by success_rate descending then times_recalled descending.
        """
        tokens = [t.strip().lower() for t in query.split() if t.strip()]

        async with self._session_factory() as session:
            stmt = select(Memory)
            if memory_type is not None:
                stmt = stmt.where(Memory.memory_type == memory_type)

            result = await session.execute(stmt)
            rows = result.scalars().all()

        # Filter in Python — avoids database-specific full-text syntax
        matched: List[Memory] = []
        for row in rows:
            searchable = (
                f"{row.title} {row.content}".lower()
            )
            if all(token in searchable for token in tokens):
                matched.append(row)

        # Sort by quality: success_rate first, then recall frequency
        matched.sort(
            key=lambda r: (r.success_rate, r.times_recalled), reverse=True
        )

        # Increment recall counter asynchronously (best effort)
        if matched:
            ids = [r.id for r in matched[:limit]]
            await self._increment_recalled(ids)

        return [self._row_to_dict(r) for r in matched[:limit]]

    async def search_by_tech_stack(
        self,
        tech_stack: List[str],
        vuln_types: Optional[List[str]] = None,
        limit: int = 10,
    ) -> List[dict]:
        """
        Return memories tagged with any of the supplied tech_stack items.

        Optionally further filters by vuln_types. Results are ordered by
        success_rate descending.
        """
        async with self._session_factory() as session:
            result = await session.execute(select(Memory))
            rows = result.scalars().all()

        tech_needles = [t.lower() for t in tech_stack]
        vuln_needles = [v.lower() for v in (vuln_types or [])]

        matched: List[Memory] = []
        for row in rows:
            row_techs = [t.lower() for t in (row.tech_stack or [])]
            row_vulns = [v.lower() for v in (row.vuln_types or [])]

            tech_match = any(needle in row_techs for needle in tech_needles)
            if not tech_match:
                continue

            if vuln_needles:
                vuln_match = any(needle in row_vulns for needle in vuln_needles)
                if not vuln_match:
                    continue

            matched.append(row)

        matched.sort(key=lambda r: r.success_rate, reverse=True)

        if matched:
            ids = [r.id for r in matched[:limit]]
            await self._increment_recalled(ids)

        return [self._row_to_dict(r) for r in matched[:limit]]

    # ─────────────────────── Advisory API ────────────────────────

    async def get_advisory(
        self, tech_stack: List[str], target_type: str
    ) -> Dict[str, float]:
        """
        Return Bayesian-style prior probabilities for vulnerability types.

        For each vuln_type seen in historical memories whose tech_stack overlaps
        with the provided tech_stack, compute:

            P(vuln_type) = weighted_success_rate

        where the weight is boosted when the memory is specifically tagged for
        target_type.

        Returns a dict mapping vuln_type → probability (0.0 – 1.0).
        """
        memories = await self.search_by_tech_stack(tech_stack, limit=200)

        # Accumulate success rates per vuln type
        vuln_scores: Dict[str, List[float]] = defaultdict(list)
        target_lower = target_type.lower()

        for mem in memories:
            base_rate = mem.get("success_rate", 0.0)
            meta = mem.get("metadata", {})
            # Boost if memory specifically matches target type
            if target_lower in str(meta.get("target_type", "")).lower():
                base_rate = min(1.0, base_rate * 1.25)

            for vtype in mem.get("vuln_types", []):
                vuln_scores[vtype.lower()].append(base_rate)

        if not vuln_scores:
            return {}

        # Average the scores per vuln type
        advisory: Dict[str, float] = {}
        for vtype, scores in vuln_scores.items():
            advisory[vtype] = round(sum(scores) / len(scores), 4)

        return advisory

    # ─────────────────────── Feedback API ────────────────────────

    async def record_outcome(self, memory_id: int, was_useful: bool) -> None:
        """
        Update the success_rate of a memory based on whether it proved useful.

        success_rate = times_useful / times_recalled (with at least 1 recall).
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(Memory).where(Memory.id == memory_id)
            )
            row = result.scalar_one_or_none()
            if row is None:
                logger.warning(
                    "LongTermMemory.record_outcome: memory id=%d not found.",
                    memory_id,
                )
                return

            new_recalled = row.times_recalled + 1
            new_useful = row.times_useful + (1 if was_useful else 0)
            new_rate = new_useful / new_recalled

            await session.execute(
                update(Memory)
                .where(Memory.id == memory_id)
                .values(
                    times_recalled=new_recalled,
                    times_useful=new_useful,
                    success_rate=new_rate,
                    updated_at=datetime.utcnow(),
                )
            )
            await session.commit()

        logger.debug(
            "LongTermMemory: outcome recorded for id=%d useful=%s rate=%.3f",
            memory_id,
            was_useful,
            new_rate,
        )

    # ─────────────────────── Helpers ─────────────────────────────

    async def _increment_recalled(self, memory_ids: List[int]) -> None:
        """Increment times_recalled for a list of memory IDs in one query."""
        try:
            async with self._session_factory() as session:
                for mid in memory_ids:
                    await session.execute(
                        update(Memory)
                        .where(Memory.id == mid)
                        .values(
                            times_recalled=Memory.times_recalled + 1,
                            updated_at=datetime.utcnow(),
                        )
                    )
                await session.commit()
        except Exception as exc:
            # Non-critical — don't propagate
            logger.warning(
                "LongTermMemory: failed to increment recall counts: %s", exc
            )

    @staticmethod
    def _row_to_dict(row: Memory) -> dict:
        return {
            "id": row.id,
            "memory_type": row.memory_type,
            "title": row.title,
            "content": row.content,
            "metadata": row.metadata or {},
            "tech_stack": row.tech_stack or [],
            "vuln_types": row.vuln_types or [],
            "times_recalled": row.times_recalled,
            "times_useful": row.times_useful,
            "success_rate": row.success_rate,
            "source_engagement_id": row.source_engagement_id,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }
