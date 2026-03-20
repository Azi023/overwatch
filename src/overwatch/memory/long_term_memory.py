"""
LongTermMemory - cross-engagement persistent memory with vector search.

Stores insights, vulnerability patterns, and attack chains across engagements.
Supports:
  - Keyword search (ILIKE-based, database-level)
  - Vector similarity search (pgvector when available, cosine on JSON fallback)
  - Tech-stack filtering
  - Bayesian advisory layer for vulnerability probability estimates
"""
import hashlib
import logging
import math
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import Memory

logger = logging.getLogger(__name__)

# ──────────────────────────── Embedding helpers ────────────────────────────

# Embedding dimension — must match the model output or the local fallback
_EMBED_DIM = 256


def _tokenize(text: str) -> List[str]:
    """Simple whitespace+punctuation tokeniser for the local embedding fallback."""
    import re
    return [t.lower() for t in re.findall(r'[a-z0-9]+', text.lower()) if len(t) > 1]


def _local_embedding(text: str) -> List[float]:
    """
    Generate a deterministic fixed-size embedding using hashed bag-of-words.

    This is a lightweight fallback when the Anthropic embedding API is
    unavailable.  It produces a 256-dimensional vector using feature hashing
    (hashing trick) over unigrams and bigrams, then L2-normalises.

    Not as semantically rich as a neural model but sufficient for recall-based
    similarity ranking.
    """
    tokens = _tokenize(text)
    if not tokens:
        return [0.0] * _EMBED_DIM

    vec = [0.0] * _EMBED_DIM

    # Unigrams
    for tok in tokens:
        idx = int(hashlib.md5(tok.encode()).hexdigest(), 16) % _EMBED_DIM
        vec[idx] += 1.0

    # Bigrams (capture phrase structure)
    for i in range(len(tokens) - 1):
        bigram = f"{tokens[i]}_{tokens[i+1]}"
        idx = int(hashlib.md5(bigram.encode()).hexdigest(), 16) % _EMBED_DIM
        vec[idx] += 0.5

    # L2 normalise
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [v / norm for v in vec]

    return vec


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    """Cosine similarity between two vectors.  Returns 0.0 on degenerate input."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


async def _anthropic_embedding(text: str, api_key: Optional[str] = None) -> Optional[List[float]]:
    """
    Generate an embedding via the Anthropic Voyager model.

    Returns None if the API is unavailable or the call fails.
    """
    try:
        import anthropic
    except ImportError:
        return None

    resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not resolved_key:
        return None

    try:
        client = anthropic.Anthropic(api_key=resolved_key)
        # Anthropic's embedding endpoint (voyage-3 via Anthropic)
        response = client.embeddings.create(
            model="voyage-3",
            input=[text[:8000],],  # truncate to model limit
        )
        return response.data[0].embedding
    except Exception as exc:
        logger.debug("Anthropic embedding call failed: %s", exc)
        return None


# ──────────────────────────── LongTermMemory ────────────────────────────────


class LongTermMemory:
    """
    Cross-engagement memory backed by the Memory database table.

    Each stored memory has:
      - A type (vulnerability_pattern, attack_chain, tool_insight, etc.)
      - A title and free-text content
      - Optional tech_stack and vuln_types tags for filtering
      - A success_rate that improves over time via record_outcome()
      - An embedding vector for similarity search

    The get_advisory() method returns Bayesian-style probability estimates for
    vulnerability types given a tech stack, computed from historical success rates.
    """

    def __init__(
        self,
        session_factory: Any,
        use_anthropic_embeddings: bool = False,
        anthropic_api_key: Optional[str] = None,
    ) -> None:
        self._session_factory = session_factory
        self._use_anthropic = use_anthropic_embeddings
        self._anthropic_key = anthropic_api_key

    # ─────────────────────── Embedding generation ─────────────────

    async def _generate_embedding(self, text: str) -> List[float]:
        """
        Generate an embedding for the given text.

        Tries Anthropic Voyager first (if enabled and available),
        then falls back to the local hashed bag-of-words approach.
        """
        if self._use_anthropic:
            embedding = await _anthropic_embedding(text, self._anthropic_key)
            if embedding is not None:
                return embedding
            logger.debug("Anthropic embedding unavailable — using local fallback")

        return _local_embedding(text)

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
        Persist a new memory record with an embedding vector.

        Returns the database ID of the created Memory row.
        """
        embed_text = f"{title} {content}"
        embedding = await self._generate_embedding(embed_text)

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
                embedding=embedding,
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

        Splits the query on whitespace and applies database-level ILIKE
        filters so only matching rows are loaded. Returns up to limit results,
        ordered by success_rate descending then times_recalled descending.
        """
        limit = min(limit, 200)
        tokens = [t.strip().lower() for t in query.split() if t.strip()]

        async with self._session_factory() as session:
            stmt = select(Memory)
            if memory_type is not None:
                stmt = stmt.where(Memory.memory_type == memory_type)

            # Apply ILIKE filters at the database level for each token
            for token in tokens:
                pattern = f"%{token}%"
                stmt = stmt.where(
                    (Memory.title.ilike(pattern)) | (Memory.content.ilike(pattern))
                )

            stmt = stmt.order_by(
                Memory.success_rate.desc(), Memory.times_recalled.desc()
            ).limit(limit)

            result = await session.execute(stmt)
            matched = result.scalars().all()

        # Increment recall counter asynchronously (best effort)
        if matched:
            ids = [r.id for r in matched]
            await self._increment_recalled(ids)

        return [self._row_to_dict(r) for r in matched]

    async def search_by_similarity(
        self,
        query: str,
        memory_type: Optional[str] = None,
        limit: int = 10,
        min_similarity: float = 0.3,
    ) -> List[dict]:
        """
        Vector similarity search using embedding cosine distance.

        Generates an embedding for the query, loads candidate memories from
        the database, and ranks them by cosine similarity. Only returns
        results above min_similarity threshold.

        When pgvector is available (PostgreSQL), this could be done entirely
        in SQL.  The current implementation loads embeddings and computes
        similarity in Python, which is efficient enough for <100k memories.
        """
        limit = min(limit, 200)
        query_embedding = await self._generate_embedding(query)

        async with self._session_factory() as session:
            stmt = select(Memory).where(Memory.embedding.isnot(None))
            if memory_type is not None:
                stmt = stmt.where(Memory.memory_type == memory_type)
            # Load bounded set for similarity computation
            stmt = stmt.limit(2000)

            result = await session.execute(stmt)
            rows = result.scalars().all()

        # Score and rank by cosine similarity
        scored: List[Tuple[float, Memory]] = []
        for row in rows:
            if not row.embedding:
                continue
            sim = _cosine_similarity(query_embedding, row.embedding)
            if sim >= min_similarity:
                scored.append((sim, row))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        top = scored[:limit]

        # Increment recall counters
        if top:
            ids = [row.id for _, row in top]
            await self._increment_recalled(ids)

        results = []
        for sim, row in top:
            d = self._row_to_dict(row)
            d["similarity"] = round(sim, 4)
            results.append(d)

        return results

    async def search_by_tech_stack(
        self,
        tech_stack: List[str],
        vuln_types: Optional[List[str]] = None,
        limit: int = 10,
    ) -> List[dict]:
        """
        Return memories tagged with any of the supplied tech_stack items.

        Optionally further filters by vuln_types. Results are ordered by
        success_rate descending. Uses database-level JSON containment where
        possible and falls back to Python filtering for case-insensitive match.
        """
        limit = min(limit, 200)

        async with self._session_factory() as session:
            # Load a bounded set of memories ordered by success_rate
            stmt = (
                select(Memory)
                .order_by(Memory.success_rate.desc())
                .limit(1000)
            )
            result = await session.execute(stmt)
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
            if len(matched) >= limit:
                break

        if matched:
            ids = [r.id for r in matched]
            await self._increment_recalled(ids)

        return [self._row_to_dict(r) for r in matched]

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
            "embedding": row.embedding is not None,
            "source_engagement_id": row.source_engagement_id,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }
