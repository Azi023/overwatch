"""
EngagementMemory - PostgreSQL-backed shared memory for a single engagement.

All agents within the same engagement share this memory. It persists for the
lifetime of the engagement in the database, allowing agents to communicate
discoveries and avoid duplicate work.
"""
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import Credential, Engagement

logger = logging.getLogger(__name__)


class EngagementMemory:
    """
    Shared, persistent memory for a single penetration testing engagement.

    Key-value pairs are stored in the Engagement.scope_config JSON column under
    a dedicated namespace so they don't collide with other engagement metadata.

    Credentials are stored in the Credential table (encrypted values are passed
    in by the caller — use CredentialStore to encrypt before calling here).

    Discoveries are stored as lists under category namespaces within the
    engagement's JSON column.
    """

    _KV_NAMESPACE = "_engagement_kv"
    _DISCOVERY_NAMESPACE = "_discoveries"

    def __init__(self, engagement_id: int, session_factory: Any) -> None:
        self._engagement_id = engagement_id
        self._session_factory = session_factory

    # ─────────────────────── Key-Value API ───────────────────────

    async def store(
        self,
        key: str,
        value: Any,
        category: str = "general",
    ) -> None:
        """
        Upsert a key-value pair scoped to this engagement.

        Values are JSON-serialisable Python objects. The category is used as a
        sub-namespace so related keys can be retrieved together.
        """
        async with self._session_factory() as session:
            engagement = await self._load_engagement(session)
            config = dict(engagement.scope_config or {})

            ns = config.setdefault(self._KV_NAMESPACE, {})
            cat = ns.setdefault(category, {})
            cat[key] = value
            ns[category] = cat
            config[self._KV_NAMESPACE] = ns

            await session.execute(
                update(Engagement)
                .where(Engagement.id == self._engagement_id)
                .values(scope_config=config)
            )
            await session.commit()
            logger.debug(
                "EngagementMemory[%d] stored key='%s' category='%s'",
                self._engagement_id,
                key,
                category,
            )

    async def retrieve(self, key: str) -> Optional[Any]:
        """Return the value for key, searching across all categories."""
        async with self._session_factory() as session:
            engagement = await self._load_engagement(session)
            ns = (engagement.scope_config or {}).get(self._KV_NAMESPACE, {})
            for _category, entries in ns.items():
                if key in entries:
                    return entries[key]
            return None

    async def retrieve_all(self, category: Optional[str] = None) -> Dict[str, Any]:
        """
        Return all stored key-value pairs.

        If category is given, only return pairs from that category. Otherwise
        return a flat dict merging all categories (later categories win on
        key collisions).
        """
        async with self._session_factory() as session:
            engagement = await self._load_engagement(session)
            ns = (engagement.scope_config or {}).get(self._KV_NAMESPACE, {})

            if category is not None:
                return dict(ns.get(category, {}))

            merged: Dict[str, Any] = {}
            for _cat, entries in ns.items():
                merged.update(entries)
            return merged

    # ─────────────────────── Credential API ──────────────────────

    async def store_credential(
        self,
        service: str,
        username: str,
        credential_type: str,
        encrypted_value: str,
    ) -> None:
        """
        Persist an already-encrypted credential for this engagement.

        The caller is responsible for encrypting the plaintext value before
        calling this method (use CredentialStore.encrypt).
        """
        async with self._session_factory() as session:
            credential = Credential(
                engagement_id=self._engagement_id,
                credential_type=credential_type,
                username=username,
                service=service,
                encrypted_value=encrypted_value,
                scope="engagement",
                discovered_at=datetime.utcnow(),
                is_valid=True,
            )
            session.add(credential)
            await session.commit()
            logger.info(
                "EngagementMemory[%d] stored credential for service='%s' user='%s'",
                self._engagement_id,
                service,
                username,
            )

    async def get_credentials(self, service: Optional[str] = None) -> List[dict]:
        """
        Return credentials for this engagement.

        If service is given, filter by service name. Values remain encrypted;
        use CredentialStore.decrypt to read the plaintext.
        """
        async with self._session_factory() as session:
            stmt = select(Credential).where(
                Credential.engagement_id == self._engagement_id,
                Credential.is_valid == True,  # noqa: E712
            )
            if service is not None:
                stmt = stmt.where(Credential.service == service)

            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [
                {
                    "id": row.id,
                    "service": row.service,
                    "username": row.username,
                    "credential_type": row.credential_type,
                    "encrypted_value": row.encrypted_value,
                    "scope": row.scope,
                    "discovered_at": row.discovered_at.isoformat()
                    if row.discovered_at
                    else None,
                    "is_valid": row.is_valid,
                }
                for row in rows
            ]

    # ─────────────────────── Discovery API ───────────────────────

    async def store_discovery(self, discovery_type: str, data: dict) -> None:
        """
        Append a discovery record under the given discovery_type.

        Examples of discovery_type: "open_port", "subdomain", "http_service",
        "directory", "technology".
        """
        async with self._session_factory() as session:
            engagement = await self._load_engagement(session)
            config = dict(engagement.scope_config or {})

            disc_ns = config.setdefault(self._DISCOVERY_NAMESPACE, {})
            type_list: List[dict] = list(disc_ns.get(discovery_type, []))
            type_list.append(
                {**data, "_stored_at": datetime.utcnow().isoformat()}
            )
            disc_ns[discovery_type] = type_list
            config[self._DISCOVERY_NAMESPACE] = disc_ns

            await session.execute(
                update(Engagement)
                .where(Engagement.id == self._engagement_id)
                .values(scope_config=config)
            )
            await session.commit()
            logger.debug(
                "EngagementMemory[%d] stored discovery type='%s'",
                self._engagement_id,
                discovery_type,
            )

    async def get_discoveries(
        self, discovery_type: Optional[str] = None
    ) -> List[dict]:
        """
        Return all discoveries for this engagement.

        If discovery_type is given, return only that category. Otherwise return
        a flat list of all discoveries (with a '_type' key injected).
        """
        async with self._session_factory() as session:
            engagement = await self._load_engagement(session)
            disc_ns = (engagement.scope_config or {}).get(
                self._DISCOVERY_NAMESPACE, {}
            )

            if discovery_type is not None:
                return list(disc_ns.get(discovery_type, []))

            all_discoveries: List[dict] = []
            for dtype, entries in disc_ns.items():
                for entry in entries:
                    all_discoveries.append({"_type": dtype, **entry})
            return all_discoveries

    # ─────────────────────── Helpers ─────────────────────────────

    async def _load_engagement(self, session: AsyncSession) -> Engagement:
        result = await session.execute(
            select(Engagement).where(Engagement.id == self._engagement_id)
        )
        engagement = result.scalar_one_or_none()
        if engagement is None:
            raise ValueError(
                f"Engagement {self._engagement_id} not found in database."
            )
        return engagement

    def __repr__(self) -> str:
        return f"EngagementMemory(engagement_id={self._engagement_id})"
