"""
Database connection and session management for Overwatch V2.

Engine and session factory are created lazily so the module can be imported
even when asyncpg is not installed (e.g., test environments using aiosqlite).
"""
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from .models import Base


def _resolve_database_url() -> str:
    """Resolve DATABASE_URL from environment with fallback."""
    url = os.getenv("DATABASE_URL")
    if not url:
        import warnings
        url = "postgresql://overwatch:overwatch_pass@localhost:5432/overwatch_db"
        warnings.warn(
            "DATABASE_URL is not set — using default development credentials. "
            "Set the DATABASE_URL environment variable in production.",
            stacklevel=2,
        )
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


# Lazy singletons — initialised on first access via _get_engine()
_engine = None
_async_session_local: Optional[async_sessionmaker] = None


def _get_engine():
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            _resolve_database_url(),
            echo=os.getenv("SQL_ECHO", "false").lower() == "true",
            poolclass=NullPool,
        )
    return _engine


def _get_session_factory() -> async_sessionmaker:
    global _async_session_local
    if _async_session_local is None:
        _async_session_local = async_sessionmaker(
            _get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _async_session_local


class _AsyncSessionLocalProxy:
    """
    Proxy that defers engine creation to first use.

    Supports both ``AsyncSessionLocal()`` (call) and reassignment for testing.
    """
    def __call__(self):
        return _get_session_factory()()

    def __getattr__(self, name):
        return getattr(_get_session_factory(), name)


AsyncSessionLocal = _AsyncSessionLocalProxy()


async def init_db() -> None:
    """Create all tables."""
    async with _get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_db() -> None:
    """Drop all tables. Use with caution."""
    async with _get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Context-manager session for internal use."""
    async with _get_session_factory()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async session."""
    async with _get_session_factory()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
