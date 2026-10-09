"""Database engine and session factory (SQLAlchemy 2, asyncpg)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import MetaData, text
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

# Deterministic constraint names, so Alembic autogenerate produces stable migrations.
NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


def make_engine(url: str) -> AsyncEngine:
    if url.startswith("sqlite"):
        # SQLite (tests and quick local trials only): one file, no server.
        return create_async_engine(url)
    # pool_pre_ping drops connections the server closed (e.g. after a DB restart).
    return create_async_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5)


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def ping(engine: AsyncEngine) -> None:
    """Raise if the database can't answer a trivial query."""
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))


async def session_scope(maker: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    async with maker() as session:
        yield session


def upsert_insert(session: AsyncSession, model: Any) -> Any:
    """A dialect-specific INSERT that supports ``on_conflict_do_nothing`` /
    ``on_conflict_do_update`` (PostgreSQL in production, SQLite in tests)."""
    dialect = session.get_bind().dialect.name
    return (postgresql.insert if dialect == "postgresql" else sqlite.insert)(model)
