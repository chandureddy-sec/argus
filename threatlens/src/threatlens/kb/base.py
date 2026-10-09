"""Knowledge sources: ATT&CK, NVD, EPSS, OSV.

They differ from indicator feeds: what they produce is context (entities,
CVE records, edges), not indicators, so they don't go through the indicator
pipeline. They share everything else with connectors: a ``SourceInfo``
contract (licence, reliability, fetch limits), a ``sources`` row with health
and checkpoint, scheduling, run records and the raw archive. The collector
runs them through the same ``run()`` entry point.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens.connectors.base import MissingKeyError, SourceInfo
from threatlens.models import RawDocument
from threatlens.net.http import SafeHttp
from threatlens.rawstore import RawStore
from threatlens.settings import Settings


class BudgetExhaustedError(Exception):
    """The run used its request budget; the rest waits for the next run."""


@dataclass
class KbContext:
    sm: async_sessionmaker[AsyncSession]
    http: SafeHttp
    store: RawStore
    settings: Settings
    now: datetime
    source_id: int
    source_name: str
    checkpoint: dict[str, Any]
    sleep: Callable[[float], Awaitable[None]]


@dataclass
class KbResult:
    status: str = "success"  # success | partial | not_modified
    items_total: int = 0
    items_new: int = 0
    items_updated: int = 0
    http_status: int | None = 200
    raw_id: int | None = None
    checkpoint: dict[str, Any] = field(default_factory=dict)
    note: str | None = None


class KnowledgeSource(ABC):
    info: ClassVar[SourceInfo]

    def __init__(self, api_key: str | None = None) -> None:
        if self.info.key_required and not api_key:
            setting = f"TL_{self.info.key_setting.upper()}" if self.info.key_setting else "an API key"
            raise MissingKeyError(f"{self.info.name} needs {setting}")
        self.api_key = api_key

    @abstractmethod
    async def sync(self, ctx: KbContext) -> KbResult: ...


KB_REGISTRY: dict[str, type[KnowledgeSource]] = {}


def register_kb(cls: type[KnowledgeSource]) -> type[KnowledgeSource]:
    if cls.info.name in KB_REGISTRY:
        raise ValueError(f"duplicate knowledge source {cls.info.name}")
    KB_REGISTRY[cls.info.name] = cls
    return cls


async def archive(ctx: KbContext, url: str, body: bytes, content_type: str, items: int = 0) -> int:
    """Store a fetched body in the raw archive and record it; returns its id.
    An identical body fetched before is recorded once."""
    sha, ref = ctx.store.put(ctx.source_name, body)
    async with ctx.sm() as s, s.begin():
        doc = await s.scalar(
            select(RawDocument).where(RawDocument.source_id == ctx.source_id, RawDocument.sha256 == sha)
        )
        if doc is None:
            doc = RawDocument(
                source_id=ctx.source_id,
                url=url[:2000],
                sha256=sha,
                size=len(body),
                content_type=content_type[:200],
                payload_ref=ref,
                fetched_at=ctx.now,
                parse_status="parsed",
                items=items,
            )
            s.add(doc)
            await s.flush()
        return doc.id
