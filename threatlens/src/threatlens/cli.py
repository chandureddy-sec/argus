"""Command-line entry point: ``threatlens <command>``."""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import AsyncIterator, Callable, Coroutine, Sequence
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import __version__
from threatlens.auth import ROLE_RANK, create_key, revoke_key
from threatlens.collect import RunSummary
from threatlens.connectors import REGISTRY
from threatlens.db import make_engine, make_sessionmaker
from threatlens.ioc.defang import defang
from threatlens.ioc.extract import extract
from threatlens.ioc.types import Observable, Rejected
from threatlens.jobs import collect_due, open_collector, refresh_allowlists
from threatlens.kb import KB_REGISTRY
from threatlens.models import ApiKey, AuditLog, Source
from threatlens.profile import ProfileError, load_pirs, load_profile
from threatlens.settings import get_settings

# Indicator feeds and knowledge sources (ATT&CK, NVD, EPSS, OSV).
ALL_SOURCES = sorted({*REGISTRY, *KB_REGISTRY})


def _validate_profile(args: argparse.Namespace) -> int:
    s = get_settings()
    profile_path = Path(args.profile or s.profile_path)
    pirs_path = Path(args.pirs or s.pirs_path)
    try:
        profile = load_profile(profile_path)
        pirs = load_pirs(pirs_path, profile)
    except ProfileError as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    org = profile.org
    print(
        f"ok: {org.name} - {len(org.domains)} domains, {len(org.ip_ranges)} IP ranges, "
        f"{len(org.brands)} brands, {len(org.tech_stack)} tech-stack items; {len(pirs.pirs)} PIRs"
    )
    return 0


def _api(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "threatlens.api.app:create_app", factory=True, host=args.host, port=args.port, log_config=None
    )
    return 0


@asynccontextmanager
async def _session() -> AsyncIterator[AsyncSession]:
    engine = make_engine(get_settings().database_url.get_secret_value())
    try:
        async with make_sessionmaker(engine)() as s:
            yield s
    finally:
        await engine.dispose()


def _run(
    coro: Callable[[argparse.Namespace], Coroutine[Any, Any, int]],
) -> Callable[[argparse.Namespace], int]:
    def runner(args: argparse.Namespace) -> int:
        return asyncio.run(coro(args))

    return runner


def _when(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M") if dt else "-"


async def _init_db(args: argparse.Namespace) -> int:
    url = get_settings().database_url.get_secret_value()
    if not url.startswith("sqlite"):
        print("init-db is for SQLite trials; on Postgres run: alembic upgrade head", file=sys.stderr)
        return 2
    import threatlens.models  # noqa: F401 - register tables
    from threatlens.db import Base

    engine = make_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    finally:
        await engine.dispose()
    print("ok: tables created")
    return 0


# ── collection ──────────────────────────────────────────────────────────────

FAILED = {"failed"}


def _print_runs(runs: list[RunSummary]) -> None:
    print(f"{'source':<15} {'status':<13} {'total':>7} {'new':>7} {'upd':>7} {'rej':>5} {'allow':>5}  note")
    for r in runs:
        print(
            f"{r.source:<15} {r.status:<13} {r.items_total:>7} {r.items_new:>7} {r.items_updated:>7} "
            f"{r.items_rejected:>5} {r.items_allowlisted:>5}  {r.error or r.note or ''}"
        )


async def _collect(args: argparse.Namespace) -> int:
    unknown = [n for n in args.sources if n not in ALL_SOURCES]
    if unknown:
        print(f"unknown source(s): {', '.join(unknown)}; known: {', '.join(ALL_SOURCES)}", file=sys.stderr)
        return 2
    if not args.sources and not args.due and not args.all:
        print("name one or more sources, or pass --due or --all", file=sys.stderr)
        return 2
    async with open_collector(get_settings()) as c:
        if args.due:
            runs = await collect_due(c)
        else:
            names = ALL_SOURCES if args.all else args.sources
            runs = [await c.run(n, force=args.force) for n in names]
    if not runs:
        print("nothing due")
        return 0
    _print_runs(runs)
    return 1 if any(r.status in FAILED for r in runs) else 0


async def _sources(args: argparse.Namespace) -> int:
    async with open_collector(get_settings()) as c, c.sm() as s, s.begin():
        if args.action in ("enable", "disable"):
            row = await s.scalar(select(Source).where(Source.name == args.name))
            if row is None:
                print(f"unknown source {args.name!r}", file=sys.stderr)
                return 2
            row.enabled = args.action == "enable"
            s.add(AuditLog(actor="cli", action=f"source.{args.action}", target=args.name, details={}))
            print(f"{args.name}: {'enabled' if row.enabled else 'disabled'}")
            return 0
        rows = (await s.scalars(select(Source).order_by(Source.name))).all()
    print(
        f"{'source':<15} {'on':<3} {'health':<9} {'every':>6} {'last success':<17} {'next run':<17} licence"
    )
    for r in rows:
        print(
            f"{r.name:<15} {'y' if r.enabled else 'n':<3} {r.health:<9} {r.interval_minutes:>5}m "
            f"{_when(r.last_success_at):<17} {_when(r.next_run_at):<17} "
            f"{r.license}{'' if r.commercial_use else ' (non-commercial)'}"
        )
        if r.last_error and r.health != "ok":
            print(f"{'':<15} last error: {r.last_error[:150]}")
    return 0


async def _allowlist_refresh(args: argparse.Namespace) -> int:
    async with open_collector(get_settings()) as c:
        out = await refresh_allowlists(c)
    for origin, result in out.items():
        print(f"{origin:<12} {result if isinstance(result, str) else f'{result} entries'}")
    return 1 if any(isinstance(v, str) and not v.startswith("empty") for v in out.values()) else 0


async def _attack_load(args: argparse.Namespace) -> int:
    """Load one specific ATT&CK release (e.g. an older one, to see a diff)."""
    from threatlens.kb.attack import DowngradeError, load_release
    from threatlens.kb.base import KbContext

    url = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        f"{args.domain}/{args.domain}-{args.version}.json"
    )
    async with open_collector(get_settings()) as c:
        src = await c.source_row("mitre_attack")
        ctx = KbContext(c.sm, c.http, c.store, c.settings, c.now(), src.id, "mitre_attack", {}, c.sleep)
        try:
            res = await load_release(ctx, args.domain, args.version, url, force=args.force)
        except DowngradeError as e:
            print(str(e), file=sys.stderr)
            return 2
    print(
        f"loaded {res.note}: {res.items_total} objects, {res.items_new} added, {res.items_updated} modified"
    )
    return 0


# ── API keys ────────────────────────────────────────────────────────────────


async def _keys(args: argparse.Namespace) -> int:
    async with _session() as s, s.begin():
        if args.action == "create":
            try:
                _, key = await create_key(s, args.name, args.role, expires_days=args.expires_days)
            except ValueError as e:
                print(str(e), file=sys.stderr)
                return 2
            print(key)
            print("Store this key now; it is not shown again.", file=sys.stderr)
            return 0
        if args.action == "revoke":
            if not await revoke_key(s, args.name):
                print(f"no active key named {args.name!r}", file=sys.stderr)
                return 2
            print(f"revoked {args.name}")
            return 0
        rows = (await s.scalars(select(ApiKey).order_by(ApiKey.name))).all()
    print(f"{'name':<20} {'role':<8} {'prefix':<11} {'created':<17} {'last used':<17} state")
    for k in rows:
        state = (
            "revoked" if k.revoked_at else (f"expires {_when(k.expires_at)}" if k.expires_at else "active")
        )
        print(
            f"{k.name:<20} {k.role:<8} {k.prefix:<11} {_when(k.created_at):<17} "
            f"{_when(k.last_used_at):<17} {state}"
        )
    return 0


# ── extraction ──────────────────────────────────────────────────────────────


def _extract(args: argparse.Namespace) -> int:
    text = Path(args.file).read_text(encoding="utf-8", errors="replace") if args.file else sys.stdin.read()
    for r in extract(text, include_rejected=args.rejected):
        if isinstance(r, Observable):
            print(f"{r.type.value}\t{defang(r.value, r.type) if args.defang else r.value}")
        elif isinstance(r, Rejected):
            print(f"rejected\t{r.raw[:200]}\t{r.reason}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="threatlens", description="ThreatLens threat intelligence platform")
    parser.add_argument("--version", action="version", version=f"threatlens {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate-profile", help="validate the org profile and PIR files")
    v.add_argument("--profile", help="org profile YAML (default: TL_PROFILE_PATH)")
    v.add_argument("--pirs", help="PIR YAML (default: TL_PIRS_PATH)")
    v.set_defaults(func=_validate_profile)

    a = sub.add_parser("api", help="run the API server")
    a.add_argument("--host", default="127.0.0.1")
    a.add_argument("--port", type=int, default=8000)
    a.set_defaults(func=_api)

    i = sub.add_parser(
        "init-db", help="create tables in a SQLite database (local trials; Postgres uses Alembic)"
    )
    i.set_defaults(func=_run(_init_db))

    c = sub.add_parser("collect", help="run connectors now (the worker does this on a schedule)")
    c.add_argument("sources", nargs="*", metavar="SOURCE", help=f"one of: {', '.join(ALL_SOURCES)}")
    c.add_argument("--due", action="store_true", help="run only the sources whose next run time has passed")
    c.add_argument("--all", action="store_true", help="run every source")
    c.add_argument("--force", action="store_true", help="ignore the minimum gap and re-parse unchanged data")
    c.set_defaults(func=_run(_collect))

    s = sub.add_parser("sources", help="list sources and their health, or enable/disable one")
    s.add_argument("action", nargs="?", choices=["list", "enable", "disable"], default="list")
    s.add_argument("name", nargs="?")
    s.set_defaults(func=_run(_sources))

    ak = sub.add_parser("attack-load", help="load one specific ATT&CK release (the worker loads the newest)")
    ak.add_argument(
        "--domain", choices=["enterprise-attack", "mobile-attack", "ics-attack"], default="enterprise-attack"
    )
    ak.add_argument("--version", required=True, help="e.g. 19.1")
    ak.add_argument("--force", action="store_true", help="allow loading a release older than the current one")
    ak.set_defaults(func=_run(_attack_load))

    al = sub.add_parser(
        "allowlist-refresh", help="refresh Tranco, CDN ranges and org-profile allowlist entries"
    )
    al.set_defaults(func=_run(_allowlist_refresh))

    k = sub.add_parser("keys", help="manage API keys")
    k.add_argument("action", choices=["create", "list", "revoke"])
    k.add_argument("name", nargs="?")
    k.add_argument("--role", choices=list(ROLE_RANK), default="viewer")
    k.add_argument("--expires-days", type=int)
    k.set_defaults(func=_run(_keys))

    e = sub.add_parser("extract", help="extract IOCs from a file or stdin (nothing is stored)")
    e.add_argument("file", nargs="?")
    e.add_argument("--defang", action="store_true", help="print values defanged")
    e.add_argument("--rejected", action="store_true", help="also print rejected candidates and why")
    e.set_defaults(func=_extract)

    args = parser.parse_args(argv)
    if args.command == "sources" and args.action != "list" and not args.name:
        parser.error(f"sources {args.action} needs a source name")
    if args.command == "keys" and args.action != "list" and not args.name:
        parser.error(f"keys {args.action} needs a key name")
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
