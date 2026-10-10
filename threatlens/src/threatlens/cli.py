"""Command-line entry point: ``threatlens <command>``."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
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
from threatlens.enrich.service import EnrichmentService
from threatlens.ioc.defang import defang
from threatlens.ioc.extract import defang_text, extract
from threatlens.ioc.normalize import guess, normalize
from threatlens.ioc.types import IOCType, Observable, Rejected
from threatlens.jobs import collect_due, open_collector, refresh_allowlists
from threatlens.kb import KB_REGISTRY
from threatlens.models import TLP_LEVELS, ApiKey, AuditLog, Source, User
from threatlens.profile import ProfileError, load_pirs, load_profile
from threatlens.settings import get_settings
from threatlens.users import UserError, create_user, set_disabled, set_password, set_role

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


@asynccontextmanager
async def _enrichment() -> AsyncIterator[EnrichmentService]:
    """The enrichment service with the stack's shared quota book (Redis)."""
    from redis.asyncio import Redis

    from threatlens.enrich.quota import RedisQuotaStore
    from threatlens.enrich.service import enrichment_http

    s = get_settings()
    engine = make_engine(s.database_url.get_secret_value())
    redis: Redis = Redis.from_url(s.redis_url.get_secret_value())
    http = enrichment_http(s)
    try:
        yield EnrichmentService(make_sessionmaker(engine), http, RedisQuotaStore(redis), s)
    finally:
        await http.aclose()
        await redis.aclose()
        await engine.dispose()


async def _lookup(args: argparse.Namespace) -> int:
    r = normalize(IOCType(args.type), args.value) if args.type else guess(args.value)
    if not isinstance(r, Observable):
        print(f"rejected: {r.reason}", file=sys.stderr)
        return 2
    async with _enrichment() as svc:
        res = await svc.lookup(r, actor="cli", active=args.active, refresh=args.refresh, tlp=args.tlp)
    if args.json:
        print(json.dumps(res, default=str, indent=2))
        return 0
    q = res["query"]
    verdict = f"{res['verdict'].upper()} score {res['score']} -> {res['recommended_action']}"
    print(f"{q['defanged']} ({q['type']}): {verdict}")
    print(f"  {res['recommended_action_text']}")
    for e in res["evidence"]:
        mark = f"{e['kind']} {e['weight']}" if e["kind"] != "info" else "info"
        print(f"  [{mark:>13}] {e['source']}: {defang_text(e['text'])}")
    for e in res["enrichments"]:
        why = e.get("skipped_reason") or e.get("error") or ("found" if e.get("found") else "not found")
        print(f"  {e['enricher']:<14} {e['status']:<8} {why}")
    print(f"  ({res['took_ms']} ms{', partial' if res['partial'] else ''})")
    return 0


async def _enrich_backlog(args: argparse.Namespace) -> int:
    async with _enrichment() as svc:
        out = await svc.enrich_backlog(args.limit)
    print(f"{out['candidates']} IP indicators checked, {out['enriched']} answers stored")
    return 0


async def _import_reconx(args: argparse.Namespace) -> int:
    """Import ReconX scan reports (JSON) as own assets and observed tech stack."""
    import hashlib
    import json as _json

    from threatlens.assets import ImportFormatError, import_reconx

    engine = make_engine(get_settings().database_url.get_secret_value())
    failed = 0
    try:
        sm = make_sessionmaker(engine)
        for path in args.files:
            body = await asyncio.to_thread(Path(path).read_bytes)
            try:
                r = await import_reconx(sm, _json.loads(body), hashlib.sha256(body).hexdigest(), "cli")
            except (ValueError, ImportFormatError) as e:
                print(f"{path}: not imported: {e}", file=sys.stderr)
                failed += 1
                continue
            if r.duplicate:
                print(f"{path}: already imported (import #{r.import_id})")
                continue
            print(
                f"{path}: {r.target}: {r.hosts} hosts, {r.ips} IPs, {r.products} products; "
                f"{r.new_assets} new, {r.updated_assets} updated, {len(r.rejected)} not imported"
            )
    finally:
        await engine.dispose()
    return 1 if failed else 0


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


# ── UI accounts ─────────────────────────────────────────────────────────────


def _read_password(from_stdin: bool) -> str:
    """One line from stdin (used by ``tl user``), else an interactive prompt typed twice."""
    if from_stdin:
        return sys.stdin.readline().lstrip("\ufeff").rstrip("\r\n")
    first = getpass.getpass("Password: ")
    if getpass.getpass("Repeat password: ") != first:
        raise UserError("the passwords don't match")
    return first


async def _users(args: argparse.Namespace) -> int:
    if args.action != "list" and not args.name:
        print(f"users {args.action} needs a NAME", file=sys.stderr)
        return 2
    if args.action == "role" and not args.role:
        print("users role needs --role viewer|analyst|admin", file=sys.stderr)
        return 2
    try:
        password = _read_password(args.password_stdin) if args.action in ("create", "passwd") else ""
        async with _session() as s, s.begin():
            if args.action == "create":
                row = await create_user(s, args.name, password, args.role or "viewer")
                print(f"created {row.name} ({row.role}); sign in at /ui/login")
            elif args.action == "passwd":
                row = await set_password(s, args.name, password)
                print(f"password changed for {row.name}; their other sessions are signed out")
            elif args.action == "role":
                row = await set_role(s, args.name, args.role)
                print(f"{row.name} is now {row.role}")
            elif args.action in ("disable", "enable"):
                row = await set_disabled(s, args.name, args.action == "disable")
                print(f"{row.name} {args.action}d")
            else:
                rows = (await s.scalars(select(User).order_by(User.login))).all()
                print(f"{'name':<24} {'role':<8} {'created':<17} {'last sign-in':<17} state")
                for u in rows:
                    print(
                        f"{u.name:<24} {u.role:<8} {_when(u.created_at):<17} "
                        f"{_when(u.last_login_at):<17} {'disabled' if u.disabled_at else 'active'}"
                    )
    except UserError as e:
        print(str(e), file=sys.stderr)
        return 2
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

    k = sub.add_parser("keys", help="manage API keys (for programs such as ReconX)")
    k.add_argument("action", choices=["create", "list", "revoke"])
    k.add_argument("name", nargs="?")
    k.add_argument("--role", choices=list(ROLE_RANK), default="viewer")
    k.add_argument("--expires-days", type=int)
    k.set_defaults(func=_run(_keys))

    us = sub.add_parser("users", help="manage analyst UI accounts (username + password)")
    us.add_argument("action", choices=["create", "passwd", "role", "disable", "enable", "list"])
    us.add_argument("name", nargs="?", help='username; quote it if it has spaces: "chandu reddy"')
    us.add_argument("--role", choices=list(ROLE_RANK), help="create: default viewer; role: required")
    us.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    us.set_defaults(func=_run(_users))

    ir = sub.add_parser("import-reconx", help="import ReconX scan reports (JSON) as own assets")
    ir.add_argument("files", nargs="+", help="reports/recon_<target>_<time>.json from ReconX")
    ir.set_defaults(func=_run(_import_reconx))

    lk = sub.add_parser("lookup", help="enrich one value and print the verdict and evidence")
    lk.add_argument("value", help="IP, domain, URL, hash or email (defanged input is fine)")
    lk.add_argument("--type", choices=[t.value for t in IOCType if t != IOCType.CVE], help="default: guess")
    lk.add_argument("--active", action="store_true", help="also run active enrichers (DNS); audited")
    lk.add_argument("--refresh", action="store_true", help="ignore cached answers")
    lk.add_argument("--tlp", choices=list(TLP_LEVELS), help="TLP of the value (default: stored, else CLEAR)")
    lk.add_argument("--json", action="store_true", help="print the full result as JSON")
    lk.set_defaults(func=_run(_lookup))

    eb = sub.add_parser("enrich-backlog", help="enrich new active IP indicators now (ASN, location)")
    eb.add_argument("--limit", type=int, default=100)
    eb.set_defaults(func=_run(_enrich_backlog))

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
