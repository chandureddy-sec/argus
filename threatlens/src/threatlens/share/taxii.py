"""A read-only TAXII 2.1 server (OASIS TAXII 2.1, ADR 0019).

Collections are tiers of TLP and confidence. Each is a fixed set of sharing
rules (``share.select.Rules``) over the live indicator store, so nothing is
copied or published: a collection is always current, and the rules that keep
TLP:RED, over-clearance and non-redistributable intelligence at home apply
here exactly as everywhere else.

* Discovery ``/taxii2/``, one API root ``/taxii2/api/``.
* ``objects`` and ``manifest`` support ``added_after``, ``limit``, ``next``,
  ``match[id]``, ``match[type]``, ``match[version]`` and
  ``match[spec_version]``, with ``X-TAXII-Date-Added-First/Last``.
* Authentication: an API key (``X-API-Key``, ``Authorization: Bearer`` or
  HTTP Basic with the key as the password). A reader only sees collections at
  or below their TLP clearance; others answer 404, as if they didn't exist.
* Only the latest version of each object is kept, so every ``match[version]``
  value returns that one version.
* Writing (``POST objects``) is refused: consumers pull, they don't push.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from threatlens import tlp as tlp_rules
from threatlens.auth import Principal, require
from threatlens.share import select as sel
from threatlens.share import stix
from threatlens.share.select import aware

MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"
EPOCH = datetime(2022, 10, 1, tzinfo=UTC)  # date_added of the static objects
_NS = uuid.UUID("5c0b7e93-2c5d-4f8a-8f1b-1a3c9d6e7f20")


@dataclass(frozen=True)
class Collection:
    key: str
    title: str
    description: str
    rules: sel.Rules

    @property
    def id(self) -> str:
        return str(uuid.uuid5(_NS, self.key))


COLLECTIONS: tuple[Collection, ...] = (
    Collection("clear-high", "TLP:CLEAR, high confidence",
               "Shareable indicators marked TLP:CLEAR scoring 60 or more (block-worthy).",
               sel.Rules("TLP:CLEAR", 60.0)),
    Collection("clear-all", "TLP:CLEAR, monitor and up",
               "Shareable indicators marked TLP:CLEAR scoring 30 or more (watch-list).",
               sel.Rules("TLP:CLEAR", 30.0)),
    Collection("green-high", "TLP:GREEN, high confidence",
               "TLP:CLEAR and TLP:GREEN indicators scoring 60 or more, for our community.",
               sel.Rules("TLP:GREEN", 60.0)),
    Collection("amber-high", "TLP:AMBER, high confidence",
               "Up to TLP:AMBER, scoring 60 or more. Readers need AMBER clearance.",
               sel.Rules("TLP:AMBER", 60.0)),
)  # fmt: skip

router = APIRouter(prefix="/taxii2", include_in_schema=False)
_viewer = require("viewer")


class TaxiiError(Exception):
    def __init__(self, status: int, title: str, description: str = "") -> None:
        self.status, self.title, self.description = status, title, description


def error_response(e: TaxiiError) -> JSONResponse:
    body = {"title": e.title, "http_status": str(e.status)}
    if e.description:
        body["description"] = e.description
    headers = {"WWW-Authenticate": 'Basic realm="TAXII"'} if e.status == 401 else None
    return JSONResponse(body, status_code=e.status, media_type=MEDIA, headers=headers)


def _ok(body: Any, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(body, media_type=MEDIA, headers=headers)


def _check_accept(request: Request) -> None:
    accept = request.headers.get("accept", "*/*").replace(" ", "").lower()
    ok = ("application/taxii+json" in accept and ("version=2.1" in accept or ";version" not in accept)) or (
        "*/*" in accept or "application/*" in accept
    )
    if not ok:
        raise TaxiiError(406, "Not acceptable", f"this server speaks {MEDIA}")


async def _who(request: Request) -> Principal:
    _check_accept(request)
    try:
        return await _viewer(request)
    except HTTPException as e:
        raise TaxiiError(
            e.status_code, "Unauthorized" if e.status_code == 401 else "Refused", str(e.detail)
        ) from e


def _visible(who: Principal) -> list[Collection]:
    return [c for c in COLLECTIONS if tlp_rules.may_read(who.clearance, c.rules.max_tlp)]


def _collection(who: Principal, cid: str) -> Collection:
    for c in _visible(who):
        if c.id == cid:
            return c
    raise TaxiiError(404, "Collection not found", "no such collection, or it is above your clearance")


def _info(c: Collection) -> dict[str, Any]:
    return {"id": c.id, "title": c.title, "description": c.description, "can_read": True, "can_write": False,
            "media_types": [STIX_MEDIA]}  # fmt: skip


def _ts(v: datetime) -> str:
    """date_added with microseconds, so ``added_after`` a returned value
    excludes that object (TAXII 2.1 3.4: precision matters for paging)."""
    return aware(v).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _encode_next(at: datetime, ind_id: int) -> str:
    return base64.urlsafe_b64encode(f"{aware(at).isoformat()}|{ind_id}".encode()).decode().rstrip("=")


def _decode_next(token: str) -> tuple[datetime, int]:
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode()
        at, _, ind_id = raw.partition("|")
        return aware(datetime.fromisoformat(at)), int(ind_id)
    except (ValueError, binascii.Error, UnicodeDecodeError) as e:
        raise TaxiiError(400, "Bad next", "next must be a value this server returned") from e


def _parse_added_after(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        return aware(datetime.fromisoformat(v.replace("Z", "+00:00")))
    except ValueError as e:
        raise TaxiiError(400, "Bad added_after", "added_after must be an RFC 3339 timestamp") from e


async def _objects(
    request: Request,
    c: Collection,
    *,
    added_after: str | None,
    limit: int | None,
    next_: str | None,
    ids: list[str],
    types: list[str],
    spec_versions: list[str],
) -> tuple[list[tuple[datetime, dict[str, Any]]], bool, str | None]:
    """(date_added, object) pairs for one page, whether there is more, and the next token."""
    if spec_versions and "2.1" not in spec_versions:
        return [], False, None
    settings = request.app.state.settings
    size = min(limit or settings.taxii_page_size, settings.taxii_page_size)
    after = _decode_next(next_) if next_ else None
    since = _parse_added_after(added_after)
    want_static = after is None and (since is None or since < EPOCH)
    ind_ids = [i for i in ids if i.startswith("indicator--")]
    async with request.app.state.sessionmaker() as s:
        rows = await sel.page(s, c.rules, after=after, added_after=since, limit=size + 1, ids=ind_ids or None)
        more = len(rows) > size
        rows = rows[:size]
        ident = stix.identity(settings.org_identity)
        out: list[tuple[datetime, dict[str, Any]]] = []
        if want_static:
            out.append((EPOCH, ident))
            out += [(EPOCH, stix.marking(lv)) for lv in sel.levels(c.rules.max_tlp)]
        dates = {r.ind.stix_id: aware(r.ind.updated_at) for r in rows}
        out += [(aware(r.ind.updated_at), stix.indicator(r, ident["id"])) for r in rows]
        sdos, rels = await stix.related(s, rows)
        for rel in rels:
            out.append((dates[rel["source_ref"]], rel))
        first_for: dict[str, datetime] = {}
        for rel in rels:
            d = dates[rel["source_ref"]]
            first_for[rel["target_ref"]] = min(first_for.get(rel["target_ref"], d), d)
        out += [(first_for.get(o["id"], EPOCH), o) for o in sdos]
    if ids:
        out = [(d, o) for d, o in out if o["id"] in ids]
    if types:
        out = [(d, o) for d, o in out if o["type"] in types]
    out.sort(key=lambda x: x[0])
    nxt = _encode_next(rows[-1].ind.updated_at, rows[-1].ind.id) if more and rows else None
    return out, more, nxt


def _date_headers(pairs: list[tuple[datetime, dict[str, Any]]]) -> dict[str, str]:
    if not pairs:
        return {}
    return {"X-TAXII-Date-Added-First": _ts(pairs[0][0]), "X-TAXII-Date-Added-Last": _ts(pairs[-1][0])}


def _filters(request: Request) -> tuple[list[str], list[str], list[str]]:
    q = request.query_params

    def many(name: str) -> list[str]:
        return [v.strip() for raw in q.getlist(name) for v in raw.split(",") if v.strip()]

    return many("match[id]"), many("match[type]"), many("match[spec_version]")


# ── endpoints ────────────────────────────────────────────────────────────────


@router.get("/")
async def discovery(request: Request) -> JSONResponse:
    try:
        await _who(request)
    except TaxiiError as e:
        return error_response(e)
    s = request.app.state.settings
    base = s.public_url.rstrip("/")
    return _ok({
        "title": f"{s.org_identity} TAXII",
        "description": "Threat intelligence shared by Argus: indicators by TLP and confidence tier.",
        "default": f"{base}/taxii2/api/",
        "api_roots": [f"{base}/taxii2/api/"],
    })  # fmt: skip


@router.get("/api/")
async def api_root(request: Request) -> JSONResponse:
    try:
        await _who(request)
    except TaxiiError as e:
        return error_response(e)
    s = request.app.state.settings
    return _ok({"title": f"{s.org_identity} indicators", "versions": [MEDIA], "max_content_length": 0,
                "description": "Read-only. Collections are TLP and confidence tiers."})  # fmt: skip


@router.get("/api/collections/")
async def collections(request: Request) -> JSONResponse:
    try:
        who = await _who(request)
    except TaxiiError as e:
        return error_response(e)
    return _ok({"collections": [_info(c) for c in _visible(who)]})


@router.get("/api/collections/{cid}/")
async def collection(request: Request, cid: str) -> JSONResponse:
    try:
        return _ok(_info(_collection(await _who(request), cid)))
    except TaxiiError as e:
        return error_response(e)


@router.get("/api/collections/{cid}/objects/")
async def get_objects(
    request: Request,
    cid: str,
    added_after: str | None = None,
    limit: Annotated[int | None, Query(ge=1, le=10_000)] = None,
    next: str | None = None,  # noqa: A002 - TAXII's parameter name
) -> JSONResponse:
    try:
        c = _collection(await _who(request), cid)
        ids, types, specs = _filters(request)
        pairs, more, nxt = await _objects(
            request,
            c,
            added_after=added_after,
            limit=limit,
            next_=next,
            ids=ids,
            types=types,
            spec_versions=specs,
        )
    except TaxiiError as e:
        return error_response(e)
    body: dict[str, Any] = {"more": more}
    if nxt:
        body["next"] = nxt
    if pairs:
        body["objects"] = [o for _, o in pairs]
    return _ok(body, _date_headers(pairs))


@router.get("/api/collections/{cid}/objects/{object_id}/")
async def get_object(request: Request, cid: str, object_id: str) -> JSONResponse:
    try:
        c = _collection(await _who(request), cid)
        _, types, specs = _filters(request)
        pairs, _, _ = await _objects(
            request,
            c,
            added_after=None,
            limit=None,
            next_=None,
            ids=[object_id],
            types=types,
            spec_versions=specs,
        )
        if not pairs:
            raise TaxiiError(404, "Object not found", "no such object in this collection")
    except TaxiiError as e:
        return error_response(e)
    return _ok({"more": False, "objects": [o for _, o in pairs]}, _date_headers(pairs))


@router.get("/api/collections/{cid}/objects/{object_id}/versions/")
async def get_versions(request: Request, cid: str, object_id: str) -> JSONResponse:
    try:
        c = _collection(await _who(request), cid)
        pairs, _, _ = await _objects(
            request, c, added_after=None, limit=None, next_=None, ids=[object_id], types=[], spec_versions=[]
        )
        if not pairs:
            raise TaxiiError(404, "Object not found", "no such object in this collection")
    except TaxiiError as e:
        return error_response(e)
    return _ok({"more": False, "versions": [o.get("modified") or o.get("created") for _, o in pairs]},
               _date_headers(pairs))  # fmt: skip


@router.get("/api/collections/{cid}/manifest/")
async def manifest(
    request: Request,
    cid: str,
    added_after: str | None = None,
    limit: Annotated[int | None, Query(ge=1, le=10_000)] = None,
    next: str | None = None,  # noqa: A002 - TAXII's parameter name
) -> JSONResponse:
    try:
        c = _collection(await _who(request), cid)
        ids, types, specs = _filters(request)
        pairs, more, nxt = await _objects(
            request,
            c,
            added_after=added_after,
            limit=limit,
            next_=next,
            ids=ids,
            types=types,
            spec_versions=specs,
        )
    except TaxiiError as e:
        return error_response(e)
    body: dict[str, Any] = {"more": more}
    if nxt:
        body["next"] = nxt
    if pairs:
        body["objects"] = [
            {"id": o["id"], "date_added": _ts(d), "version": o.get("modified") or o.get("created"),
             "media_type": STIX_MEDIA}
            for d, o in pairs
        ]  # fmt: skip
    return _ok(body, _date_headers(pairs))


@router.post("/api/collections/{cid}/objects/")
async def add_objects(request: Request, cid: str) -> JSONResponse:
    try:
        _collection(await _who(request), cid)
    except TaxiiError as e:
        return error_response(e)
    return error_response(TaxiiError(403, "Read-only collection", "this server does not accept objects"))


@router.delete("/api/collections/{cid}/objects/{object_id}/")
async def delete_object(request: Request, cid: str, object_id: str) -> JSONResponse:
    try:
        _collection(await _who(request), cid)
    except TaxiiError as e:
        return error_response(e)
    return error_response(TaxiiError(403, "Read-only collection", "objects can't be deleted here"))


@router.get("/api/status/{status_id}/")
async def status(request: Request, status_id: str) -> JSONResponse:
    try:
        await _who(request)
    except TaxiiError as e:
        return error_response(e)
    return error_response(
        TaxiiError(404, "Status not found", "this server accepts no writes, so has no status")
    )
