"""HTTP surface (ARCHITECTURE §3). The app is built from a Node, so deployments inject their own seams."""
from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Awaitable, Callable

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request

from pydantic import ValidationError

from .models import ClaimIn
from .store import key_hash
from .service import Node
from .verifiers import REGISTRY, load_builtin


CLAIMS_PER_MIN_PER_KEY = 60
READS_PER_MIN_PER_IP = 120
LIST_CLAIMS_DEFAULT_LIMIT = 50
LIST_CLAIMS_MAX_LIMIT = 200
MAX_BODY_BYTES = 64 * 1024


def _encode_cursor(created_at: datetime, claim_id: str) -> str:
    raw = f"{created_at.isoformat()}|{claim_id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        ts_str, sep, claim_id = raw.partition("|")
        if not sep or not claim_id:
            raise ValueError("malformed cursor")
        return datetime.fromisoformat(ts_str), claim_id
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="invalid cursor") from None

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


EDGE_IP_HEADER = "x-qed-viewer-ip"
EDGE_SECRET_HEADER = "x-qed-edge"


def client_ip(request: Request) -> str:
    """The caller's IP as AWS saw it. The Lambda Web Adapter forwards the Function URL request context in
    `x-amzn-request-context`, and `http.sourceIp` there is set by AWS. X-Forwarded-For is NOT trusted, because the caller
    controls it and could rotate it to dodge the per-IP limit.

    Behind a CDN (e.g. CloudFront), `sourceIp` is the edge, not the caller. If `POAW_TRUSTED_EDGE_SECRET` is set, an
    `x-qed-viewer-ip` header is trusted ONLY when the request also carries `x-qed-edge` equal to that secret (the edge adds
    it; a direct caller can't know it), and the edge must overwrite any client-sent `x-qed-viewer-ip`."""
    import hmac
    import json
    import os
    edge_secret = os.environ.get("POAW_TRUSTED_EDGE_SECRET", "")
    if edge_secret:
        presented = request.headers.get(EDGE_SECRET_HEADER, "")
        viewer = request.headers.get(EDGE_IP_HEADER, "").strip()
        if viewer and presented and hmac.compare_digest(presented.encode(), edge_secret.encode()):
            return viewer[:64]
    ctx = request.headers.get("x-amzn-request-context")
    if ctx:
        try:
            ip = json.loads(ctx).get("http", {}).get("sourceIp")
            if ip:
                return str(ip)[:64]
        except (ValueError, AttributeError):
            pass
    return (request.client.host if request.client else "unknown")[:64]


def create_app(get_node: Callable[[], Awaitable[Node]], *, log_id: str, tick_enabled: Callable[[], bool],
               after_tick: Callable[[], Awaitable[dict]] | None = None,
               keyset: Callable[[], Awaitable[dict]] | None = None,
               admission: Callable[[str, ClaimIn], Awaitable[str | None]] | None = None) -> FastAPI:
    app = FastAPI(title="poaw-node", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def harden(request: Request, call_next):
        # SECURITY F3: cap the body before anything parses it.
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            from fastapi.responses import JSONResponse
            resp = JSONResponse({"detail": "request body too large"}, status_code=413)
        else:
            resp = await call_next(request)
        # SECURITY F7: headers on every response, and no caching of anything authenticated.
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        if request.headers.get("authorization"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def limited() -> HTTPException:
        return HTTPException(status_code=429, detail="rate limit exceeded", headers={"Retry-After": "5"})

    async def node() -> Node:
        return await get_node()

    async def workspace(authorization: str = Header(default=""), n: Node = Depends(node)) -> str:
        scheme, _, key = authorization.partition(" ")
        ws = await n.store.workspace_for_key(key) if scheme.lower() == "bearer" and key else None
        if not ws:
            raise HTTPException(status_code=401, detail="invalid or missing API key")
        if not await n.store.rate_take(f"key:{key_hash(key)}", per_minute=CLAIMS_PER_MIN_PER_KEY):
            raise limited()
        return ws

    @app.get("/.well-known/poaw-keys.json")
    async def poaw_keys() -> dict:
        # SPEC §5.2 + §8.4: the receipt keys, and the anchor attesters and schemas a checker must accept. Public by design.
        if keyset is None:
            raise HTTPException(status_code=404)
        return await keyset()

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    @app.post("/v1/claims", status_code=202)
    async def submit(c: ClaimIn, ws: str = Depends(workspace), n: Node = Depends(node)) -> dict:
        # A deployment's admission policy (e.g. a plan quota) may refuse a NEW claim up front. A refused claim creates
        # nothing and gets no receipt. Nothing here can change the verdict of a claim that was accepted.
        if admission is not None and (refusal := await admission(ws, c)):
            raise HTTPException(status_code=402, detail=refusal)
        try:
            claim, created = await n.submit(ws, c)
        except (ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=f"invalid params for {c.action}: {_brief(exc)}") from None
        receipt_id = None
        if created:  # first check inline, so fast destinations decide without waiting for the tick
            attempts = await n.store.bump_attempt(claim.id)
            receipt_id = await n.check(claim, attempts=attempts)
        status = await n.store.claim_status(ws, claim.id)
        return {"claim_id": claim.id, "created": created, **(status or {}), "receipt_id": receipt_id or (status or {}).get("receipt_id")}

    @app.get("/v1/claims")
    async def list_claims(limit: int = Query(LIST_CLAIMS_DEFAULT_LIMIT, ge=1, le=LIST_CLAIMS_MAX_LIMIT),
                          cursor: str | None = None, agent_id: str | None = None, action: str | None = None,
                          verdict: str | None = None, state: str | None = None, ws: str = Depends(workspace),
                          n: Node = Depends(node)) -> dict:
        # Newest first, keyset-paginated on (created_at desc, id desc). `limit` items are returned; one extra row is
        # fetched to tell whether a next page exists, so `next_cursor` is only set when it does (SPEC parity: each
        # item is the exact dict shape claim_status returns).
        before = _decode_cursor(cursor) if cursor else None
        rows = await n.store.list_claims(ws, limit=limit + 1, before=before, agent_id=agent_id, action=action,
                                         verdict=verdict, state=state)
        more = len(rows) > limit
        rows = rows[:limit]
        claims = [{"claim_id": r["claim_id"], "state": r["state"], "attempts": r["attempts"],
                   "receipt_id": r["receipt_id"], "verdict": r["verdict"]} for r in rows]
        next_cursor = _encode_cursor(rows[-1]["created_at"], rows[-1]["claim_id"]) if more and rows else None
        return {"claims": claims, "next_cursor": next_cursor}

    @app.get("/v1/connections")
    async def list_connections(ws: str = Depends(workspace), n: Node = Depends(node)) -> dict:
        # What this workspace can have verified: each active connection with the verifier actions its provider
        # supports here, plus the actions that need no connection. Deliberately no account identifiers (the key holder
        # is usually an agent; the console shows names to signed-in members). Lane connections-list-api.
        load_builtin()
        by_provider: dict[str, list[str]] = {}
        public: list[str] = []
        for action, spec in REGISTRY.items():
            (by_provider.setdefault(spec.provider, []) if spec.provider else public).append(action)
        rows = await n.store.list_connections(ws)
        return {
            "connections": [{"id": r["id"], "provider": r["provider"], "scopes": sorted(r["scopes"] or []),
                             "connected_at": r["created_at"].isoformat().replace("+00:00", "Z"),
                             "actions": sorted(by_provider.get(r["provider"], []))} for r in rows],
            "public_actions": sorted(public),
        }

    @app.get("/v1/claims/{claim_id}")
    async def claim_status(claim_id: str, ws: str = Depends(workspace), n: Node = Depends(node)) -> dict:
        s = await n.store.claim_status(ws, claim_id)
        if not s:
            raise HTTPException(status_code=404, detail="claim not found")
        return s

    @app.get("/v1/receipts/{receipt_id}")
    async def receipt(receipt_id: str, request: Request, n: Node = Depends(node)) -> dict:
        # Receipts are designed to be shared and checked by anyone, so reading one needs no key (SPEC §1) — an
        # Authorization header is never required. But when one IS presented and resolves to a real workspace, the
        # read is rate-limited per KEY instead of per IP (many agents sharing an egress IP shouldn't share a budget).
        # An invalid/unknown key falls back to the IP bucket rather than failing the read. Deliberately a SEPARATE
        # bucket namespace (truncated hash) from the `key:<full hash>` bucket `workspace()` uses for writes, since
        # the two buckets carry different per-minute rates and rate_take's refill math assumes one rate per bucket.
        bucket = f"ip:{client_ip(request)}"
        scheme, _, key = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() == "bearer" and key and await n.store.workspace_for_key(key):
            bucket = f"key:{key_hash(key)[:16]}"
        if not await n.store.rate_take(bucket, per_minute=READS_PER_MIN_PER_IP):
            raise limited()
        r = await n.store.receipt_with_proof(receipt_id, log_id)
        if not r:
            raise HTTPException(status_code=404, detail="receipt not found")
        return r

    @app.post("/events")
    async def events(request: Request, n: Node = Depends(node)) -> dict:
        if not tick_enabled():
            raise HTTPException(status_code=404)
        result = await n.tick()
        if after_tick is not None:  # e.g. the anchorer. It runs after claims are decided, so the anchored root includes them
            result.update(await after_tick())
        return result

    return app


def _brief(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return "; ".join(f"{'.'.join(map(str, e['loc'])) or 'params'}: {e['msg']}" for e in exc.errors()[:5])
    return str(exc)[:200]
