"""HTTP surface (ARCHITECTURE §3). The app is built from a Node, so deployments inject their own seams."""
from __future__ import annotations

from typing import Awaitable, Callable

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from pydantic import ValidationError

from .models import ClaimIn
from .store import key_hash
from .service import Node


CLAIMS_PER_MIN_PER_KEY = 60
READS_PER_MIN_PER_IP = 120
MAX_BODY_BYTES = 64 * 1024

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def client_ip(request: Request) -> str:
    """The caller's IP as AWS saw it. The Lambda Web Adapter forwards the Function URL request context in
    `x-amzn-request-context`, and `http.sourceIp` there is set by AWS. X-Forwarded-For is NOT trusted, because the caller
    controls it and could rotate it to dodge the per-IP limit."""
    import json
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

    @app.get("/v1/claims/{claim_id}")
    async def claim_status(claim_id: str, ws: str = Depends(workspace), n: Node = Depends(node)) -> dict:
        s = await n.store.claim_status(ws, claim_id)
        if not s:
            raise HTTPException(status_code=404, detail="claim not found")
        return s

    @app.get("/v1/receipts/{receipt_id}")
    async def receipt(receipt_id: str, request: Request, n: Node = Depends(node)) -> dict:
        # Receipts are designed to be shared and checked by anyone, so reading one needs no key (SPEC §1).
        if not await n.store.rate_take(f"ip:{client_ip(request)}", per_minute=READS_PER_MIN_PER_IP):
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
