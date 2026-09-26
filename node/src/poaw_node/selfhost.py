"""Run a poaw node on your own machine (configuration by environment variables).

  POAW_DATABASE_URL       postgresql://… (required). Apply the schema first: `poaw-node init-db`.
  POAW_SIGNING_KEY_FILE   a file holding the 32-byte Ed25519 seed that signs receipts (required; `poaw-node keygen`).
  POAW_ISSUER_NAME        shown in receipts (default "poaw-node").
  POAW_LOG_NAME           names this node's log; its log_id is SHA-256 of it (default "poaw-selfhost-log-v1").
  POAW_PUBLIC_BASE        the URL this node is reachable at, used in alert links (optional).
  POAW_TICK_SECONDS       how often queued claims are re-checked (default 30).
  POAW_GITHUB_TOKEN       a read-only GitHub token for the github.* verifiers (optional; without it they're unverifiable).
  POAW_ANCHOR_CHAIN       e.g. "eip155:84532" to anchor the log on Base Sepolia (optional; needs `poaw-node[anchor]`).
  POAW_ANCHOR_KEY_FILE    a file holding the 32-byte secp256k1 key that pays for anchors (hex or raw).
  POAW_ANCHOR_RPC         the chain's JSON-RPC URL (default: the public endpoint for that chain).
  POAW_ANCHOR_INTERVAL_S / _DAILY_MAX_WEI / _MIN_BALANCE_WEI   anchoring cadence and spend limits.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import asyncpg
import httpx
from fastapi import FastAPI

import poaw_core

from .app import create_app
from .interfaces import EnvConnections, LocalSigner, StdoutAlerts
from .service import Node
from .store import Store

SCHEMA = Path(__file__).with_name("schema.sql")


def _require(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        sys.exit(f"{name} is not set (see `poaw-node --help`)")
    return v


def log_id() -> str:
    return poaw_core.b64u(poaw_core.sha256(os.environ.get("POAW_LOG_NAME", "poaw-selfhost-log-v1").encode()))


def read_seed(path: str) -> bytes:
    raw = Path(path).read_bytes()
    txt = raw.strip()
    if len(raw) == 32:
        return raw
    try:
        b = bytes.fromhex(txt.decode())
    except ValueError:
        b = b""
    if len(b) != 32:
        sys.exit(f"{path} must hold a 32-byte key (raw bytes or 64 hex characters)")
    return b


async def pool() -> asyncpg.Pool:
    return await asyncpg.create_pool(_require("POAW_DATABASE_URL"), min_size=0, max_size=5)


async def init_db() -> str:
    conn = await asyncpg.connect(_require("POAW_DATABASE_URL"))
    try:
        if await conn.fetchval("select to_regclass('qed.workspaces') is not null"):
            return "already initialised; nothing changed"
        async with conn.transaction():
            await conn.execute(SCHEMA.read_text())
        return "schema applied"
    finally:
        await conn.close()


def build_app() -> FastAPI:
    state: dict = {}

    async def get_node() -> Node:
        if "node" not in state:
            p = await pool()
            state["pool"], state["http"] = p, httpx.AsyncClient()
            state["node"] = Node(store=Store(p), signer=LocalSigner(read_seed(_require("POAW_SIGNING_KEY_FILE"))),
                                 connections=EnvConnections(), alerts=StdoutAlerts(), http=state["http"],
                                 issuer_name=os.environ.get("POAW_ISSUER_NAME", "poaw-node"))
            state["anchorer"] = _anchorer(p, state["node"])
        return state["node"]

    async def keyset() -> dict:
        n = await get_node()
        a = state.get("anchorer")
        out = {"issuer": n.issuer_name, "log_id": log_id(),
               "keys": [{"key_id": n.key_id, "public_key": poaw_core.b64u(n.signer.public_key()),
                         "valid_from": os.environ.get("POAW_KEY_VALID_FROM", "2026-01-01T00:00:00Z"), "revoked_at": None}],
               "anchor_addresses": [a.signer.address] if a else [], "anchor_schemas": []}
        if a:
            from .anchoring import eth
            out["anchor_schemas"] = ["0x" + eth.schema_uid(eth.ANCHOR_SCHEMA).hex()]
        return out

    async def loop() -> None:
        every = float(os.environ.get("POAW_TICK_SECONDS", "30"))
        while True:
            try:
                n = await get_node()
                result = await n.tick()
                if state.get("anchorer"):
                    result.update(await state["anchorer"].run())
                print(json.dumps({"event": "tick", "at": datetime.now(timezone.utc).isoformat(), **result}, default=str), flush=True)
            except Exception as exc:  # noqa: BLE001 - one bad tick must not stop the node
                print(json.dumps({"event": "tick.error", "error": type(exc).__name__, "detail": str(exc)[:300]}), flush=True)
            await asyncio.sleep(every)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        task = asyncio.create_task(loop())
        try:
            yield
        finally:
            task.cancel()
            if "pool" in state:
                await state["pool"].close()

    inner = create_app(get_node, log_id=log_id(), tick_enabled=lambda: False, keyset=keyset)
    outer = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    outer.mount("/", inner)
    return outer


def _anchorer(p: asyncpg.Pool, node: Node):
    from .anchoring import anchor as anchoring
    cfg = anchoring.config_from_env(log_id(), prefix="POAW_ANCHOR_")
    if not cfg:
        return None
    from .anchoring import eth
    signer = eth.local_signer(read_seed(_require("POAW_ANCHOR_KEY_FILE")))
    rpc = eth.Rpc(os.environ.get("POAW_ANCHOR_RPC") or eth.CHAINS[cfg.chain])

    async def ops_alert(text: str) -> None:
        print(json.dumps({"event": "ops_alert", "text": text[:300]}), flush=True)
    return anchoring.Anchorer(p, signer, rpc, cfg, ops_alert)
