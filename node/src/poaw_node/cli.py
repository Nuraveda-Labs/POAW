"""`poaw-node` — run and administer a self-hosted poaw node. Configuration is by environment (see selfhost.py)."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import secrets
import sys
from pathlib import Path


def _keygen(path: str) -> None:
    p = Path(path)
    if p.exists():
        sys.exit(f"{path} already exists; refusing to overwrite a signing key")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secrets.token_bytes(32).hex() + "\n")
    print(f"wrote a new 32-byte key to {path} (mode 600). Back it up: receipts are verified against its public key.")


async def _create_workspace(name: str, label: str) -> None:
    import asyncpg
    from .selfhost import _require
    key = "poaw_sk_" + secrets.token_urlsafe(32)
    conn = await asyncpg.connect(_require("POAW_DATABASE_URL"))
    try:
        async with conn.transaction():
            ws = await conn.fetchval("insert into qed.workspaces (name) values ($1) returning id::text", name)
            await conn.execute("insert into qed.api_keys (workspace_id, key_hash, key_prefix, label) values ($1::uuid, $2, $3, $4)",
                               ws, hashlib.sha256(key.encode()).hexdigest(), key[:12], label)
    finally:
        await conn.close()
    print(f"workspace: {ws}\napi key (shown once, store it now): {key}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="poaw-node", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db", help="apply the schema to an empty database (safe to re-run)")
    k = sub.add_parser("keygen", help="write a new 32-byte key file (for POAW_SIGNING_KEY_FILE or POAW_ANCHOR_KEY_FILE)")
    k.add_argument("path")
    w = sub.add_parser("create-workspace", help="create a workspace and print its first API key once")
    w.add_argument("--name", required=True)
    w.add_argument("--label", default="initial")
    s = sub.add_parser("serve", help="run the claims API and the background tick")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8080)
    a = ap.parse_args(argv)
    if a.cmd == "init-db":
        from .selfhost import init_db
        print(asyncio.run(init_db()))
    elif a.cmd == "keygen":
        _keygen(a.path)
    elif a.cmd == "create-workspace":
        asyncio.run(_create_workspace(a.name, a.label))
    elif a.cmd == "serve":
        import uvicorn
        from .selfhost import build_app
        uvicorn.run(build_app(), host=a.host, port=a.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
