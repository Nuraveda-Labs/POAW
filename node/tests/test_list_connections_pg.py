"""LIST_CONNECTIONS_SQL against REAL Postgres (lane connections-list-api): workspace isolation, active-only,
oldest-first order, and the column list (no identifying column is ever selected).
Needs QED_TEST_PG_URL (CI provides it and requires this test to run)."""
import os
import uuid
from datetime import datetime, timezone

import pytest

from poaw_node.store import LIST_CONNECTIONS_SQL

asyncpg = pytest.importorskip("asyncpg")
URL = os.environ.get("QED_TEST_PG_URL")
pytestmark = pytest.mark.skipif(not URL, reason="QED_TEST_PG_URL not set")

# The hosted shape (several connections per provider, identifying columns present), so the test proves the query
# ignores them rather than relying on their absence.
TABLE = """create schema qed;
create table qed.connections (id uuid primary key default gen_random_uuid(), workspace_id uuid not null,
  provider text not null, scopes text[] not null default '{}', secret_ref text, status text not null default 'active',
  created_at timestamptz not null default now(), revoked_at timestamptz, account_key text, account_name text,
  account_login text, installation_id bigint);"""


async def _db():
    name = "conns_" + uuid.uuid4().hex[:10]
    admin = await asyncpg.connect(URL)
    await admin.execute(f'create database "{name}"')
    await admin.close()
    base, _, q = URL.partition("?")
    c = await asyncpg.connect(base.rsplit("/", 1)[0] + "/" + name + ("?" + q if q else ""))
    await c.execute(TABLE)
    return c, name


async def _drop(c, name):
    await c.close()
    admin = await asyncpg.connect(URL)
    await admin.execute(f'drop database "{name}"')
    await admin.close()


async def test_active_only_this_workspace_oldest_first_and_no_identifying_columns():
    c, name = await _db()
    try:
        ws, other = uuid.uuid4(), uuid.uuid4()
        ins = """insert into qed.connections (workspace_id, provider, scopes, status, created_at, account_key,
                 account_name, account_login, installation_id, secret_ref)
                 values ($1, $2, $3, $4, $5, 'U1', '@who', 'octo', 7, 'qed/conn/s') returning id"""
        second = await c.fetchval(ins, ws, "slack", ["channels:read"], "active", datetime(2026, 9, 26, 13, tzinfo=timezone.utc))
        first = await c.fetchval(ins, ws, "github", [], "active", datetime(2026, 9, 26, 12, tzinfo=timezone.utc))
        await c.fetchval(ins, ws, "x", [], "revoked", datetime(2026, 9, 26, 11, tzinfo=timezone.utc))
        theirs = await c.fetchval(ins, other, "gitlab", [], "active", datetime(2026, 9, 26, 10, tzinfo=timezone.utc))
        rows = await c.fetch(LIST_CONNECTIONS_SQL, str(ws))
        assert [r["id"] for r in rows] == [str(first), str(second)]
        assert set(rows[0].keys()) == {"id", "provider", "scopes", "created_at"}
        assert rows[1]["scopes"] == ["channels:read"]
        assert [r["id"] for r in await c.fetch(LIST_CONNECTIONS_SQL, str(other))] == [str(theirs)]
    finally:
        await _drop(c, name)
