"""GET /v1/connections (lane: connections-list-api): auth, workspace isolation, active-only, registry-driven actions,
and data minimisation (no field that identifies the connected account ever reaches an API key holder)."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from poaw_node.app import create_app
from poaw_node.verifiers import REGISTRY, load_builtin

T0 = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 9, 26, 13, 0, tzinfo=timezone.utc)
ITEM_KEYS = {"id", "provider", "scopes", "connected_at", "actions"}


class FakeStore:
    """Mirrors Store.list_connections (LIST_CONNECTIONS_SQL): this workspace, active only, oldest first. The rows
    carry identifying columns on purpose, to prove the route never passes them through."""

    def __init__(self):
        self.rows: list[dict] = []
        self.rate_calls: list[str] = []

    async def workspace_for_key(self, key):
        return {"good": "ws-1", "other": "ws-2"}.get(key)

    async def rate_take(self, bucket, *, per_minute):
        self.rate_calls.append(bucket)
        return True

    def add(self, *, workspace_id="ws-1", id, provider, created_at=T0, status="active", scopes=None):
        self.rows.append(dict(workspace_id=workspace_id, id=id, provider=provider, created_at=created_at, status=status,
                              scopes=scopes or [], account_name="@someone", account_key="U123",
                              account_login="octo", installation_id=42, secret_ref="qed/conn/secret"))

    async def list_connections(self, workspace_id):
        rows = [r for r in self.rows if r["workspace_id"] == workspace_id and r["status"] == "active"]
        rows.sort(key=lambda r: (r["created_at"], r["id"]))
        return [dict(r) for r in rows]


class FakeNode:
    def __init__(self, store):
        self.store = store


def client(store: FakeStore | None = None) -> tuple[TestClient, FakeStore]:
    store = store or FakeStore()
    node = FakeNode(store)

    async def get_node():
        return node

    return TestClient(create_app(get_node, log_id="x", tick_enabled=lambda: False)), store


AUTH = {"Authorization": "Bearer good"}


def _expected(provider):
    load_builtin()
    return sorted(a for a, s in REGISTRY.items() if s.provider == provider)


def test_auth_required():
    c, _ = client()
    assert c.get("/v1/connections").status_code == 401
    assert c.get("/v1/connections", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_rate_limited_per_key():
    c, store = client()
    assert c.get("/v1/connections", headers=AUTH).status_code == 200
    assert len(store.rate_calls) == 1 and store.rate_calls[0].startswith("key:")


def test_lists_only_this_workspaces_active_connections_oldest_first():
    store = FakeStore()
    store.add(id="b", provider="slack", created_at=T1, scopes=["channels:history", "channels:read"])
    store.add(id="a", provider="github", created_at=T0)
    store.add(id="r", provider="x", status="revoked")
    store.add(id="z", provider="gitlab", workspace_id="ws-2")
    c, _ = client(store)
    body = c.get("/v1/connections", headers=AUTH).json()
    assert [x["id"] for x in body["connections"]] == ["a", "b"]
    assert body["connections"][1]["scopes"] == ["channels:history", "channels:read"]
    assert body["connections"][0]["connected_at"] == "2026-09-26T12:00:00Z"


def test_other_workspace_sees_only_its_own():
    store = FakeStore()
    store.add(id="a", provider="github")
    store.add(id="z", provider="gitlab", workspace_id="ws-2")
    c, _ = client(store)
    body = c.get("/v1/connections", headers={"Authorization": "Bearer other"}).json()
    assert [x["id"] for x in body["connections"]] == ["z"]


def test_no_identifying_fields_ever():
    store = FakeStore()
    for i, p in enumerate(["github", "slack", "x", "gitlab", "meta_page"]):
        store.add(id=str(i), provider=p)
    c, _ = client(store)
    body = c.get("/v1/connections", headers=AUTH).json()
    assert set(body) == {"connections", "public_actions"}
    for item in body["connections"]:
        assert set(item) == ITEM_KEYS  # exact: adding a field is a deliberate, reviewed change
    raw = c.get("/v1/connections", headers=AUTH).text
    for leak in ("@someone", "U123", "octo", "secret", "installation"):
        assert leak not in raw


def test_actions_come_from_the_registry():
    store = FakeStore()
    for i, p in enumerate(["github", "slack", "x", "meta_page"]):
        store.add(id=str(i), provider=p)
    c, _ = client(store)
    body = c.get("/v1/connections", headers=AUTH).json()
    got = {x["provider"]: x["actions"] for x in body["connections"]}
    for p in ("github", "slack", "x"):
        assert got[p] == _expected(p) and got[p], p  # every live connector has at least one verifier
    assert got["meta_page"] == []  # connected, but no verifier live yet — the tool must say so, not invent one
    assert body["public_actions"] == sorted(a for a, s in REGISTRY.items() if s.provider is None)
    assert "http.url.status" in body["public_actions"]


def test_empty_workspace():
    c, _ = client()
    body = c.get("/v1/connections", headers=AUTH).json()
    assert body["connections"] == [] and body["public_actions"]
