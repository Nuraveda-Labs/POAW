"""GET /v1/claims (lane: list-claims): auth, workspace isolation, ordering, keyset pagination, filters."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from poaw_node.app import create_app

T0 = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)


class FakeStore:
    """Mirrors the real Store.list_claims's contract (filter, order, keyset before-cursor, limit) in memory, so
    these tests exercise the app's pagination/cursor logic exactly as it will run against Postgres."""

    def __init__(self):
        self.claims: list[dict] = []
        self.rate_calls: list[str] = []

    async def workspace_for_key(self, key):
        return {"good": "ws-1", "other": "ws-2"}.get(key)

    async def rate_take(self, bucket, *, per_minute):
        self.rate_calls.append(bucket)
        return True

    def add(self, *, workspace_id="ws-1", claim_id, created_at, state="decided", attempts=1, receipt_id=None,
            verdict=None, agent_id="agent-1", action="github.commit.push"):
        self.claims.append(dict(workspace_id=workspace_id, claim_id=claim_id, created_at=created_at, state=state,
                                attempts=attempts, receipt_id=receipt_id, verdict=verdict, agent_id=agent_id,
                                action=action))

    async def list_claims(self, workspace_id, *, limit, before=None, agent_id=None, action=None, verdict=None,
                          state=None):
        rows = [c for c in self.claims if c["workspace_id"] == workspace_id]
        if agent_id is not None:
            rows = [c for c in rows if c["agent_id"] == agent_id]
        if action is not None:
            rows = [c for c in rows if c["action"] == action]
        if verdict is not None:
            rows = [c for c in rows if c["verdict"] == verdict]
        if state is not None:
            rows = [c for c in rows if c["state"] == state]
        rows.sort(key=lambda c: (c["created_at"], c["claim_id"]), reverse=True)
        if before is not None:
            rows = [c for c in rows if (c["created_at"], c["claim_id"]) < before]
        return [dict(c) for c in rows[:limit]]

    # unused by these tests but required by the FakeNode/create_app surface
    async def claim_status(self, ws, cid):
        return None

    async def receipt_with_proof(self, rid, log_id):
        return None


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


def test_auth_required():
    c, _ = client()
    assert c.get("/v1/claims").status_code == 401


def test_workspace_isolation():
    store = FakeStore()
    store.add(claim_id="mine", created_at=T0, workspace_id="ws-1")
    store.add(claim_id="theirs", created_at=T0, workspace_id="ws-2")
    c, _ = client(store)
    body = c.get("/v1/claims", headers=AUTH).json()
    assert [x["claim_id"] for x in body["claims"]] == ["mine"]


def test_empty_list():
    c, _ = client()
    r = c.get("/v1/claims", headers=AUTH)
    assert r.status_code == 200
    assert r.json() == {"claims": [], "next_cursor": None}


def test_item_shape_mirrors_claim_status():
    store = FakeStore()
    store.add(claim_id="c1", created_at=T0, state="decided", attempts=2, receipt_id="rcpt_1", verdict="verified")
    c, _ = client(store)
    item = c.get("/v1/claims", headers=AUTH).json()["claims"][0]
    assert item == {"claim_id": "c1", "state": "decided", "attempts": 2, "receipt_id": "rcpt_1", "verdict": "verified"}


def test_newest_first_ordering():
    store = FakeStore()
    for i in range(5):
        store.add(claim_id=f"c{i}", created_at=T0 + timedelta(seconds=i))
    c, _ = client(store)
    body = c.get("/v1/claims", headers=AUTH).json()
    assert [x["claim_id"] for x in body["claims"]] == ["c4", "c3", "c2", "c1", "c0"]
    assert body["next_cursor"] is None


def test_pagination_across_pages_no_dupes_or_gaps():
    store = FakeStore()
    for i in range(11):
        store.add(claim_id=f"c{i:02d}", created_at=T0 + timedelta(seconds=i))
    c, _ = client(store)
    seen: list[str] = []
    cursor = None
    for _ in range(20):  # generous cap so a bug (e.g. an infinite loop) fails loudly instead of hanging
        params = {"limit": 4} | ({"cursor": cursor} if cursor else {})
        body = c.get("/v1/claims", params=params, headers=AUTH).json()
        seen.extend(x["claim_id"] for x in body["claims"])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    expected = [f"c{i:02d}" for i in range(10, -1, -1)]
    assert seen == expected, "pagination must cover every claim exactly once, in order"


def test_filter_agent_id():
    store = FakeStore()
    store.add(claim_id="a", created_at=T0, agent_id="agent-a")
    store.add(claim_id="b", created_at=T0 + timedelta(seconds=1), agent_id="agent-b")
    c, _ = client(store)
    body = c.get("/v1/claims", params={"agent_id": "agent-b"}, headers=AUTH).json()
    assert [x["claim_id"] for x in body["claims"]] == ["b"]


def test_filter_action():
    store = FakeStore()
    store.add(claim_id="a", created_at=T0, action="github.commit.push")
    store.add(claim_id="b", created_at=T0 + timedelta(seconds=1), action="x.post.publish")
    c, _ = client(store)
    body = c.get("/v1/claims", params={"action": "x.post.publish"}, headers=AUTH).json()
    assert [x["claim_id"] for x in body["claims"]] == ["b"]


def test_filter_verdict():
    store = FakeStore()
    store.add(claim_id="a", created_at=T0, verdict="verified")
    store.add(claim_id="b", created_at=T0 + timedelta(seconds=1), verdict="failed")
    c, _ = client(store)
    body = c.get("/v1/claims", params={"verdict": "failed"}, headers=AUTH).json()
    assert [x["claim_id"] for x in body["claims"]] == ["b"]


def test_filter_state():
    store = FakeStore()
    store.add(claim_id="a", created_at=T0, state="queued")
    store.add(claim_id="b", created_at=T0 + timedelta(seconds=1), state="decided")
    c, _ = client(store)
    body = c.get("/v1/claims", params={"state": "queued"}, headers=AUTH).json()
    assert [x["claim_id"] for x in body["claims"]] == ["a"]


def test_bad_limit_is_422():
    c, _ = client()
    assert c.get("/v1/claims", params={"limit": 0}, headers=AUTH).status_code == 422
    assert c.get("/v1/claims", params={"limit": 201}, headers=AUTH).status_code == 422


def test_bad_cursor_is_400():
    c, _ = client()
    assert c.get("/v1/claims", params={"cursor": "not-valid-base64!!"}, headers=AUTH).status_code == 400
    assert c.get("/v1/claims", params={"cursor": "aGVsbG8"}, headers=AUTH).status_code == 400  # no '|' separator
