"""Regression tests for SECURITY.md §8 findings F2, F3, F4 and F7 (lane security-fixes)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from pydantic import ValidationError

from poaw_node.app import CLAIMS_PER_MIN_PER_KEY, client_ip, create_app
from poaw_node.models import ClaimIn, Unverifiable
from poaw_node.service import Node
from poaw_node.verifiers import http as httpv
from poaw_node.verifiers import load_builtin

load_builtin()
NOW = datetime(2026, 9, 25, 14, 0, tzinfo=timezone.utc)


def claim(**kw) -> ClaimIn:
    base = dict(client_claim_id="c", agent_id="a", action="github.commit.push", target="o/r",
                params={"sha": "a" * 40, "branch": "main"}, claimed_at=NOW)
    base.update(kw)
    return ClaimIn(**base)


# -- F3: params are schema-checked and small --------------------------------------------------------------------------
def test_unknown_param_key_rejected():
    with pytest.raises(ValidationError):
        Node.validate_params(claim(params={"sha": "a" * 40, "branch": "main", "email_body": "secret"}))


def test_wrong_param_type_rejected():
    with pytest.raises(ValidationError):
        Node.validate_params(claim(action="github.pr.open", params={"number": "7"}))


def test_oversized_params_rejected():
    with pytest.raises(ValidationError):
        claim(params={"sha": "a" * 40, "branch": "b" * 5000})


def test_unsupported_action_must_have_empty_params():
    with pytest.raises(ValueError):
        Node.validate_params(claim(action="gmail.message.send", params={"text": "hello"}))
    Node.validate_params(claim(action="gmail.message.send", params={}))


# -- F2 + F7: rate limiting, body cap, headers ---------------------------------------------------------------------
class FakeStore:
    def __init__(self, allow_after: int):
        self.calls, self.allow_after = 0, allow_after
        self.buckets: list[str] = []

    async def workspace_for_key(self, key):
        return "ws-1" if key == "good" else None

    async def rate_take(self, bucket, *, per_minute):
        self.calls += 1
        self.buckets.append(bucket)
        return self.calls <= self.allow_after

    async def claim_status(self, ws, cid):
        return {"claim_id": cid, "state": "queued"}

    async def receipt_with_proof(self, rid, log_id):
        return None


class FakeNode:
    def __init__(self, store):
        self.store = store


def client(allow_after=10_000) -> tuple[TestClient, FakeStore]:
    store = FakeStore(allow_after)
    node = FakeNode(store)

    async def get_node():
        return node

    return TestClient(create_app(get_node, log_id="x", tick_enabled=lambda: False)), store


def test_rate_limit_returns_429_with_retry_after():
    c, _ = client(allow_after=2)
    h = {"Authorization": "Bearer good"}
    assert c.get("/v1/claims/abc", headers=h).status_code == 200
    assert c.get("/v1/claims/abc", headers=h).status_code == 200
    r = c.get("/v1/claims/abc", headers=h)
    assert r.status_code == 429 and r.headers["retry-after"] == "5"


def test_public_receipt_reads_are_rate_limited_per_ip():
    c, _ = client(allow_after=1)
    assert c.get("/v1/receipts/rcpt_x").status_code == 404
    assert c.get("/v1/receipts/rcpt_x").status_code == 429


# -- receipts: per-key rate limit when a valid key is presented (lane: list-claims addition B) -----------------------
def test_authed_receipt_reads_use_a_key_bucket_not_the_ip_bucket():
    c, store = client()
    c.get("/v1/receipts/rcpt_x", headers={"Authorization": "Bearer good"})
    assert len(store.buckets) == 1
    assert store.buckets[0].startswith("key:") and not store.buckets[0].startswith("ip:")


def test_two_resolvable_keys_get_separate_buckets():
    class TwoKeyStore:
        def __init__(self):
            self.buckets: list[str] = []

        async def workspace_for_key(self, key):
            return {"good": "ws-1", "also-good": "ws-2"}.get(key)

        async def rate_take(self, bucket, *, per_minute):
            self.buckets.append(bucket)
            return True

        async def claim_status(self, ws, cid):
            return {"claim_id": cid, "state": "queued"}

        async def receipt_with_proof(self, rid, log_id):
            return None

    store = TwoKeyStore()
    node = FakeNode(store)

    async def get_node():
        return node

    c = TestClient(create_app(get_node, log_id="x", tick_enabled=lambda: False))
    c.get("/v1/receipts/rcpt_x", headers={"Authorization": "Bearer good"})
    c.get("/v1/receipts/rcpt_x", headers={"Authorization": "Bearer also-good"})
    assert len(store.buckets) == 2 and store.buckets[0] != store.buckets[1]
    assert all(b.startswith("key:") for b in store.buckets)


def test_unresolvable_key_falls_back_to_ip_bucket():
    c, store = client()
    c.get("/v1/receipts/rcpt_x", headers={"Authorization": "Bearer nope"})
    assert len(store.buckets) == 1 and store.buckets[0].startswith("ip:")


def test_security_headers_and_no_store():
    c, _ = client()
    r = c.get("/healthz")
    assert r.headers["strict-transport-security"].startswith("max-age=")
    assert r.headers["x-content-type-options"] == "nosniff"
    r = c.get("/v1/claims/abc", headers={"Authorization": "Bearer good"})
    assert r.headers["cache-control"] == "no-store"


def test_body_cap_413():
    c, _ = client()
    r = c.post("/v1/claims", content=b"{" + b" " * (70 * 1024) + b"}", headers={"content-type": "application/json",
                                                                                   "Authorization": "Bearer good"})
    assert r.status_code == 413


def test_body_cap_413_without_content_length():
    """#143: a chunked body has no Content-Length, so the cap must count the bytes that arrive."""
    c, _ = client()

    def chunks():
        for _ in range(20):
            yield b" " * (8 * 1024)

    r = c.post("/v1/claims", content=chunks(), headers={"content-type": "application/json", "Authorization": "Bearer good"})
    assert r.status_code == 413
    assert r.headers["x-content-type-options"] == "nosniff"


def test_small_body_still_reaches_the_app_after_the_cap():
    c, _ = client()
    r = c.post("/v1/claims", content=b"{}", headers={"content-type": "application/json", "Authorization": "Bearer good"})
    assert r.status_code not in (413, 500)


def test_docs_endpoints_are_off():
    c, _ = client()
    assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404


def test_client_ip_ignores_forwarded_for_and_uses_aws_context():
    from starlette.requests import Request
    scope = {"type": "http", "headers": [(b"x-forwarded-for", b"1.2.3.4"),
                                         (b"x-amzn-request-context", json.dumps({"http": {"sourceIp": "9.9.9.9"}}).encode())],
             "client": ("10.0.0.1", 1)}
    assert client_ip(Request(scope)) == "9.9.9.9"
    spoof_only = {"type": "http", "headers": [(b"x-forwarded-for", b"1.2.3.4")], "client": ("10.0.0.1", 1)}
    assert client_ip(Request(spoof_only)) == "10.0.0.1"


def _req(headers):
    from starlette.requests import Request
    ctx = (b"x-amzn-request-context", json.dumps({"http": {"sourceIp": "9.9.9.9"}}).encode())  # the edge, as AWS saw it
    return Request({"type": "http", "headers": [ctx, *headers], "client": ("10.0.0.1", 1)})


def test_client_ip_trusts_edge_header_only_with_the_edge_secret(monkeypatch):
    monkeypatch.setenv("POAW_TRUSTED_EDGE_SECRET", "s3cret")
    good = [(b"x-qed-edge", b"s3cret"), (b"x-qed-viewer-ip", b"203.0.113.7")]
    assert client_ip(_req(good)) == "203.0.113.7"
    # A direct caller who forges the viewer header without the secret (or with a wrong one) gets the AWS-seen IP.
    assert client_ip(_req([(b"x-qed-viewer-ip", b"203.0.113.7")])) == "9.9.9.9"
    assert client_ip(_req([(b"x-qed-edge", b"guess"), (b"x-qed-viewer-ip", b"203.0.113.7")])) == "9.9.9.9"


def test_client_ip_ignores_edge_headers_when_no_secret_is_configured(monkeypatch):
    monkeypatch.delenv("POAW_TRUSTED_EDGE_SECRET", raising=False)
    assert client_ip(_req([(b"x-qed-edge", b""), (b"x-qed-viewer-ip", b"203.0.113.7")])) == "9.9.9.9"


# -- F4: connect to the pinned, validated IP -------------------------------------------------------------------------
@respx.mock
async def test_http_verifier_connects_to_pinned_ip(monkeypatch):
    async def fake_resolve(host):
        return "93.184.216.34"
    monkeypatch.setattr(httpv, "resolve_public", fake_resolve)
    route = respx.get("https://93.184.216.34/health").respond(200, text="ok")
    from poaw_node.models import Claim
    c = Claim(id="1", workspace_id="w", agent_ref="a", client_claim_id="c", action="http.url.status",
              target="https://status.example.com/health", params={"status": 200}, claimed_at=NOW, deadline_at=NOW)
    async with httpx.AsyncClient() as http:
        r = await httpv.url_status(c, None, http)
    assert route.called, "must connect to the validated IP, never re-resolve the name"
    sent = route.calls.last.request
    assert sent.headers["host"] == "status.example.com"
    assert sent.extensions.get("sni_hostname") == "status.example.com"
    assert not isinstance(r, Unverifiable)


async def test_http_verifier_refuses_when_any_address_is_private(monkeypatch):
    async def fake_resolve(host):
        return None  # e.g. one of the A records is 10.0.0.5
    monkeypatch.setattr(httpv, "resolve_public", fake_resolve)
    from poaw_node.models import Claim
    c = Claim(id="1", workspace_id="w", agent_ref="a", client_claim_id="c", action="http.url.status",
              target="https://rebind.example.com/", params={}, claimed_at=NOW, deadline_at=NOW)
    async with httpx.AsyncClient() as http:
        assert isinstance(await httpv.url_status(c, None, http), Unverifiable)


def test_keyset_is_published_only_when_configured():
    async def get_node():
        raise AssertionError("the keyset route must not need a node here")

    assert TestClient(create_app(get_node, log_id="x", tick_enabled=lambda: False)).get("/.well-known/poaw-keys.json").status_code == 404

    async def keyset():
        return {"keys": [], "anchor_addresses": ["0xabc"], "anchor_schemas": []}
    r = TestClient(create_app(get_node, log_id="x", tick_enabled=lambda: False, keyset=keyset)).get("/.well-known/poaw-keys.json")
    assert r.status_code == 200 and r.json()["anchor_addresses"] == ["0xabc"]


def test_admission_refusal_is_402_and_never_reaches_the_node():
    """A deployment's admission policy (e.g. a plan quota) refuses NEW claims up front. The refused claim must not be
    stored, checked or receipted, so billing can never produce or alter a verdict."""
    submitted = []

    class N(FakeNode):
        async def submit(self, *a, **k):
            submitted.append(a)
            raise AssertionError("must not be called")

    node = N(FakeStore(10_000))

    async def get_node():
        return node

    async def refuse(ws, claim):
        return "over the free plan"

    c = TestClient(create_app(get_node, log_id="x", tick_enabled=lambda: False, admission=refuse))
    body = {"client_claim_id": "c1", "agent_id": "a", "action": "http.url.status", "target": "https://example.com",
            "params": {}, "claimed_at": "2026-09-26T00:00:00Z"}
    r = c.post("/v1/claims", json=body, headers={"Authorization": "Bearer good"})
    assert r.status_code == 402 and r.json()["detail"] == "over the free plan" and not submitted
