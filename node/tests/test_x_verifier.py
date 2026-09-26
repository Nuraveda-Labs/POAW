"""x.post.publish v1: every rule in spec/profiles/x.post.publish.md, against a mocked X API (no real calls)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx
from pydantic import ValidationError

from poaw_node.models import Claim, ClaimIn, Observed, Reason, Retry, Unverifiable, Verdict
from poaw_node.service import Node
from poaw_node.verdict import decide
from poaw_node.verifiers import REGISTRY, load_builtin
from poaw_node.verifiers import x

load_builtin()
T0 = datetime(2026, 9, 26, 14, 0, tzinfo=timezone.utc)
POST = "1839000000000000001"
URL = f"{x.API}/tweets/{POST}"
OWNER = "1234567890"


class Creds:
    def __init__(self, token="app-bearer", account="1234567890"):
        self._t, self._a = token, account

    def token(self):
        return self._t

    def account_id(self):
        return self._a


class TokenOnly:
    def token(self):
        return "t"


def claim(**kw) -> Claim:
    base = dict(id="c1", workspace_id="w1", agent_ref="agent-1", client_claim_id="cc-1", action="x.post.publish",
                target="@example_agent", params={"post_id": POST}, claimed_at=T0, deadline_at=T0 + timedelta(minutes=30))
    base.update(kw)
    return Claim(**base)


def post(**kw) -> dict:
    data = {"id": POST, "author_id": OWNER, "created_at": "2026-09-26T14:01:00.000Z", "text": "Shipped v1.2 today"}
    data.update(kw)
    return {"data": data}


async def run(c: Claim, creds=None) -> object:
    async with httpx.AsyncClient() as client:
        return await x.post_publish(c, Creds() if creds is None else creds, client)


def test_registered_with_profile_windows():
    spec = REGISTRY["x.post.publish"]
    assert (spec.version, spec.provider) == ("1", "x")
    assert spec.tolerance == timedelta(minutes=10) and spec.deadline == timedelta(minutes=30)


@respx.mock
async def test_verified_when_author_matches_and_no_hash():
    route = respx.get(URL).respond(200, json=post())
    r = await run(claim())
    assert isinstance(r, Observed) and r.outcome is Verdict.VERIFIED
    assert r.appeared_at == datetime(2026, 9, 26, 14, 1, tzinfo=timezone.utc)
    assert r.facts == {"post_id": POST, "author_id": OWNER, "found": True, "created_at": "2026-09-26T14:01:00.000Z"}
    req = route.calls.last.request
    assert req.headers["authorization"] == "Bearer app-bearer"
    assert req.url.params["tweet.fields"] == x.FIELDS


@respx.mock
async def test_verified_with_matching_text_hash_and_no_text_in_facts():
    respx.get(URL).respond(200, json=post())
    r = await run(claim(params={"post_id": POST, "text_sha256": x.text_sha256("  Shipped v1.2 today\n")}))
    assert r.outcome is Verdict.VERIFIED and r.facts["text_sha256_matched"] is True
    assert "Shipped" not in repr(r.facts)


def test_text_hash_is_nfc_and_stripped():
    composed, decomposed = "café", "café"
    assert x.text_sha256(composed) == x.text_sha256(f"  {decomposed}\n")
    assert len(x.text_sha256("a")) == 64


def test_posted_text_rebuilds_long_posts_links_media_and_entities():
    p = {"text": "short… https://t.co/abc", "note_tweet": {
        "text": "Read &amp; see https://t.co/abc https://t.co/img",
        "entities": {"urls": [
            {"start": 15, "end": 38, "url": "https://t.co/abc", "expanded_url": "https://example.com/a"},
            {"start": 39, "end": 62, "url": "https://t.co/img", "expanded_url": "https://x.com/i/photo", "media_key": "3_1"},
        ]}}}
    assert x.posted_text(p).strip() == "Read & see https://example.com/a"


@respx.mock
async def test_different_author_is_target_mismatch():
    respx.get(URL).respond(200, json=post(author_id="999"))
    r = await run(claim())
    assert r.outcome is Verdict.MISMATCH and r.reason is Reason.TARGET_MISMATCH and r.final
    assert r.facts["author_id"] == "999"


@respx.mock
async def test_text_hash_differs_is_content_mismatch():
    respx.get(URL).respond(200, json=post())
    r = await run(claim(params={"post_id": POST, "text_sha256": "0" * 64}))
    assert r.outcome is Verdict.MISMATCH and r.reason is Reason.CONTENT_MISMATCH
    assert r.facts["text_sha256_matched"] is False


@respx.mock
@pytest.mark.parametrize("response", [
    httpx.Response(404),
    httpx.Response(200, json={"errors": [{"type": "https://api.twitter.com/2/problems/resource-not-found",
                                          "title": "Not Found Error"}]}),
])
async def test_absent_post_is_failed_not_final(response):
    respx.get(URL).mock(return_value=response)
    r = await run(claim())
    assert isinstance(r, Observed) and r.outcome is Verdict.FAILED and r.reason is Reason.NOT_FOUND and not r.final
    assert r.facts == {"post_id": POST, "found": False}
    kw = dict(claimed_at=T0, deadline_at=T0 + timedelta(minutes=30), tolerance=timedelta(minutes=10))
    assert decide(r, now=T0 + timedelta(minutes=5), **kw) is None  # retried until the deadline
    assert decide(r, now=T0 + timedelta(minutes=31), **kw).verdict is Verdict.FAILED


@respx.mock
@pytest.mark.parametrize("status", [401, 403])
async def test_auth_refusal_is_permission_denied(status):
    respx.get(URL).respond(status)
    r = await run(claim())
    assert isinstance(r, Unverifiable) and r.reason is Reason.PERMISSION_DENIED


@respx.mock
async def test_refused_post_in_a_200_body_is_permission_denied():
    respx.get(URL).respond(200, json={"errors": [{"type": "https://api.twitter.com/2/problems/not-authorized-for-resource"}]})
    r = await run(claim())
    assert isinstance(r, Unverifiable) and r.reason is Reason.PERMISSION_DENIED


@respx.mock
async def test_credits_exhausted_is_unverifiable_with_a_clear_detail():
    respx.get(URL).respond(402)
    r = await run(claim())
    assert isinstance(r, Unverifiable) and r.reason is Reason.DESTINATION_UNAVAILABLE and "credits" in r.detail


@respx.mock
@pytest.mark.parametrize("status,reason", [(429, Reason.RATE_LIMITED), (500, Reason.DESTINATION_UNAVAILABLE),
                                           (503, Reason.DESTINATION_UNAVAILABLE)])
async def test_throttling_and_server_errors_retry(status, reason):
    respx.get(URL).respond(status)
    r = await run(claim())
    assert isinstance(r, Retry) and r.reason is reason


@respx.mock
async def test_transport_error_retries():
    respx.get(URL).mock(side_effect=httpx.ConnectTimeout("slow"))
    assert isinstance(await run(claim()), Retry)


@respx.mock
async def test_late_post_decides_late():
    respx.get(URL).respond(200, json=post(created_at="2026-09-26T14:20:00.000Z"))
    r = await run(claim())
    d = decide(r, claimed_at=T0, deadline_at=T0 + timedelta(minutes=30), now=T0 + timedelta(minutes=21),
               tolerance=timedelta(minutes=10))
    assert d.verdict is Verdict.LATE


@pytest.mark.parametrize("target,params", [
    ("example_agent", {"post_id": POST}),                     # no @
    ("@has-dash", {"post_id": POST}),
    ("@waytoolonghandle123", {"post_id": POST}),
    ("@example_agent", {"post_id": "12ab"}),
    ("@example_agent", {"post_id": 1839}),
    ("@example_agent", {"post_id": POST, "text_sha256": "XYZ"}),
])
async def test_malformed_claim_is_ambiguous(target, params):
    r = await run(claim(target=target, params=params))
    assert isinstance(r, Unverifiable) and r.reason is Reason.CLAIM_AMBIGUOUS


@pytest.mark.parametrize("creds", [None, Creds(token=None), Creds(account=None), TokenOnly()])
async def test_no_bound_account_is_no_connection(creds):
    async with httpx.AsyncClient() as client:
        r = await x.post_publish(claim(), creds, client)
    assert isinstance(r, Unverifiable) and r.reason is Reason.NO_CONNECTION


def _claim_in(params) -> ClaimIn:
    return ClaimIn(client_claim_id="c", agent_id="a", action="x.post.publish", target="@example_agent", params=params,
                   claimed_at=T0)


@pytest.mark.parametrize("params", [
    {"post_id": POST, "text": "the post itself"},             # extra key: content must never reach a receipt
    {"post_id": 1839},                                        # strict: not a string
    {"post_id": "1" * 21},
    {"post_id": POST, "text_sha256": "A" * 64},
    {},
])
def test_params_are_validated_at_intake(params):
    with pytest.raises(ValidationError):
        Node.validate_params(_claim_in(params))


def test_valid_params_pass_intake():
    Node.validate_params(_claim_in({"post_id": POST}))
    Node.validate_params(_claim_in({"post_id": POST, "text_sha256": "a" * 64}))


# -- the ConnectionStore `target` seam ----------------------------------------------------------------------------------
async def test_node_passes_the_claim_target_and_two_argument_stores_still_work():
    from poaw_node.interfaces import EnvConnections
    from poaw_node.service import _accepts_target, _credentials

    seen = []

    class New:
        async def credentials(self, workspace_id, provider, target=None):
            seen.append(target)
            return Creds()

    class Legacy:  # written before `target` existed
        async def credentials(self, workspace_id, provider):
            seen.append("legacy")
            return Creds()

    assert (await _credentials(New(), claim(), "x")).account_id() == OWNER
    assert (await _credentials(Legacy(), claim(), "x")).token() == "app-bearer"
    assert seen == ["@example_agent", "legacy"]
    assert _accepts_target(EnvConnections()) and not _accepts_target(Legacy())
