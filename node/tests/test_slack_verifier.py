"""slack.message.post v1: every rule in spec/profiles/slack.message.post.md, against a mocked Slack API (no real calls)."""
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
from poaw_node.verifiers import slack
from poaw_node.verifiers.x import text_sha256

load_builtin()
T0 = datetime(2026, 9, 26, 14, 0, tzinfo=timezone.utc)
TS = "1790431260.000200"  # 2026-09-26T14:01:00.0002Z
HISTORY = f"{slack.API}/conversations.history"
REPLIES = f"{slack.API}/conversations.replies"


class Creds:
    def __init__(self, token="user-token", account="T0TEAM1"):
        self._t, self._a = token, account

    def token(self):
        return self._t

    def account_id(self):
        return self._a


def claim(**kw) -> Claim:
    base = dict(id="c1", workspace_id="w1", agent_ref="agent-1", client_claim_id="cc-1", action="slack.message.post",
                target="slack://T0TEAM1/C0CHAN1", params={"ts": TS}, claimed_at=T0, deadline_at=T0 + timedelta(minutes=30))
    base.update(kw)
    return Claim(**base)


def msgs(*items) -> dict:
    return {"ok": True, "messages": list(items)}


async def run(c: Claim, creds=None):
    async with httpx.AsyncClient() as client:
        return await slack.message_post(c, Creds() if creds is None else creds, client)


def test_registered_with_profile_windows():
    spec = REGISTRY["slack.message.post"]
    assert (spec.version, spec.provider) == ("1", "slack")
    assert spec.tolerance == timedelta(minutes=10) and spec.deadline == timedelta(minutes=30)


@respx.mock
async def test_verified_from_history():
    route = respx.get(HISTORY).respond(200, json=msgs({"ts": TS, "text": "Deploy finished"}))
    replies = respx.get(REPLIES).respond(200, json=msgs())
    r = await run(claim())
    assert isinstance(r, Observed) and r.outcome is Verdict.VERIFIED
    assert r.facts == {"team_id": "T0TEAM1", "channel_id": "C0CHAN1", "ts": TS, "found": True}
    assert r.appeared_at == datetime(2026, 9, 26, 14, 1, 0, 200, tzinfo=timezone.utc)
    q = route.calls.last.request.url.params
    assert (q["channel"], q["latest"], q["oldest"], q["inclusive"], q["limit"]) == ("C0CHAN1", TS, TS, "true", "1")
    assert route.calls.last.request.headers["authorization"] == "Bearer user-token"
    assert not replies.called


@respx.mock
async def test_threaded_reply_falls_back_to_replies():
    respx.get(HISTORY).respond(200, json=msgs())
    route = respx.get(REPLIES).respond(200, json=msgs({"ts": "1790431000.000100", "text": "parent"},
                                                      {"ts": TS, "text": "reply"}))
    r = await run(claim())
    assert r.outcome is Verdict.VERIFIED
    q = route.calls.last.request.url.params
    assert (q["channel"], q["ts"], q["limit"]) == ("C0CHAN1", TS, "1")


@respx.mock
async def test_text_hash_matches_as_returned_or_with_entities_decoded_and_never_stores_text():
    respx.get(HISTORY).respond(200, json=msgs({"ts": TS, "text": "Tests &amp; lint &lt;green&gt;"}))
    r = await run(claim(params={"ts": TS, "text_sha256": text_sha256("Tests & lint <green>")}))
    assert r.outcome is Verdict.VERIFIED and r.facts["text_sha256_matched"] is True
    assert "lint" not in repr(r.facts)


@respx.mock
async def test_text_hash_differs_is_content_mismatch():
    respx.get(HISTORY).respond(200, json=msgs({"ts": TS, "text": "something else"}))
    r = await run(claim(params={"ts": TS, "text_sha256": text_sha256("Deploy finished")}))
    assert r.outcome is Verdict.MISMATCH and r.reason is Reason.CONTENT_MISMATCH and r.facts["text_sha256_matched"] is False


@respx.mock
@pytest.mark.parametrize("replies", [msgs(), {"ok": False, "error": "thread_not_found"},
                                     msgs({"ts": "1790431000.000100", "text": "a different message"})])
async def test_absent_message_is_failed_not_final(replies):
    respx.get(HISTORY).respond(200, json=msgs())
    respx.get(REPLIES).respond(200, json=replies)
    r = await run(claim())
    assert isinstance(r, Observed) and r.outcome is Verdict.FAILED and r.reason is Reason.NOT_FOUND and not r.final
    assert r.facts["found"] is False
    kw = dict(claimed_at=T0, deadline_at=T0 + timedelta(minutes=30), tolerance=timedelta(minutes=10))
    assert decide(r, now=T0 + timedelta(minutes=1), **kw) is None


@respx.mock
@pytest.mark.parametrize("error", ["channel_not_found", "not_in_channel", "missing_scope"])
async def test_channel_access_errors_are_permission_denied(error):
    respx.get(HISTORY).respond(200, json={"ok": False, "error": error})
    r = await run(claim())
    assert isinstance(r, Unverifiable) and r.reason is Reason.PERMISSION_DENIED


@respx.mock
@pytest.mark.parametrize("error", ["invalid_auth", "token_revoked"])
async def test_dead_token_is_no_connection(error):
    respx.get(HISTORY).respond(200, json={"ok": False, "error": error})
    r = await run(claim())
    assert isinstance(r, Unverifiable) and r.reason is Reason.NO_CONNECTION


@respx.mock
async def test_errors_on_the_replies_fallback_are_mapped_too():
    respx.get(HISTORY).respond(200, json=msgs())
    respx.get(REPLIES).respond(200, json={"ok": False, "error": "token_revoked"})
    r = await run(claim())
    assert isinstance(r, Unverifiable) and r.reason is Reason.NO_CONNECTION


@respx.mock
@pytest.mark.parametrize("response,reason", [
    (httpx.Response(200, json={"ok": False, "error": "ratelimited"}), Reason.RATE_LIMITED),
    (httpx.Response(429, headers={"Retry-After": "30"}), Reason.RATE_LIMITED),
    (httpx.Response(500), Reason.DESTINATION_UNAVAILABLE),
    (httpx.Response(503), Reason.DESTINATION_UNAVAILABLE),
])
async def test_throttling_and_server_errors_retry(response, reason):
    respx.get(HISTORY).mock(return_value=response)
    r = await run(claim())
    assert isinstance(r, Retry) and r.reason is reason


@respx.mock
async def test_transport_error_retries():
    respx.get(HISTORY).mock(side_effect=httpx.ReadTimeout("slow"))
    assert isinstance(await run(claim()), Retry)


@pytest.mark.parametrize("target,params", [
    ("T0TEAM1/C0CHAN1", {"ts": TS}),
    ("slack://T0TEAM1", {"ts": TS}),
    ("slack://X0TEAM1/C0CHAN1", {"ts": TS}),
    ("slack://T0TEAM1/D0DM1", {"ts": TS}),                     # direct messages are out of scope
    ("slack://t0team1/c0chan1", {"ts": TS}),
    ("slack://T0TEAM1/C0CHAN1", {"ts": "1790431260"}),
    ("slack://T0TEAM1/C0CHAN1", {"ts": TS, "text_sha256": "short"}),
])
async def test_malformed_claim_is_ambiguous(target, params):
    r = await run(claim(target=target, params=params))
    assert isinstance(r, Unverifiable) and r.reason is Reason.CLAIM_AMBIGUOUS


@pytest.mark.parametrize("creds", [None, Creds(token=None), Creds(account="T0OTHER")])
async def test_missing_or_wrong_workspace_connection_is_no_connection(creds):
    async with httpx.AsyncClient() as client:
        r = await slack.message_post(claim(), creds, client)
    assert isinstance(r, Unverifiable) and r.reason is Reason.NO_CONNECTION


def test_parse_target():
    assert slack.parse_target("slack://T0TEAM1/G0PRIV1") == ("T0TEAM1", "G0PRIV1")
    assert slack.parse_target("slack://T0TEAM1/C0CHAN1/extra") is None


def _claim_in(params) -> ClaimIn:
    return ClaimIn(client_claim_id="c", agent_id="a", action="slack.message.post", target="slack://T0TEAM1/C0CHAN1",
                   params=params, claimed_at=T0)


@pytest.mark.parametrize("params", [
    {"ts": TS, "text": "the message itself"},
    {"ts": 1790431260.0002},
    {"ts": "1790431260.2"},
    {"ts": TS, "text_sha256": "g" * 64},
    {},
])
def test_params_are_validated_at_intake(params):
    with pytest.raises(ValidationError):
        Node.validate_params(_claim_in(params))


def test_valid_params_pass_intake():
    Node.validate_params(_claim_in({"ts": TS}))
    Node.validate_params(_claim_in({"ts": TS, "text_sha256": "a" * 64}))
