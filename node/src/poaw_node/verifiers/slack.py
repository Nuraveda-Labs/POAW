"""slack.message.post v1 (SPEC §9, profile: spec/profiles/slack.message.post.md). Read-only Slack Web API calls.

Facts carry the team, channel and message timestamp, and whether a text fingerprint matched. Never the message text.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import httpx
from pydantic import Field

from ..models import Claim, Observed, Reason, Retry, Unverifiable, Verdict
from . import Params, VerifierSpec, account_id, register
from .x import text_sha256

API = "https://slack.com/api"
_TARGET = re.compile(r"^slack://(T[A-Z0-9]{2,20})/([CG][A-Z0-9]{2,20})$")
_TS = re.compile(r"^[0-9]{10}\.[0-9]{6}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

_PERMISSION = {"channel_not_found", "not_in_channel", "missing_scope", "no_permission", "access_denied"}
_NO_CONNECTION = {"invalid_auth", "token_revoked", "token_expired", "not_authed", "account_inactive"}
_ABSENT = {"thread_not_found", "message_not_found"}


class MessageParams(Params):
    ts: str = Field(pattern=_TS.pattern)
    text_sha256: str | None = Field(default=None, pattern=_HEX64.pattern)


def parse_target(target: str) -> tuple[str, str] | None:
    """`slack://<team_id>/<channel_id>` → (team_id, channel_id), or None when malformed."""
    m = _TARGET.match(target or "")
    return (m.group(1), m.group(2)) if m else None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts_time(ts: str) -> datetime:
    secs, micros = ts.split(".")
    return datetime.fromtimestamp(int(secs), tz=timezone.utc).replace(microsecond=int(micros))


async def _call(client: httpx.AsyncClient, method: str, params: dict, token: str) -> dict | Retry:
    """One Web API call. Returns the parsed body (ok or not), or Retry for throttling and transport trouble."""
    try:
        r = await client.get(f"{API}/{method}", params=params, timeout=10,
                             headers={"Authorization": f"Bearer {token}", "User-Agent": "poaw-node"})
    except httpx.HTTPError as exc:
        return Retry(Reason.DESTINATION_UNAVAILABLE, type(exc).__name__)
    if r.status_code == 429:
        return Retry(Reason.RATE_LIMITED, f"{method} HTTP 429")
    if r.status_code != 200:
        return Retry(Reason.DESTINATION_UNAVAILABLE, f"{method} HTTP {r.status_code}")
    try:
        body = r.json()
    except ValueError:
        return Retry(Reason.DESTINATION_UNAVAILABLE, f"{method} returned a non-JSON body")
    if not isinstance(body, dict):
        return Retry(Reason.DESTINATION_UNAVAILABLE, f"{method} returned an unexpected body")
    if body.get("ok") is not True and body.get("error") == "ratelimited":
        return Retry(Reason.RATE_LIMITED, f"{method}: ratelimited")
    return body


def _find(body: dict, ts: str) -> dict | None:
    msgs = body.get("messages")
    return next((m for m in msgs if isinstance(m, dict) and m.get("ts") == ts), None) if isinstance(msgs, list) else None


def _refusal(body: dict, method: str) -> Unverifiable | Retry | None:
    """Map a Slack `ok:false` error. None means "no such message" (the read itself worked)."""
    err = body.get("error")
    if err in _PERMISSION:
        return Unverifiable(Reason.PERMISSION_DENIED, f"{method}: {err}")
    if err in _NO_CONNECTION:
        return Unverifiable(Reason.NO_CONNECTION, f"{method}: {err}")
    if err in _ABSENT:
        return None
    return Retry(Reason.DESTINATION_UNAVAILABLE, f"{method}: {err if isinstance(err, str) else 'error'}")


async def message_post(claim: Claim, creds, client: httpx.AsyncClient):
    """Verified iff a message with exactly `ts` exists in the channel (top level or in a thread) and, optionally, its
    text hashes to `text_sha256`. A message that isn't there yet is `failed`, retried until the deadline."""
    parsed = parse_target(claim.target)
    ts, want_hash = claim.params.get("ts"), claim.params.get("text_sha256")
    if (parsed is None or not isinstance(ts, str) or not _TS.match(ts)
            or (want_hash is not None and (not isinstance(want_hash, str) or not _HEX64.match(want_hash)))):
        return Unverifiable(Reason.CLAIM_AMBIGUOUS, "need target slack://<team_id>/<channel_id>, params.ts, optional params.text_sha256 (64 hex)")
    team_id, channel_id = parsed
    token, bound = (creds.token() if creds else None), account_id(creds)
    if not token:
        return Unverifiable(Reason.NO_CONNECTION, "no connection for this Slack workspace")
    if bound is not None and bound != team_id:
        return Unverifiable(Reason.NO_CONNECTION, "the connection is for a different Slack workspace")

    facts = {"team_id": team_id, "channel_id": channel_id, "ts": ts}
    hist = await _call(client, "conversations.history",
                       {"channel": channel_id, "latest": ts, "oldest": ts, "inclusive": "true", "limit": 1}, token)
    if isinstance(hist, Retry):
        return hist
    if hist.get("ok") is not True:
        refused = _refusal(hist, "conversations.history")
        if refused is not None:
            return refused
    msg = _find(hist, ts) if hist.get("ok") is True else None
    if msg is None:  # a threaded reply isn't in the channel history
        rep = await _call(client, "conversations.replies", {"channel": channel_id, "ts": ts, "limit": 1}, token)
        if isinstance(rep, Retry):
            return rep
        if rep.get("ok") is not True:
            refused = _refusal(rep, "conversations.replies")
            if refused is not None:
                return refused
        msg = _find(rep, ts) if rep.get("ok") is True else None
    if msg is None:
        return Observed({**facts, "found": False}, Verdict.FAILED, Reason.NOT_FOUND, observed_at=_now(), final=False)

    facts["found"] = True
    if want_hash is not None:
        text = msg.get("text") if isinstance(msg.get("text"), str) else ""
        # Slack returns `&`, `<` and `>` escaped. The text matches as returned, or with those three decoded.
        decoded = text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        facts["text_sha256_matched"] = want_hash in (text_sha256(text), text_sha256(decoded))
        if not facts["text_sha256_matched"]:
            return Observed(facts, Verdict.MISMATCH, Reason.CONTENT_MISMATCH, observed_at=_now())
    return Observed(facts, Verdict.VERIFIED, observed_at=_now(), appeared_at=_ts_time(ts))


register(VerifierSpec("slack.message.post", "1", "slack", timedelta(minutes=10), timedelta(minutes=30), message_post,
                      MessageParams))
