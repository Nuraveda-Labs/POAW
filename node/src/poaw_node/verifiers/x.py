"""x.post.publish v1 (SPEC §9, profile: spec/profiles/x.post.publish.md). One read-only X API v2 lookup.

Facts carry IDs, timestamps and whether a text fingerprint matched. Never the post text.
"""
from __future__ import annotations

import hashlib
import html
import re
import unicodedata
from datetime import datetime, timedelta, timezone

import httpx
from pydantic import Field

from ..models import Claim, Observed, Reason, Retry, Unverifiable, Verdict
from . import Params, VerifierSpec, account_id, register

API = "https://api.x.com/2"
FIELDS = "author_id,created_at,text,entities,note_tweet"
_HANDLE = re.compile(r"^@[A-Za-z0-9_]{1,15}$")
_POST_ID = re.compile(r"^[0-9]{1,20}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NOT_FOUND = "https://api.twitter.com/2/problems/resource-not-found"


class PostParams(Params):
    post_id: str = Field(pattern=_POST_ID.pattern)
    text_sha256: str | None = Field(default=None, pattern=_HEX64.pattern)


def text_sha256(text: str) -> str:
    """The profile's text fingerprint: lowercase hex SHA-256 of the NFC-normalised text with its edges stripped."""
    return hashlib.sha256(unicodedata.normalize("NFC", text).strip().encode("utf-8")).hexdigest()


def posted_text(post: dict) -> str:
    """The text as the author wrote it, rebuilt from what X returns: the full text of a long post (`note_tweet`), links
    expanded from X's shortened form, links X appends for attached media removed, and HTML entities decoded."""
    note = post.get("note_tweet") if isinstance(post.get("note_tweet"), dict) else None
    source = note if note and isinstance(note.get("text"), str) else post
    text = source.get("text") or ""
    urls = (source.get("entities") or {}).get("urls") or []
    for u in sorted((u for u in urls if isinstance(u, dict) and isinstance(u.get("url"), str)),
                    key=lambda u: u.get("start", 0), reverse=True):
        replacement = "" if u.get("media_key") else (u.get("expanded_url") or u["url"])
        text = text.replace(u["url"], replacement)
    return html.unescape(text)


def _parse_time(s) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")) if isinstance(s, str) else None
    except ValueError:
        return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def post_publish(claim: Claim, creds, client: httpx.AsyncClient):
    """Verified iff the post exists, was written by the account `target` is bound to, and (optionally) its text hashes
    to `text_sha256`. A post that isn't there yet is `failed`, retried until the deadline."""
    post_id, want_hash = claim.params.get("post_id"), claim.params.get("text_sha256")
    if (not _HANDLE.match(claim.target) or not isinstance(post_id, str) or not _POST_ID.match(post_id)
            or (want_hash is not None and (not isinstance(want_hash, str) or not _HEX64.match(want_hash)))):
        return Unverifiable(Reason.CLAIM_AMBIGUOUS, "need target @handle, params.post_id (digits), optional params.text_sha256 (64 hex)")
    token, owner = (creds.token() if creds else None), account_id(creds)
    if not token or not owner:
        return Unverifiable(Reason.NO_CONNECTION, "the target handle is not a connected account")

    try:
        r = await client.get(f"{API}/tweets/{post_id}", params={"tweet.fields": FIELDS}, timeout=10,
                             headers={"Authorization": f"Bearer {token}", "User-Agent": "poaw-node"})
    except httpx.HTTPError as exc:
        return Retry(Reason.DESTINATION_UNAVAILABLE, type(exc).__name__)

    absent = Observed({"post_id": post_id, "found": False}, Verdict.FAILED, Reason.NOT_FOUND, observed_at=_now(), final=False)
    if r.status_code == 404:
        return absent
    if r.status_code in (401, 403):
        return Unverifiable(Reason.PERMISSION_DENIED, f"X API HTTP {r.status_code}")
    if r.status_code == 402:
        return Unverifiable(Reason.DESTINATION_UNAVAILABLE, "X API HTTP 402: the reading app's API credits are exhausted")
    if r.status_code == 429:
        return Retry(Reason.RATE_LIMITED, "X API HTTP 429")
    if r.status_code != 200:
        return Retry(Reason.DESTINATION_UNAVAILABLE, f"X API HTTP {r.status_code}")
    try:
        body = r.json()
    except ValueError:
        return Retry(Reason.DESTINATION_UNAVAILABLE, "X API returned a non-JSON body")

    post = body.get("data") if isinstance(body, dict) else None
    if not isinstance(post, dict):
        errors = body.get("errors") if isinstance(body, dict) else None
        types = {e.get("type") for e in errors if isinstance(e, dict)} if isinstance(errors, list) else set()
        if _NOT_FOUND in types:
            return absent
        if types:  # e.g. a protected or suspended account's post: the read itself was refused
            return Unverifiable(Reason.PERMISSION_DENIED, "X API refused to return the post")
        return Retry(Reason.DESTINATION_UNAVAILABLE, "X API returned no post and no error")

    created_at = post.get("created_at") if isinstance(post.get("created_at"), str) else None
    facts = {"post_id": post_id, "author_id": post.get("author_id"), "found": True, "created_at": created_at}
    if facts["author_id"] != owner:
        return Observed(facts, Verdict.MISMATCH, Reason.TARGET_MISMATCH, observed_at=_now())
    if want_hash is not None:
        facts["text_sha256_matched"] = text_sha256(posted_text(post)) == want_hash
        if not facts["text_sha256_matched"]:
            return Observed(facts, Verdict.MISMATCH, Reason.CONTENT_MISMATCH, observed_at=_now())
    return Observed(facts, Verdict.VERIFIED, observed_at=_now(), appeared_at=_parse_time(created_at))


register(VerifierSpec("x.post.publish", "1", "x", timedelta(minutes=10), timedelta(minutes=30), post_publish, PostParams))
