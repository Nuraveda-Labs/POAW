"""The invariants that make QED worth anything. If one of these fails, the product is lying."""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import respx
from hypothesis import given, settings
from hypothesis import strategies as st

from poaw_node import receipt as rc
from poaw_node.interfaces import LocalSigner
from poaw_node.models import Claim, Decision, Observed, Reason, Retry, Unverifiable, Verdict
from poaw_node.verdict import decide
from poaw_node.verifiers import github, http as httpv

SPEC_TOOLS = Path(__file__).parents[2] / "spec" / "tools"
sys.path.insert(0, str(SPEC_TOOLS))
from check import check  # noqa: E402  the spec's reference checker, not ours

T0 = datetime(2026, 9, 25, 14, 0, tzinfo=timezone.utc)
RFC8032_T1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")  # gitleaks:allow (RFC 8032 public test key)

results = st.one_of(
    st.builds(Observed, facts=st.just({}), outcome=st.sampled_from(list(Verdict)), reason=st.none() | st.sampled_from(list(Reason)),
              appeared_at=st.none() | st.datetimes(timezones=st.just(timezone.utc)), final=st.booleans()),
    st.builds(Retry, reason=st.sampled_from(list(Reason))),
    st.builds(Unverifiable, reason=st.sampled_from(list(Reason))),
    st.builds(RuntimeError, st.text(max_size=5)),
    st.none(), st.integers(), st.text(max_size=5),
)


@settings(max_examples=2000)
@given(result=results, now_offset=st.integers(-3600, 7200))
def test_verdict_is_total_and_never_fails_open(result, now_offset):
    now = T0 + timedelta(seconds=now_offset)
    d = decide(result, claimed_at=T0, deadline_at=T0 + timedelta(minutes=15), now=now, tolerance=timedelta(minutes=5))
    assert d is None or isinstance(d, Decision)
    if d is not None and d.verdict is Verdict.VERIFIED:
        # The ONLY path to `verified` is an Observed result whose own comparison said verified.
        assert isinstance(result, Observed) and result.outcome is Verdict.VERIFIED
    if d is not None and d.verdict in (Verdict.FAILED, Verdict.MISMATCH):
        assert isinstance(result, Observed), "blame needs a successful destination read (SPEC §6.2 rule 2)"
    if d is not None and d.verdict is Verdict.UNVERIFIABLE:
        assert d.reason is not None


def test_errors_before_deadline_retry_after_deadline_unverifiable():
    kw = dict(claimed_at=T0, deadline_at=T0 + timedelta(minutes=15), tolerance=timedelta(minutes=5))
    assert decide(RuntimeError("boom"), now=T0, **kw) is None
    d = decide(RuntimeError("boom"), now=T0 + timedelta(minutes=16), **kw)
    assert d.verdict is Verdict.UNVERIFIABLE and d.reason is Reason.VERIFIER_ERROR


def _claim(**kw) -> Claim:
    base = dict(id="c1", workspace_id="w1", agent_ref="agent-1", client_claim_id="cc-1", action="github.commit.push",
                target="octo/repo", params={"sha": "a" * 40, "branch": "main"}, claimed_at=T0, deadline_at=T0 + timedelta(minutes=15))
    base.update(kw)
    return Claim(**base)


def test_signed_receipt_passes_the_spec_reference_checker():
    signer = LocalSigner(RFC8032_T1)
    import poaw_core
    kid = poaw_core.key_id(signer.public_key())
    body = rc.build_body(claim=_claim(), decision=Decision(Verdict.VERIFIED, None, {"sha": "a" * 40, "branch_contains_sha": True}, T0),
                         verifier_id="github.commit.push", verifier_version="1", attempts=1, issuer_key_id=kid,
                         issuer_name="test", issued_at=T0 + timedelta(seconds=5))
    receipt = rc.sign(body, signer)
    keyset = {"keys": [{"key_id": kid, "public_key": poaw_core.b64u(signer.public_key()),
                        "valid_from": "2026-01-01T00:00:00.000Z", "revoked_at": None}]}
    report = check(receipt, keyset)
    assert report["valid"], report
    assert report["verdict"] == "verified"
    receipt["body"]["verdict"] = {"value": "failed", "reason_code": "not_found"}
    assert not check(receipt, keyset)["valid"]


class _Tok:
    def token(self):
        return "t"


@respx.mock
async def test_commit_push_verified_when_branch_contains_sha():
    sha = "a" * 40
    respx.get(f"{github.API}/repos/octo/repo/commits/{sha}").respond(200, json={"commit": {"committer": {"date": "2026-09-25T14:00:00Z"}}})
    respx.get(f"{github.API}/repos/octo/repo/compare/{sha}...main").respond(200, json={"status": "identical"})
    async with httpx.AsyncClient() as c:
        r = await github.commit_push(_claim(), _Tok(), c)
    assert isinstance(r, Observed) and r.outcome is Verdict.VERIFIED and "sha" in r.facts


@respx.mock
async def test_commit_push_missing_sha_is_failed_not_final():
    sha = "b" * 40
    respx.get(f"{github.API}/repos/octo/repo/commits/{sha}").respond(404)
    respx.get(f"{github.API}/repos/octo/repo").respond(200, json={})
    async with httpx.AsyncClient() as c:
        r = await github.commit_push(_claim(params={"sha": sha, "branch": "main"}), _Tok(), c)
    assert isinstance(r, Observed) and r.outcome is Verdict.FAILED and r.final is False


@respx.mock
async def test_unreadable_repo_is_never_blamed_on_the_agent():
    sha = "c" * 40
    respx.get(f"{github.API}/repos/octo/repo/commits/{sha}").respond(404)
    respx.get(f"{github.API}/repos/octo/repo").respond(404)
    async with httpx.AsyncClient() as c:
        r = await github.commit_push(_claim(params={"sha": sha, "branch": "main"}), None, c)
    assert isinstance(r, Unverifiable) and r.reason is Reason.NO_CONNECTION


@respx.mock
async def test_rate_limit_is_retry():
    sha = "d" * 40
    respx.get(f"{github.API}/repos/octo/repo/commits/{sha}").respond(403, headers={"x-ratelimit-remaining": "0"})
    async with httpx.AsyncClient() as c:
        r = await github.commit_push(_claim(params={"sha": sha, "branch": "main"}), _Tok(), c)
    assert isinstance(r, Retry) and r.reason is Reason.RATE_LIMITED


async def test_http_verifier_refuses_private_destinations():
    for url in ("https://127.0.0.1/", "https://localhost/", "http://example.com/", "https://10.0.0.5/x"):
        async with httpx.AsyncClient() as c:
            r = await httpv.url_status(_claim(action="http.url.status", target=url, params={"status": 200}), None, c)
        assert isinstance(r, Unverifiable), url


def test_fingerprint_normalisation_is_stable():
    assert httpv.fingerprint("a  \r\nb\n\n") == httpv.fingerprint("a\nb")
