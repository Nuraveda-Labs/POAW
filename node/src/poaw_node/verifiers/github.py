"""github.* verifiers v1 (SPEC §9). Read-only GitHub REST calls. Facts carry IDs and states, never file contents."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import httpx

from ..models import Claim, Observed, Reason, Retry, Unverifiable, Verdict
from . import Params, VerifierSpec, register


class PushParams(Params):
    sha: str
    branch: str


class PrParams(Params):
    number: int
    base: str | None = None
    head_sha: str | None = None


class ChecksParams(Params):
    sha: str

API = "https://api.github.com"
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _headers(creds) -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "poaw-node"}
    tok = creds.token() if creds else None
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _transport_reason(resp: httpx.Response) -> Reason:
    if resp.status_code == 429 or (resp.status_code == 403 and resp.headers.get("x-ratelimit-remaining") == "0"):
        return Reason.RATE_LIMITED
    if resp.status_code in (401, 403):
        return Reason.PERMISSION_DENIED
    return Reason.DESTINATION_UNAVAILABLE


async def _get(client: httpx.AsyncClient, url: str, creds) -> httpx.Response | Retry:
    try:
        return await client.get(url, headers=_headers(creds), timeout=10)
    except httpx.HTTPError as exc:
        return Retry(Reason.DESTINATION_UNAVAILABLE, type(exc).__name__)


def _parse_time(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def commit_push(claim: Claim, creds, client: httpx.AsyncClient):
    """Verified iff `branch` contains `sha` on the remote. Absent SHA → failed (retried until the deadline)."""
    sha, branch = claim.params.get("sha"), claim.params.get("branch")
    if not _REPO.match(claim.target) or not isinstance(sha, str) or not _SHA.match(sha) or not isinstance(branch, str) or not branch:
        return Unverifiable(Reason.CLAIM_AMBIGUOUS, "need target owner/repo, params.sha (40 hex), params.branch")

    r = await _get(client, f"{API}/repos/{claim.target}/commits/{sha}", creds)
    if isinstance(r, Retry):
        return r
    if r.status_code == 404:
        # 404 is also what GitHub returns for a private repo without access, so only a readable repo can blame the agent.
        repo = await _get(client, f"{API}/repos/{claim.target}", creds)
        if isinstance(repo, Retry):
            return repo
        if repo.status_code != 200:
            return Unverifiable(Reason.NO_CONNECTION if not (creds and creds.token()) else Reason.PERMISSION_DENIED,
                                "repository not readable")
        return Observed({"sha": sha, "branch": branch, "commit_found": False}, Verdict.FAILED, Reason.NOT_FOUND,
                        observed_at=_now(), final=False)
    if r.status_code in (422,):
        return Observed({"sha": sha, "branch": branch, "commit_found": False}, Verdict.FAILED, Reason.NOT_FOUND,
                        observed_at=_now(), final=False)
    if r.status_code != 200:
        return Retry(_transport_reason(r), f"commit HTTP {r.status_code}")
    committed_at = _parse_time(r.json().get("commit", {}).get("committer", {}).get("date"))

    c = await _get(client, f"{API}/repos/{claim.target}/compare/{sha}...{branch}", creds)
    if isinstance(c, Retry):
        return c
    if c.status_code == 404:
        return Observed({"sha": sha, "branch": branch, "commit_found": True, "branch_found": False},
                        Verdict.MISMATCH, Reason.TARGET_MISMATCH, observed_at=_now(), final=False)
    if c.status_code != 200:
        return Retry(_transport_reason(c), f"compare HTTP {c.status_code}")
    status = c.json().get("status")  # identical | ahead | behind | diverged, from sha's point of view to branch
    on_branch = status in ("identical", "ahead")
    facts = {"sha": sha, "branch": branch, "commit_found": True, "branch_contains_sha": on_branch}
    if on_branch:
        return Observed(facts, Verdict.VERIFIED, observed_at=_now(), appeared_at=None, final=True)
    return Observed(facts, Verdict.MISMATCH, Reason.TARGET_MISMATCH, observed_at=_now(), final=False)


async def pr_open(claim: Claim, creds, client: httpx.AsyncClient):
    number, base, head_sha = claim.params.get("number"), claim.params.get("base"), claim.params.get("head_sha")
    if not _REPO.match(claim.target) or not isinstance(number, int) or number < 1:
        return Unverifiable(Reason.CLAIM_AMBIGUOUS, "need target owner/repo and integer params.number")
    r = await _get(client, f"{API}/repos/{claim.target}/pulls/{number}", creds)
    if isinstance(r, Retry):
        return r
    if r.status_code == 404:
        return Observed({"number": number, "pr_found": False}, Verdict.FAILED, Reason.NOT_FOUND, observed_at=_now(), final=False)
    if r.status_code != 200:
        return Retry(_transport_reason(r), f"pull HTTP {r.status_code}")
    pr = r.json()
    facts = {"number": number, "pr_found": True, "state": pr.get("state"), "base": pr.get("base", {}).get("ref"),
             "head_sha": pr.get("head", {}).get("sha")}
    if base is not None and facts["base"] != base:
        return Observed(facts, Verdict.MISMATCH, Reason.TARGET_MISMATCH, observed_at=_now())
    if head_sha is not None and facts["head_sha"] != head_sha:
        return Observed(facts, Verdict.MISMATCH, Reason.CONTENT_MISMATCH, observed_at=_now())
    return Observed(facts, Verdict.VERIFIED, observed_at=_now(), appeared_at=_parse_time(pr.get("created_at")))


async def checks_pass(claim: Claim, creds, client: httpx.AsyncClient):
    sha = claim.params.get("sha")
    if not _REPO.match(claim.target) or not isinstance(sha, str) or not _SHA.match(sha):
        return Unverifiable(Reason.CLAIM_AMBIGUOUS, "need target owner/repo and params.sha (40 hex)")
    r = await _get(client, f"{API}/repos/{claim.target}/commits/{sha}/check-runs?per_page=100", creds)
    if isinstance(r, Retry):
        return r
    if r.status_code != 200:
        return Retry(_transport_reason(r), f"check-runs HTTP {r.status_code}")
    runs = r.json().get("check_runs", [])
    if not runs:
        return Observed({"sha": sha, "check_runs": 0}, Verdict.FAILED, Reason.NOT_FOUND, observed_at=_now(), final=False)
    if any(run.get("status") != "completed" for run in runs):
        return Retry(Reason.DESTINATION_UNAVAILABLE, "checks still running")
    ok = {"success", "neutral", "skipped"}
    failing = sorted(run.get("name", "?") for run in runs if run.get("conclusion") not in ok)
    facts = {"sha": sha, "check_runs": len(runs), "failing": failing}
    if failing:
        return Observed(facts, Verdict.MISMATCH, Reason.CONTENT_MISMATCH, observed_at=_now())
    return Observed(facts, Verdict.VERIFIED, observed_at=_now())


register(VerifierSpec("github.commit.push", "1", "github", timedelta(minutes=10), timedelta(minutes=15), commit_push, PushParams))
register(VerifierSpec("github.pr.open", "1", "github", timedelta(minutes=10), timedelta(minutes=15), pr_open, PrParams))
register(VerifierSpec("github.checks.pass", "1", "github", timedelta(hours=1), timedelta(hours=2), checks_pass, ChecksParams))
