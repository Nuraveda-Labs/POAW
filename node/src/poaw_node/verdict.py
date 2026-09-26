"""The ONLY place a verdict is decided (ARCHITECTURE §3). Deterministic and total.

Rules (SPEC §6.2):
1. Fail toward `unverifiable`, never toward `verified`.
2. `failed` and `mismatch` need a successful read of the destination (an `Observed` result).
3. No model output ever reaches this function. It sees only the claim window and verifier results.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from .models import Decision, Observed, Reason, Retry, Unverifiable, Verdict, VerifierResult


def decide(result: VerifierResult | BaseException | object, *, claimed_at: datetime, deadline_at: datetime,
           now: datetime, tolerance: timedelta) -> Decision | None:
    """Return a final Decision, or None when the claim should be retried later.

    Never raises: anything unexpected becomes `unverifiable/verifier_error`.
    """
    try:
        return _decide(result, claimed_at=claimed_at, deadline_at=deadline_at, now=now, tolerance=tolerance)
    except Exception:  # totality: a bug in here must not produce a pass
        return Decision(Verdict.UNVERIFIABLE, Reason.VERIFIER_ERROR)


def _decide(result, *, claimed_at, deadline_at, now, tolerance) -> Decision | None:
    past_deadline = now >= deadline_at

    if isinstance(result, BaseException):
        return Decision(Verdict.UNVERIFIABLE, Reason.VERIFIER_ERROR) if past_deadline else None

    if isinstance(result, Unverifiable):
        return Decision(Verdict.UNVERIFIABLE, result.reason)

    if isinstance(result, Retry):
        return Decision(Verdict.UNVERIFIABLE, result.reason) if past_deadline else None

    if not isinstance(result, Observed):
        return Decision(Verdict.UNVERIFIABLE, Reason.VERIFIER_ERROR)

    if result.outcome not in (Verdict.VERIFIED, Verdict.MISMATCH, Verdict.FAILED):
        return Decision(Verdict.UNVERIFIABLE, Reason.VERIFIER_ERROR, observed_at=result.observed_at)

    if result.outcome is Verdict.FAILED:
        if not result.final and not past_deadline:
            return None  # absent so far, so keep looking until the deadline
        return Decision(Verdict.FAILED, result.reason or Reason.NOT_FOUND, result.facts, result.observed_at)

    if result.outcome is Verdict.MISMATCH:
        return Decision(Verdict.MISMATCH, result.reason or Reason.CONTENT_MISMATCH, result.facts, result.observed_at)

    # VERIFIED: late if it appeared after the claim time plus tolerance.
    if result.appeared_at is not None and result.appeared_at > claimed_at + tolerance:
        return Decision(Verdict.LATE, Reason.OBSERVED_AFTER_TOLERANCE, result.facts, result.observed_at)
    return Decision(Verdict.VERIFIED, None, result.facts, result.observed_at)
