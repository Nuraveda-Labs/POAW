"""Orchestration: check a claim → decide → sign → record → alert. Used by both the API (first check inline) and the tick."""
from __future__ import annotations

import inspect
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
import poaw_core

from . import receipt as rc
from .interfaces import AlertSink, ConnectionStore, Signer
from .models import Claim, ClaimIn, Reason, Unverifiable, Verdict
from .store import Store
from .verdict import decide
from .verifiers import REGISTRY, load_builtin

ALERT_ON = {Verdict.FAILED, Verdict.LATE, Verdict.MISMATCH}
UNSUPPORTED_DEADLINE = timedelta(seconds=0)


@dataclass
class Node:
    store: Store
    signer: Signer
    connections: ConnectionStore
    alerts: AlertSink
    http: httpx.AsyncClient
    issuer_name: str = "poaw-node"
    alert_sink_name: str = "default"

    def __post_init__(self) -> None:
        load_builtin()
        self.key_id = poaw_core.key_id(self.signer.public_key())

    # -- intake ---------------------------------------------------------------------------------------------------
    @staticmethod
    def validate_params(c: ClaimIn) -> None:
        """Raise ValueError if params don't match the action's declared model (SECURITY F3)."""
        spec = REGISTRY.get(c.action)
        if spec is None:
            if c.params:
                raise ValueError("params must be empty for an action with no verifier")
            return
        spec.params.model_validate(c.params)

    async def submit(self, workspace_id: str, c: ClaimIn) -> tuple[Claim, bool]:
        self.validate_params(c)
        spec = REGISTRY.get(c.action)
        deadline = c.claimed_at + (spec.deadline if spec else UNSUPPORTED_DEADLINE)
        digest_obj = {"action": c.action, "target": c.target, "params": c.params, "claimed_at": rc.ts(c.claimed_at),
                      "client_claim_id": c.client_claim_id}
        return await self.store.submit(workspace_id, c, claim_digest=poaw_core.claim_digest(digest_obj),
                                       deadline_at=deadline)

    # -- checking -------------------------------------------------------------------------------------------------
    async def check(self, claim: Claim, *, attempts: int, now: datetime | None = None) -> str | None:
        """Run one check. Returns the receipt_id once decided, or None if the claim was rescheduled."""
        now = now or datetime.now(timezone.utc)
        spec = REGISTRY.get(claim.action)
        if spec is None:
            result = Unverifiable(Reason.UNSUPPORTED_ACTION, claim.action)
            verifier_id, version, tolerance = claim.action, "0", timedelta(0)
        else:
            verifier_id, version, tolerance = spec.action, spec.version, spec.tolerance
            try:
                creds = await _credentials(self.connections, claim, spec.provider) if spec.provider else None
                result = await spec.run(claim, creds, self.http)
            except Exception as exc:  # a verifier bug must never pass a claim
                result = exc

        decision = decide(result, claimed_at=claim.claimed_at, deadline_at=claim.deadline_at, now=now,
                          tolerance=tolerance)
        if decision is None:
            backoff = min(timedelta(seconds=30 * (2 ** min(attempts, 5))), timedelta(minutes=10))
            await self.store.reschedule(claim.id, min(now + backoff, claim.deadline_at), _describe(result))
            return None

        body = rc.build_body(claim=claim, decision=decision, verifier_id=verifier_id, verifier_version=version,
                             attempts=attempts, issuer_key_id=self.key_id, issuer_name=self.issuer_name, issued_at=now)
        signed = rc.sign(body, self.signer)
        await self.store.record(claim, signed, alert=decision.verdict in ALERT_ON, sink=self.alert_sink_name)
        return body["receipt_id"]

    async def tick(self, *, limit: int = 25, budget_s: float = 45.0) -> dict:
        """One scheduled pass: lease due claims, check each, then flush alerts. Stops taking work at the budget."""
        import time
        start, done, rescheduled = time.monotonic(), 0, 0
        for claim in await self.store.lease_due(limit, timedelta(minutes=2)):
            if time.monotonic() - start > budget_s:
                break
            rid = await self.check(claim, attempts=claim.attempts)
            done, rescheduled = done + (rid is not None), rescheduled + (rid is None)
        sent = await self.flush_alerts()
        return {"decided": done, "rescheduled": rescheduled, "alerts_sent": sent}

    async def flush_alerts(self) -> int:
        sent = 0
        for a in await self.store.pending_alerts():
            try:
                await self.alerts.send(a["receipt"], alert_id=a["alert_id"], workspace_id=a.get("workspace_id"))
                await self.store.mark_alert(a["alert_id"], True)
                sent += 1
            except Exception as exc:
                await self.store.mark_alert(a["alert_id"], False, type(exc).__name__)
        return sent


def _accepts_target(store) -> bool:
    """Whether `store.credentials` takes a `target` argument. Stores written before it existed take two."""
    try:
        params = inspect.signature(store.credentials).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == "target" or p.kind is inspect.Parameter.VAR_KEYWORD for p in params)


async def _credentials(store, claim: Claim, provider: str):
    if _accepts_target(store):
        return await store.credentials(claim.workspace_id, provider, target=claim.target)
    return await store.credentials(claim.workspace_id, provider)


def _describe(result) -> str:
    if isinstance(result, BaseException):
        return f"exception:{type(result).__name__}"
    reason = getattr(result, "reason", None)
    return f"{type(result).__name__}:{getattr(reason, 'value', reason)}"
