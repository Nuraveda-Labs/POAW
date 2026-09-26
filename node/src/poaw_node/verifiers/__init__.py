"""Verifier plugins (SPEC §9). A verifier reads the destination and returns Observed | Retry | Unverifiable.

It never decides the final verdict: `verdict.decide` does. It never raises on purpose: transport errors become Retry.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Awaitable, Callable, Protocol

from pydantic import BaseModel, ConfigDict

from ..models import Claim, VerifierResult


class Credentials(Protocol):
    """Resolved at call time from the ConnectionStore. Only verifiers see it, and it's never persisted or logged."""

    def token(self) -> str | None: ...


class Params(BaseModel):
    """Base for a verifier's params model. Unknown keys are rejected, because params are copied into public receipts (SECURITY F3)."""

    model_config = ConfigDict(extra="forbid", strict=True)


@dataclass(frozen=True)
class VerifierSpec:
    action: str
    version: str
    provider: str | None  # connection provider this verifier needs (None = public destination)
    tolerance: timedelta  # appeared within claimed_at + tolerance → verified, later → late
    deadline: timedelta  # how long to keep looking after claimed_at
    run: Callable[[Claim, Any, Any], Awaitable[VerifierResult]]  # (claim, credentials | None, http_client)
    params: type[Params] = Params  # the allowed claim params (extra keys → 422)


REGISTRY: dict[str, VerifierSpec] = {}


def register(spec: VerifierSpec) -> VerifierSpec:
    if spec.action in REGISTRY:
        raise ValueError(f"duplicate verifier for {spec.action}")
    REGISTRY[spec.action] = spec
    return spec


def load_builtin() -> dict[str, VerifierSpec]:
    from . import github, http  # noqa: F401  (registration side effect)
    return REGISTRY
