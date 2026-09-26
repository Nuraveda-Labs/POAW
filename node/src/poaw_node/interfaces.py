"""Plug-in seams (ARCHITECTURE §2). The node defines them and ships simple reference implementations.
A hosted deployment supplies its own (KMS signer, managed connections, real alert channels).
How a verdict is reached never goes through these seams: that lives in verdict.py and the verifiers.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import poaw_core


class Signer(Protocol):
    def public_key(self) -> bytes: ...          # raw 32-byte Ed25519 public key
    def sign(self, message: bytes) -> bytes: ...  # 64-byte Ed25519 signature over `message` (already domain-prefixed)


class ConnectionStore(Protocol):
    async def credentials(self, workspace_id: str, provider: str, target: str | None = None):
        """An object with `.token()` (and optionally `.account_id()`), or None when there's no access.

        `target` is the claim's target (e.g. `@handle` or `slack://T…/C…`), so a store holding several accounts per
        provider can pick the right one. Stores that hold one credential per provider can ignore it. A store written
        before `target` existed (two arguments only) still works: the node only passes it when the store accepts it.
        """
        ...


class AlertSink(Protocol):
    async def send(self, receipt: dict, *, alert_id: str | None = None, workspace_id: str | None = None) -> None:
        """Deliver one alert. `alert_id` and `workspace_id` let a sink route per workspace and avoid double delivery
        across retries; a simple sink can ignore them."""
        ...


class LocalSigner:
    """Reference signer from a raw 32-byte seed. For development and self-hosting only. Hosted QED signs in KMS."""

    def __init__(self, seed: bytes):
        self._sk = Ed25519PrivateKey.from_private_bytes(seed)

    def public_key(self) -> bytes:
        return poaw_core.public_key_bytes(self._sk)

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)


class _Token:
    def __init__(self, value: str | None):
        self._v = value

    def token(self) -> str | None:
        return self._v

    def account_id(self) -> str | None:
        return None


class EnvConnections:
    """Reference ConnectionStore: `POAW_<PROVIDER>_TOKEN` env vars, the same for every workspace. Ignores `target`.
    With no account binding, verifiers that need one (`x.post.publish`) give `unverifiable/no_connection`."""

    async def credentials(self, workspace_id: str, provider: str, target: str | None = None):
        v = os.environ.get(f"POAW_{provider.upper()}_TOKEN")
        return _Token(v) if v else None


class StdoutAlerts:
    """Reference AlertSink: one JSON line per alert. Carries the verdict and IDs only, never facts beyond the receipt."""

    async def send(self, receipt: dict, *, alert_id: str | None = None, workspace_id: str | None = None) -> None:
        b = receipt["body"]
        print(json.dumps({"event": "alert", "receipt_id": b["receipt_id"], "verdict": b["verdict"],
                          "action": b["claim"]["action"], "target": b["claim"]["target"]}), file=sys.stdout, flush=True)
