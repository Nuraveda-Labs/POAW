"""poaw_core — the one implementation of the PoAW receipt primitives (poaw/0.1).

Deliberately small and dependency-light: this is the executable form of SPEC.md §3, §5 and §8,
Shared by the spec tools, the node and the SDK. The conformance vectors are its test suite.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SPEC_VERSION = "poaw/0.1"
SIG_DOMAIN = b"POAW-RECEIPT-V0\n"


# --- encoding (§3) ---------------------------------------------------------------------------
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jcs(obj: Any) -> bytes:
    return rfc8785.dumps(obj)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def has_float(obj: Any) -> bool:
    """§3: receipts carry integers only."""
    if isinstance(obj, bool):
        return False
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(has_float(v) for v in obj.values())
    if isinstance(obj, list):
        return any(has_float(v) for v in obj)
    return False


# --- keys + signatures (§5) ------------------------------------------------------------------
def public_key_bytes(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def key_id(pk_raw: bytes) -> str:
    return "ed25519:" + b64u(sha256(pk_raw))


def sign_body(sk: Ed25519PrivateKey, body: dict) -> dict:
    kid = key_id(public_key_bytes(sk))
    return {"alg": "Ed25519", "key_id": kid, "value": b64u(sk.sign(SIG_DOMAIN + jcs(body)))}


def verify_signature(pk_raw: bytes, body: dict, sig_value: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk_raw).verify(b64u_decode(sig_value), SIG_DOMAIN + jcs(body))
        return True
    except (InvalidSignature, ValueError):
        return False


def claim_digest(claim: dict) -> str:
    stripped = {k: v for k, v in claim.items() if k != "claim_digest"}
    return b64u(sha256(jcs(stripped)))


# --- Merkle log, RFC 6962 (§8) ---------------------------------------------------------------
def leaf_hash(receipt: dict) -> bytes:
    return sha256(b"\x00" + jcs({"body": receipt["body"], "signature": receipt["signature"]}))


def _node(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def _split(n: int) -> int:
    """Largest power of two strictly less than n (RFC 6962 §2.1)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def mth(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return _node(mth(leaves[:k]), mth(leaves[k:]))


def inclusion_path(index: int, leaves: list[bytes]) -> list[bytes]:
    n = len(leaves)
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_path(index, leaves[:k]) + [mth(leaves[k:])]
    return inclusion_path(index - k, leaves[k:]) + [mth(leaves[:k])]


def root_from_inclusion(index: int, size: int, leaf: bytes, path: list[bytes]) -> bytes | None:
    """RFC 9162 §2.1.3.2 audit-path verification. Returns the computed root, or None if the path is malformed."""
    if index >= size:
        return None
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = _node(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


# --- Consistency proofs + node-store proofs (SPEC §8.4, RFC 6962 §2.1.2, RFC 9162 §2.1.4) ------------------------
# A "view" answers mth(a, b) = MTH(D[a:b]). Every range RFC 6962 asks for is either a single leaf, an aligned
# power-of-two block (a stored complete-subtree node: level = log2(size), idx = a >> level), or splits into those.
# So proofs over a node store touch O(log n) nodes, never every leaf.

def _pow2(n: int) -> bool:
    return n > 0 and n & (n - 1) == 0


def mth_range(a: int, b: int, get_node) -> bytes:
    """MTH of leaves [a, b) from complete-subtree nodes. get_node(level, idx) → 32-byte hash."""
    n = b - a
    if n <= 0:
        raise ValueError("empty range")
    if _pow2(n) and a % n == 0:
        level = n.bit_length() - 1
        return get_node(level, a >> level)
    k = _split(n)
    return _node(mth_range(a, a + k, get_node), mth_range(a + k, b, get_node))


def inclusion_path_nodes(index: int, size: int, get_node, lo: int = 0) -> list[bytes]:
    """RFC 6962 PATH(index, D[lo:lo+size]) computed from stored nodes."""
    if size <= 1:
        return []
    k = _split(size)
    if index < k:
        return inclusion_path_nodes(index, k, get_node, lo) + [mth_range(lo + k, lo + size, get_node)]
    return inclusion_path_nodes(index - k, size - k, get_node, lo + k) + [mth_range(lo, lo + k, get_node)]


def consistency_proof_nodes(m: int, n: int, get_node) -> list[bytes]:
    """RFC 6962 PROOF(m, D[n]) for 0 < m <= n, computed from stored nodes."""
    if not 0 < m <= n:
        raise ValueError("need 0 < m <= n")

    def sub(m: int, lo: int, size: int, b: bool) -> list[bytes]:
        if m == size:
            return [] if b else [mth_range(lo, lo + size, get_node)]
        k = _split(size)
        if m <= k:
            return sub(m, lo, k, b) + [mth_range(lo + k, lo + size, get_node)]
        return sub(m - k, lo + k, size - k, False) + [mth_range(lo, lo + k, get_node)]

    return sub(m, 0, n, True)


def list_view(leaves: list[bytes]):
    """A get_node over an in-memory leaf list (used for tests and the spec vectors)."""
    def get(level: int, idx: int) -> bytes:
        size = 1 << level
        return mth(leaves[idx * size:(idx + 1) * size])
    return get


def consistency_proof(m: int, n: int, leaves: list[bytes]) -> list[bytes]:
    return consistency_proof_nodes(m, n, list_view(leaves[:n]))


def verify_consistency(m: int, n: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool:
    """RFC 9162 §2.1.4.2. True iff `proof` shows the size-m tree (old_root) is a prefix of the size-n tree (new_root)."""
    if not 0 < m <= n:
        return False
    if m == n:
        return not proof and old_root == new_root
    if not proof:
        return False
    path = list(proof)
    if _pow2(m):
        path = [old_root] + path
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = _node(c, fr), _node(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


def nodes_completed_by(leaf_index: int, leaf: bytes, get_node) -> list[tuple[int, int, bytes]]:
    """The (level, idx, hash) nodes that appending leaf #leaf_index completes: the leaf itself plus every ancestor whose
    block ends at this leaf. The caller persists them in the same transaction as the leaf."""
    out = [(0, leaf_index, leaf)]
    level, idx, h = 0, leaf_index, leaf
    while idx & 1:  # a right child completes its parent
        left = get_node(level, idx - 1)
        h = _node(left, h)
        level, idx = level + 1, idx >> 1
        out.append((level, idx, h))
    return out
