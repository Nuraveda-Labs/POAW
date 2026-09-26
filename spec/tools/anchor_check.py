"""SPEC §8.4: check a receipt's `proof.anchor` (scheme `eas`) against a public JSON-RPC endpoint. It needs no issuer API.

It needs only the chain: EAS.getAttestation(uid) must be a live, unrevoked attestation made by an address the issuer
publishes, under a schema the issuer publishes, whose data decodes to this proof's (log_id, tree_size, root_hash).
"""
from __future__ import annotations

import json
import urllib.request

from eth_abi import decode as abi_decode
from eth_hash.auto import keccak

EAS = "0x4200000000000000000000000000000000000021"  # the OP-stack predeploy (Base mainnet + Base Sepolia)
_GET = keccak(b"getAttestation(bytes32)")[:4]
_ATT = "(bytes32,bytes32,uint64,uint64,uint64,bytes32,address,address,bool,bytes)"
_DATA = ["bytes32", "uint64", "bytes32", "uint64", "bytes32", "string"]


def _rpc(url: str, method: str, *params):
    req = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode(),
                                 {"content-type": "application/json", "user-agent": "poaw-check/0.1"})
    with urllib.request.urlopen(req, timeout=20) as r:
        body = json.loads(r.read())
    if "error" in body:
        raise RuntimeError(f"{method}: {body['error'].get('message')}")
    return body["result"]


def check_anchor(proof: dict, keyset: dict, rpc_url: str, b64u_decode) -> dict:
    """Return {"ok": bool, "reason": str, "proven_by": unix seconds | None}. Any doubt → ok False, never a pass."""
    a = proof["anchor"]
    try:
        if a.get("scheme") != "eas":
            return {"ok": False, "reason": "unknown_scheme", "proven_by": None}
        if int(_rpc(rpc_url, "eth_chainId"), 16) != int(str(a["chain"]).split(":")[1]):
            return {"ok": False, "reason": "rpc_chain_mismatch", "proven_by": None}
        uid = bytes.fromhex(a["uid"][2:])
        out = _rpc(rpc_url, "eth_call", {"to": EAS, "data": "0x" + (_GET + uid).hex()}, "latest")
        (att,) = abi_decode([_ATT], bytes.fromhex(out[2:]))
        uid_, schema, time_, _exp, revoked_at, _ref, _recipient, attester, _revocable, data = att
    except Exception as exc:  # network, decode or shape errors: the anchor is unproven, not proven
        return {"ok": False, "reason": f"unreadable:{type(exc).__name__}", "proven_by": None}
    if uid_ != uid or time_ == 0:
        return {"ok": False, "reason": "attestation_not_found", "proven_by": None}
    if revoked_at:
        return {"ok": False, "reason": "attestation_revoked", "proven_by": None}
    if attester.lower() not in {x.lower() for x in keyset.get("anchor_addresses", [])}:
        return {"ok": False, "reason": "attester_not_published", "proven_by": None}
    if "0x" + schema.hex() not in {x.lower() for x in keyset.get("anchor_schemas", [])}:
        return {"ok": False, "reason": "schema_not_published", "proven_by": None}
    try:
        log_id, size, root, _prev_size, _prev_root, _spec = abi_decode(_DATA, data)
    except Exception:
        return {"ok": False, "reason": "data_undecodable", "proven_by": None}
    if log_id != b64u_decode(proof["log_id"]) or size != a["tree_size"]:
        return {"ok": False, "reason": "log_or_size_mismatch", "proven_by": None}
    if a["tree_size"] != proof["tree_size"]:
        return {"ok": False, "reason": "consistency_proof_required", "proven_by": None}  # this issuer proves at the anchored size
    if root != b64u_decode(proof["root_hash"]):
        return {"ok": False, "reason": "root_mismatch", "proven_by": None}
    return {"ok": True, "reason": "anchored", "proven_by": time_}  # EAS sets time = block.timestamp
