# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=43", "rfc8785==0.1.4", "jsonschema>=4.23", "eth-abi>=5", "eth-hash[pycryptodome]>=0.7"]
# ///
"""Reference checker for PoAW receipts (SPEC.md §10). Offline it checks steps 1–4. With --rpc it also checks the anchor
against the chain (§8.4). Usage: uv run check.py <receipt.json> <keys.json> [--rpc https://sepolia.base.org]"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[2] / "core-python" / "src"))
import poaw_core as ref  # noqa: E402

SCHEMA = json.loads((Path(__file__).parents[1] / "schema" / "receipt.schema.json").read_text())
_VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def check(receipt: dict, keyset: dict, rpc_url: str | None = None) -> dict:
    """Return a report. `valid` is true only if every check that applies passes."""
    report: dict = {"checks": {}}
    c = report["checks"]

    body = receipt.get("body", {}) if isinstance(receipt, dict) else {}
    version = str(body.get("spec_version", ""))
    c["spec_version"] = version.split("/")[0] == "poaw" and version.split("/")[-1].split(".")[0] == "0"
    c["schema"] = not list(_VALIDATOR.iter_errors(receipt))
    c["integers_only"] = not ref.has_float(receipt)

    sig = receipt.get("signature", {}) if isinstance(receipt, dict) else {}
    key = next((k for k in keyset.get("keys", []) if k["key_id"] == sig.get("key_id")), None)
    issued = body.get("issued_at", "")
    key_ok = bool(
        key
        and sig.get("key_id") == body.get("issuer", {}).get("key_id")
        and ref.key_id(ref.b64u_decode(key["public_key"])) == key["key_id"]
        and key["valid_from"] <= issued
        and (key.get("revoked_at") is None or issued < key["revoked_at"])
    )
    c["key"] = key_ok
    c["signature"] = bool(key_ok and ref.verify_signature(ref.b64u_decode(key["public_key"]), body, sig.get("value", "")))
    claim = body.get("claim", {})
    c["claim_digest"] = isinstance(claim, dict) and claim.get("claim_digest") == ref.claim_digest(claim)

    proof = receipt.get("proof")
    if proof is None:
        c["inclusion"] = "absent"
    else:
        root = ref.root_from_inclusion(
            proof["leaf_index"], proof["tree_size"], ref.leaf_hash(receipt),
            [ref.b64u_decode(h) for h in proof["inclusion"]],
        )
        c["inclusion"] = root is not None and ref.b64u(root) == proof["root_hash"]
    if not (proof and proof.get("anchor")):
        c["anchor"] = "absent"
    elif not rpc_url:
        c["anchor"] = "not_checked_offline"
    else:
        from anchor_check import check_anchor
        a = check_anchor(proof, keyset, rpc_url, ref.b64u_decode)
        c["anchor"] = True if a["ok"] else a["reason"]
        report["proven_by"] = a["proven_by"]

    required = ("spec_version", "schema", "integers_only", "key", "signature", "claim_digest")
    report["valid"] = all(c[k] is True for k in required) and c["inclusion"] in (True, "absent")
    # §7: report the ACHIEVED level. L2 needs inclusion AND an anchor verified on-chain (--rpc); offline the ceiling is 1.
    report["achieved_trust_level"] = (2 if c["inclusion"] is True and c["anchor"] is True else 1) if report["valid"] else 0
    report["verdict"] = body.get("verdict", {}).get("value") if report["valid"] else None
    return report


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("receipt"); ap.add_argument("keys"); ap.add_argument("--rpc")
    args = ap.parse_args()
    receipt = json.loads(Path(args.receipt).read_text())
    keyset = json.loads(Path(args.keys).read_text())
    print(json.dumps(check(receipt, keyset, args.rpc), indent=2))
