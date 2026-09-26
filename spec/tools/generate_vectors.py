# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=43", "rfc8785==0.1.4", "jsonschema>=4.23"]
# ///
"""Generate the PoAW conformance vectors (SPEC.md §13) deterministically.

    uv run oss/spec/tools/generate_vectors.py            # write vectors/
    uv run oss/spec/tools/generate_vectors.py --check    # fail if vectors/ differs (CI)

The signing keys are the PUBLIC test keys from RFC 8032 §7.1 (tests 1 and 2). They are test-only
and must never sign a real receipt.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[2] / "core-python" / "src"))
import poaw_core as ref  # noqa: E402
from check import check  # noqa: E402

OUT = Path(__file__).parents[1] / "vectors"

# RFC 8032 §7.1 TEST 1 and TEST 2 secret keys (published test material).
KEY_A = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))  # gitleaks:allow (RFC 8032 public test key)
KEY_B = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))  # gitleaks:allow (RFC 8032 public test key)
KID_A, KID_B = (ref.key_id(ref.public_key_bytes(k)) for k in (KEY_A, KEY_B))
KEY_B_REVOKED_AT = "2026-06-01T00:00:00.000Z"

KEYSET = {
    "keys": [
        {"key_id": KID_A, "public_key": ref.b64u(ref.public_key_bytes(KEY_A)), "valid_from": "2026-01-01T00:00:00.000Z", "revoked_at": None},
        {"key_id": KID_B, "public_key": ref.b64u(ref.public_key_bytes(KEY_B)), "valid_from": "2026-01-01T00:00:00.000Z", "revoked_at": KEY_B_REVOKED_AT},
    ]
}

FP_POST = "sha256:" + ref.b64u(ref.sha256(b"Shipping receipts for agents today."))
FP_OTHER = "sha256:" + ref.b64u(ref.sha256(b"A different post."))


def claim(action: str, target: str, params: dict, n: int) -> dict:
    c = {"action": action, "target": target, "params": params,
         "claimed_at": "2026-09-25T14:01:58.000Z", "client_claim_id": f"example-{n:03d}"}
    c["claim_digest"] = ref.claim_digest(c)
    return c


def body(n: int, verdict: dict, *, kid: str = KID_A, issued_at: str = "2026-09-25T14:02:12.000Z",
         action: str = "x.post.publish", facts: dict | None = None, trust_level: int = 1) -> dict:
    return {
        "spec_version": ref.SPEC_VERSION,
        "receipt_id": f"rcpt_01J8Z6Q4W3EXAMPLE{n:06d}",
        "issued_at": issued_at,
        "issuer": {"key_id": kid, "name": "example-issuer"},
        "agent": {"id": "agent-example-1"},
        "claim": claim(action, "x.com/example", {"content_fingerprint": FP_POST}, n),
        "observation": {
            "verifier": {"id": action, "version": "1"},
            "observed_at": "2026-09-25T14:02:11.000Z",
            "deadline_at": "2026-09-25T14:17:58.000Z",
            "attempts": 1,
            "facts": facts if facts is not None else {"found": True, "post_id": "1840200000000000001", "content_fingerprint": FP_POST},
        },
        "verdict": verdict,
        "trust_level": trust_level,
    }


def signed(b: dict, key: Ed25519PrivateKey = KEY_A) -> dict:  # gitleaks:allow — a type annotation, not a secret
    return {"body": b, "signature": ref.sign_body(key, b)}


def build() -> list[tuple[str, str, dict, dict]]:
    """(name, description, receipt, expected) — expected is filled from the reference checker and then
    asserted against the intent written here, so a checker bug can't silently redefine the vectors."""
    V: list[tuple[str, str, dict, dict]] = []

    def add(name, desc, receipt, valid, verdict=None):
        V.append((name, desc, receipt, {"valid": valid, "verdict": verdict if valid else None}))

    # --- valid receipts, one per verdict --------------------------------------------------------
    add("001-valid-verified", "Signed L1 receipt, verified.", signed(body(1, {"value": "verified"})), True, "verified")
    add("002-valid-late", "Outcome present but after tolerance.",
        signed(body(2, {"value": "late", "reason_code": "observed_after_tolerance"})), True, "late")
    add("003-valid-mismatch", "Post exists with a different fingerprint.",
        signed(body(3, {"value": "mismatch", "reason_code": "content_mismatch"},
                    facts={"found": True, "post_id": "1840200000000000003", "content_fingerprint": FP_OTHER})), True, "mismatch")
    add("004-valid-failed", "Destination read, outcome absent by deadline.",
        signed(body(4, {"value": "failed", "reason_code": "not_found"}, facts={"found": False})), True, "failed")
    add("005-valid-unverifiable", "Destination rate-limited until deadline.",
        signed(body(5, {"value": "unverifiable", "reason_code": "rate_limited"}, facts={})), True, "unverifiable")
    add("006-valid-key-b-before-revocation", "Key B, issued before its revocation: still valid.",
        signed(body(6, {"value": "verified"}, kid=KID_B, issued_at="2026-05-31T23:59:59.000Z"), KEY_B), True, "verified")

    # --- signature and key failures ---------------------------------------------------------------
    r = signed(body(7, {"value": "failed", "reason_code": "not_found"}))
    r["body"]["verdict"] = {"value": "verified"}  # altered after signing
    add("007-tampered-verdict", "Verdict changed from failed to verified after signing.", r, False)

    b = body(8, {"value": "verified"})  # claims key A…
    add("008-wrong-key", "Body names key A but was signed with key B.", {"body": b, "signature": {**ref.sign_body(KEY_B, b), "key_id": KID_A}}, False)

    b = body(9, {"value": "verified"}, kid="ed25519:" + ref.b64u(ref.sha256(b"unknown key")))
    s = ref.sign_body(KEY_A, b)
    add("009-unknown-key", "key_id not present in the issuer's key set.", {"body": b, "signature": {**s, "key_id": b["issuer"]["key_id"]}}, False)

    add("010-revoked-key", "Key B, issued after its revocation.",
        signed(body(10, {"value": "verified"}, kid=KID_B, issued_at="2026-09-25T14:02:12.000Z"), KEY_B), False)

    # --- structural failures ----------------------------------------------------------------------
    b = body(11, {"value": "verified"})
    b["claim"]["target"] = "x.com/someone-else"  # digest no longer matches (then re-signed, so only the digest fails)
    add("011-bad-claim-digest", "claim_digest does not match the claim.", signed(b), False)

    add("012-unverifiable-without-reason", "unverifiable MUST carry a reason_code (schema).",
        signed(body(12, {"value": "unverifiable"}, facts={})), False)
    add("013-level3-without-attestation", "trust_level 3 requires attestation + code_hash (schema).",
        signed(body(13, {"value": "verified"}, trust_level=3)), False)

    b = body(14, {"value": "verified"})
    b["observation"]["facts"]["score"] = 0.5
    add("014-float-in-body", "Floating-point numbers are not allowed (§3).", signed(b), False)

    b = body(15, {"value": "verified"})
    b["spec_version"] = "poaw/1.0"
    add("015-unsupported-major-version", "Unknown major spec_version must be rejected.", signed(b), False)

    # --- log inclusion (§8) -----------------------------------------------------------------------
    log = [signed(body(100 + i, {"value": "verified"}, trust_level=2)) for i in range(7)]
    leaves = [ref.leaf_hash(x) for x in log]
    root = ref.b64u(ref.mth(leaves))

    def with_proof(i: int) -> dict:
        x = copy.deepcopy(log[i])
        x["proof"] = {"log_id": ref.b64u(ref.sha256(b"example-log")), "leaf_index": i, "tree_size": len(log),
                      "root_hash": root, "inclusion": [ref.b64u(h) for h in ref.inclusion_path(i, leaves)]}
        return x

    add("016-inclusion-first-leaf", "Valid inclusion proof, leaf 0 of 7. Claims L2 but has no anchor: achieved level 1.", with_proof(0), True, "verified")
    add("017-inclusion-last-leaf", "Valid inclusion proof, leaf 6 of 7 (unbalanced edge).", with_proof(6), True, "verified")
    add("018-inclusion-middle-leaf", "Valid inclusion proof, leaf 3 of 7.", with_proof(3), True, "verified")
    x = with_proof(3)
    x["proof"]["inclusion"][0] = ref.b64u(ref.sha256(b"not a sibling"))
    add("019-bad-inclusion-path", "Altered audit path.", x, False)
    x = with_proof(3)
    x["proof"]["leaf_index"] = 4
    add("020-wrong-leaf-index", "Correct path, wrong index.", x, False)
    return V


def main() -> int:
    vectors = build()
    files: dict[str, str] = {"keys.json": json.dumps(KEYSET, indent=2, sort_keys=True) + "\n"}
    manifest = []
    for name, desc, receipt, intent in vectors:
        got = check(receipt, KEYSET)
        if got["valid"] != intent["valid"] or got["verdict"] != intent["verdict"]:
            print(f"reference checker disagrees with intent for {name}: {got}", file=sys.stderr)
            return 1
        files[f"{name}.json"] = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        manifest.append({"file": f"{name}.json", "description": desc, "expected": {
            "valid": got["valid"], "verdict": got["verdict"], "achieved_trust_level": got["achieved_trust_level"],
            "checks": got["checks"]}})
    files["manifest.json"] = json.dumps({"spec_version": ref.SPEC_VERSION, "keyset": "keys.json", "vectors": manifest}, indent=2, sort_keys=True) + "\n"

    if "--check" in sys.argv:
        stale = [n for n, t in files.items() if not (OUT / n).exists() or (OUT / n).read_text() != t]
        extra = sorted({p.name for p in OUT.glob("*.json")} - set(files))
        if stale or extra:
            print(f"vectors out of date: stale={stale} extra={extra}", file=sys.stderr)
            return 1
        print(f"vectors up to date ({len(vectors)} vectors)")
        return 0
    OUT.mkdir(exist_ok=True)
    for n, t in files.items():
        (OUT / n).write_text(t)
    print(f"wrote {len(vectors)} vectors + keys.json + manifest.json to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
