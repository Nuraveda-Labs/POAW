# Conformance vectors — poaw/0.1

Every conforming checker MUST produce the `expected` result in `manifest.json` for every vector,
using `keys.json` as the issuer's key set.

- `manifest.json`: one entry per vector, with `description` and `expected` (`valid`, `verdict`, `achieved_trust_level`, and per-check results)
- `keys.json`: the issuer key set (§5.2). **The keys are the public RFC 8032 §7.1 test keys (TEST 1 and TEST 2). They are test-only.**
- `NNN-*.json`: the receipts

The vectors cover a valid receipt for every verdict value, key validity windows (including a revoked key used before and after
revocation), tampering, a wrong or unknown key, claim-digest mismatch, schema violations, non-integer numbers, an unsupported
major version, and RFC 6962 inclusion proofs (first, middle and last leaf of an unbalanced tree, plus altered path and index).

**Not covered offline:** anchor checks (§8.4) need a blockchain RPC, and attestation (trust level ≥ 3) needs a platform root of
trust. A receipt that claims level 2 without a verifiable anchor is reported at its *achieved* level, 1 (vector 016).

Regenerate with `uv run oss/spec/tools/generate_vectors.py`. CI runs it with `--check`, and it fails on any byte difference.
The generator asserts that the reference checker agrees with the intent written for each vector, so a checker bug can't
quietly redefine what the vectors mean.
