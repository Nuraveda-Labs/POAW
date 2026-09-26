# poaw — Proof of Agent Work

An open protocol and reference implementation for checking what AI agents **claim** they did against what the
**destination** actually shows, and recording the result as a signed, publicly verifiable receipt.

An agent says "I pushed commit `abc123` to `main`". A verifier asks GitHub itself, signs a receipt with the verdict
(verified, failed, mismatch, late, or unverifiable), appends it to an append-only Merkle log, and anchors the log's
root on a public chain. Anyone can check a receipt later without trusting whoever issued it.

## What's here

| Path | What | License |
|---|---|---|
| [`spec/`](spec/) | The receipt specification (`poaw/0.1`, draft), JSON Schema, 20 conformance vectors, and the reference checker | Apache-2.0 |
| [`core-python/`](core-python/) | `poaw-core`: canonical JSON, hashing, signatures, and Merkle log primitives | Apache-2.0 |
| [`node/`](node/) | The reference **node**: claims API, queue, destination verifiers, signer interface, Merkle log, anchoring hooks | AGPL-3.0-only |

`LICENSE-APACHE` applies to everything except `node/`, which carries its own `LICENSE` (AGPL-3.0). Anyone may run the
node; a closed, hosted modification of it must share its changes.

## Check a receipt yourself

```
cd spec
uv run tools/generate_vectors.py --check                     # the vectors match the reference implementation
python tools/check.py --receipt receipt.json --rpc <base-rpc-url>   # signature, log inclusion, on-chain anchor
```

## Principles

- **Evidence comes from the destination**, never from the agent's own report.
- A verifier error, timeout or missing permission gives **unverifiable**, never verified.
- Receipts are **append-only**. They store fingerprints, not content.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
