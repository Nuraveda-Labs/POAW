# PoAW receipt spec

The Proof of Agent Work receipt format: how an independent verifier records what an AI agent
claimed, what the destination actually showed, and the resulting verdict, in a form anyone can check.

- [`SPEC.md`](SPEC.md): the normative specification (`poaw/0.1`, draft)
- [`schema/receipt.schema.json`](schema/receipt.schema.json): JSON Schema (draft 2020-12) for the structure
- [`profiles/`](profiles/): the verifier profiles (§9.2), one per action
- [`vectors/`](vectors/): 20 conformance vectors plus the manifest of expected results
- [`tools/`](tools/): the reference primitives, reference checker and deterministic vector generator (`uv run tools/generate_vectors.py --check`)

Licensed under Apache-2.0.
