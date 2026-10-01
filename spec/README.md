# PoAW receipt spec

The Proof of Agent Work receipt format: how an independent verifier records what an AI agent
claimed, what the destination actually showed, and the resulting verdict, in a form anyone can check.

- [`SPEC.md`](SPEC.md): the normative specification (`poaw/0.2`, draft; `poaw/0.1` receipts stay valid)
- [`schema/receipt.schema.json`](schema/receipt.schema.json): JSON Schema (draft 2020-12) for the structure
- [`schema/change.schema.json`](schema/change.schema.json): the schema for a change entry (§14), an unclaimed change recorded in the log
- [`schema/pipeline.schema.json`](schema/pipeline.schema.json): the schema for a pipeline document (§15)
- [`profiles/`](profiles/): the verifier profiles (§9.2), one per action
- [`vectors/`](vectors/): 35 conformance vectors plus the manifest of expected results
- [`tools/`](tools/): the reference primitives, reference checker and deterministic vector generator (`uv run tools/generate_vectors.py --check`)

Licensed under Apache-2.0.
