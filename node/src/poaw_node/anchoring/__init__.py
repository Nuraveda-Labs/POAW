"""Anchoring the log's root on an EVM chain through EAS attestations (SPEC §8). Optional: install `poaw-node[anchor]`.

`anchor.Anchorer` runs after each tick and attests a new signed tree head at most every `interval`, with a daily gas
ceiling, a minimum balance, and fork/consistency refusals. `eth` holds the ABI, transaction signing and JSON-RPC client.
A signer is any `eth.EthSigner`: `eth.local_signer(...)` for a key you hold, or `eth.kms_signer(...)` for AWS KMS.
"""
