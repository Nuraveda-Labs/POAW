"""Minimal Ethereum (Base) client for anchoring: KMS-signed EIP-1559 transactions, EAS calls, JSON-RPC.

Deliberately small (no web3.py): RLP + eth-abi + eth-keys. The private key lives in AWS KMS (ECC_SECG_P256K1). We sign
the keccak digest with ECDSA_SHA_256 / MessageType DIGEST, then low-s normalise, and find the recovery id by recovering the
address. A signature that doesn't recover to our address is never sent.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

import httpx
import rlp
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_hash.auto import keccak
from eth_keys import keys as eth_keys

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
EAS = "0x4200000000000000000000000000000000000021"
SCHEMA_REGISTRY = "0x4200000000000000000000000000000000000020"
ZERO_ADDR = "0x" + "00" * 20
ANCHOR_SCHEMA = ("bytes32 logId,uint64 treeSize,bytes32 rootHash,uint64 prevTreeSize,bytes32 prevRootHash,string specVersion")
CHAINS = {"eip155:84532": "https://sepolia.base.org", "eip155:8453": "https://mainnet.base.org"}


def checksum(addr_hex: str) -> str:
    a = addr_hex.lower().removeprefix("0x")
    h = keccak(a.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c for i, c in enumerate(a))


def address_from_uncompressed(pub65: bytes) -> str:
    return checksum(keccak(pub65[1:])[-20:].hex())


def selector(sig: str) -> bytes:
    return keccak(sig.encode())[:4]


def schema_uid(schema: str, resolver: str = ZERO_ADDR, revocable: bool = False) -> bytes:
    """EAS SchemaRegistry: keccak256(abi.encodePacked(schema, resolver, revocable))."""
    return keccak(schema.encode() + bytes.fromhex(resolver[2:]) + (b"\x01" if revocable else b"\x00"))


def register_calldata(schema: str = ANCHOR_SCHEMA) -> bytes:
    return selector("register(string,address,bool)") + abi_encode(["string", "address", "bool"], [schema, ZERO_ADDR, False])


def anchor_data(log_id: bytes, tree_size: int, root: bytes, prev_size: int, prev_root: bytes, spec_version: str) -> bytes:
    return abi_encode(["bytes32", "uint64", "bytes32", "uint64", "bytes32", "string"],
                      [log_id, tree_size, root, prev_size, prev_root, spec_version])


def decode_anchor_data(data: bytes) -> dict:
    log_id, size, root, prev_size, prev_root, spec = abi_decode(
        ["bytes32", "uint64", "bytes32", "uint64", "bytes32", "string"], data)
    return {"log_id": log_id, "tree_size": size, "root_hash": root, "prev_tree_size": prev_size,
            "prev_root_hash": prev_root, "spec_version": spec}


def attest_calldata(schema: bytes, data: bytes) -> bytes:
    """EAS.attest(AttestationRequest{schema, data: {recipient, expirationTime, revocable, refUID, data, value}})."""
    return selector("attest((bytes32,(address,uint64,bool,bytes32,bytes,uint256)))") + abi_encode(
        ["(bytes32,(address,uint64,bool,bytes32,bytes,uint256))"],
        [(schema, (ZERO_ADDR, 0, False, b"\x00" * 32, data, 0))])


def schema_registered(rpc: "Rpc", uid: bytes) -> bool:
    """SchemaRegistry.getSchema(uid) → SchemaRecord(uid, resolver, revocable, schema). The record holds a string, so the return
    data is a dynamic tuple (an offset word comes first). Decode it; never slice raw words. Registered ⇔ record.uid == uid."""
    out = rpc.call("eth_call", {"to": SCHEMA_REGISTRY, "data": "0x" + (selector("getSchema(bytes32)") + uid).hex()}, "latest")
    ((got_uid, _resolver, _revocable, schema),) = abi_decode(["(bytes32,address,bool,string)"], _b(out))
    return got_uid == uid and schema == ANCHOR_SCHEMA


# --- signing ---------------------------------------------------------------------------------------------------------
def _low_s(r: int, s: int) -> tuple[int, int]:
    return (r, SECP256K1_N - s) if s > SECP256K1_N // 2 else (r, s)


@dataclass
class EthSigner:
    """`sign_digest(digest32) -> DER ECDSA signature` (KMS, or a local key in tests). `address` is the expected signer."""

    address: str
    sign_digest: Callable[[bytes], bytes]

    def vrs(self, digest: bytes) -> tuple[int, int, int]:
        r, s = _low_s(*decode_dss_signature(self.sign_digest(digest)))
        for v in (0, 1):
            sig = eth_keys.Signature(vrs=(v, r, s))
            if sig.recover_public_key_from_msg_hash(digest).to_checksum_address() == self.address:
                return v, r, s
        raise RuntimeError("signature does not recover to the anchor address; refusing to use it")


def kms_signer(key_id: str, kms_client) -> EthSigner:
    der = kms_client.get_public_key(KeyId=key_id)["PublicKey"]
    pub = load_der_public_key(der).public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return EthSigner(address_from_uncompressed(pub), lambda d: kms_client.sign(
        KeyId=key_id, Message=d, MessageType="DIGEST", SigningAlgorithm="ECDSA_SHA_256")["Signature"])


def local_signer(private_key: bytes) -> EthSigner:
    """An EthSigner from a raw 32-byte secp256k1 private key you hold (self-hosting, or tests). Keep the key in a
    secret store or a file only the node can read; never in the repository."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    if len(private_key) != 32:
        raise ValueError("a secp256k1 private key is 32 bytes")
    key = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
    pub = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return EthSigner(address_from_uncompressed(pub), lambda d: key.sign(d, ec.ECDSA(Prehashed(hashes.SHA256()))))


def _b(x: str | bytes) -> bytes:
    return bytes.fromhex(x[2:]) if isinstance(x, str) else x


def sign_1559(tx: dict, signer: EthSigner) -> tuple[str, str]:
    """Sign an EIP-1559 tx. Returns (raw_hex, tx_hash_hex)."""
    fields = [tx["chainId"], tx["nonce"], tx["maxPriorityFeePerGas"], tx["maxFeePerGas"], tx["gas"],
              _b(tx["to"]), tx.get("value", 0), _b(tx["data"]), []]
    digest = keccak(b"\x02" + rlp.encode(fields))
    v, r, s = signer.vrs(digest)
    raw = b"\x02" + rlp.encode(fields + [v, r, s])
    return "0x" + raw.hex(), "0x" + keccak(raw).hex()


# --- JSON-RPC ------------------------------------------------------------------------------------------------------------
class Rpc:
    def __init__(self, url: str, http: httpx.Client | None = None):
        self.url, self.http = url, http or httpx.Client(timeout=20)

    def call(self, method: str, *params):
        r = self.http.post(self.url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)})
        r.raise_for_status()
        body = r.json()
        if "error" in body:
            raise RuntimeError(f"rpc {method}: {body['error'].get('message')}")
        return body["result"]

    def send(self, signer: EthSigner, chain_id: int, to: str, data: bytes, *, gas_margin: float = 1.25) -> str:
        nonce = int(self.call("eth_getTransactionCount", signer.address, "pending"), 16)
        est = int(self.call("eth_estimateGas", {"from": signer.address, "to": to, "data": "0x" + data.hex()}), 16)
        base = int(self.call("eth_getBlockByNumber", "latest", False)["baseFeePerGas"], 16)
        tip = int(self.call("eth_maxPriorityFeePerGas"), 16)
        tx = {"chainId": chain_id, "nonce": nonce, "maxPriorityFeePerGas": tip, "maxFeePerGas": 2 * base + tip,
              "gas": int(est * gas_margin), "to": to, "value": 0, "data": data}
        raw, h = sign_1559(tx, signer)
        sent = self.call("eth_sendRawTransaction", raw)
        if sent.lower() != h.lower():
            raise RuntimeError("node returned a different tx hash than we computed")
        return h

    def wait(self, tx_hash: str, timeout_s: float = 45) -> dict | None:
        end = time.monotonic() + timeout_s
        while time.monotonic() < end:
            rc = self.call("eth_getTransactionReceipt", tx_hash)
            if rc:
                return rc
            time.sleep(2)
        return None


ATTESTED_TOPIC = "0x" + keccak(b"Attested(address,address,bytes32,bytes32)").hex()


def uid_from_receipt(rc: dict) -> str | None:
    for log in rc.get("logs", []):
        if log["address"].lower() == EAS.lower() and log["topics"][0].lower() == ATTESTED_TOPIC:
            return "0x" + log["data"][2:66]  # data = uid (bytes32). recipient, attester and schema are indexed topics
    return None


def get_attestation(rpc: Rpc, uid: str) -> dict:
    """EAS.getAttestation(uid) → the fields we check (SPEC §8.4)."""
    out = rpc.call("eth_call", {"to": EAS, "data": "0x" + (selector("getAttestation(bytes32)") + _b(uid)).hex()}, "latest")
    (att,) = abi_decode(["(bytes32,bytes32,uint64,uint64,uint64,bytes32,address,address,bool,bytes)"], _b(out))
    uid_, schema, time_, exp, revoked_at, ref, recipient, attester, revocable, data = att
    return {"uid": "0x" + uid_.hex(), "schema": schema, "time": time_, "revocation_time": revoked_at,
            "attester": checksum(attester), "revocable": revocable, "data": data}
