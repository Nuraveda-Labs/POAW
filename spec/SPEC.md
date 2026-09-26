# Proof of Agent Work (PoAW) — Receipt Specification

**Version:** `poaw/0.1` (draft) · **Status:** Draft. Breaking changes are expected before 1.0. · **License:** Apache-2.0

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119.

## 1. Purpose

An AI agent **claims** it did something ("published a post", "pushed a commit", "sent an email").
A **verifier** independently checks the **destination** where that work was supposed to land and
records what it **observed**. A **receipt** is the signed, tamper-evident record of the claim, the
observation and the resulting **verdict**.

A receipt is meant to be checked **by anyone, without trusting the issuer's servers**. It needs
the issuer's public key, the log's inclusion proof and a public blockchain RPC.

This document defines the receipt format, how it is signed, how receipts are logged and anchored,
and what each verdict means. It does not define how any particular verifier talks to any
particular destination. Each verifier publishes its own profile (§9).

## 2. Terminology

| Term | Definition |
|---|---|
| **Agent** | The software that performed (or claims to have performed) the work. |
| **Claim** | The agent's statement of what it did. **Always untrusted input.** |
| **Destination** | The external system where the work should be observable (a repository, a social timeline, a mailbox, an HTTP endpoint). |
| **Verifier** | A versioned procedure that reads the destination and produces an observation. It is deterministic given the same destination state. |
| **Observation** | What the verifier saw, recorded as **facts**: identifiers, timestamps and fingerprints. Never content. |
| **Verdict** | The outcome of comparing the claim with the observation (§6). |
| **Issuer** | The party that ran the verifier and signed the receipt. It is identified by a public key. |
| **Log** | An append-only Merkle tree of receipts, operated by the issuer (§8). |
| **Anchor** | A public, timestamped commitment to a log root, e.g. an attestation on a blockchain (§8.4). |

## 3. Encoding

- Receipts are JSON (RFC 8259), encoded as UTF-8.
- **Canonicalisation:** every signature and hash in this spec is computed over the
  **JSON Canonicalization Scheme (JCS, RFC 8785)** serialisation of the object named. Implementations
  MUST canonicalise with an RFC 8785-conformant library, not by re-serialising with sorted keys.
- Timestamps are RFC 3339 strings in UTC with a `Z` suffix and at most millisecond precision, e.g. `2026-09-25T14:02:11.000Z`.
- Binary values (hashes, signatures, keys) are **base64url without padding** (RFC 4648 §5), unless noted otherwise.
- Hashes are SHA-256.
- Numbers MUST be integers within ±2^53. Floating-point values MUST NOT appear in a receipt (JCS number
  formatting of non-integers is a common source of cross-language disagreement).

## 4. The receipt object

A receipt has three top-level members:

```json
{
  "body":      { … },   // the signed statement (§4.1)
  "signature": { … },   // over the body (§5)
  "proof":     { … }    // log inclusion and anchor (§8). NOT signed, and may be added later
}
```

`body` and `signature` are immutable once issued. `proof` is attached by the log and may be
extended over time (for example, when an anchor lands). It is verified on its own terms (§8), so it
doesn't need to be signed.

### 4.1 `body`

| Field | Type | Req. | Meaning |
|---|---|---|---|
| `spec_version` | string | MUST | `"poaw/0.1"` |
| `receipt_id` | string | MUST | Issuer-unique ID. RECOMMENDED form: `rcpt_` followed by a ULID. |
| `issued_at` | timestamp | MUST | When the issuer signed. |
| `issuer` | object | MUST | `{ "key_id": string, "name"?: string }`. `key_id` per §5.2. |
| `agent` | object | MUST | `{ "id": string, "erc8004"?: { "chain": string, "registry": string, "agent_id": string } }`. `id` is opaque to this spec. `chain` is a CAIP-2 ID (e.g. `eip155:8453`). |
| `operator` | string | MAY | Opaque ID of the party that runs the agent. |
| `claim` | object | MUST | §4.2 |
| `observation` | object | MUST | §4.3 |
| `verdict` | object | MUST | `{ "value": Verdict, "reason_code"?: ReasonCode }` (§6) |
| `trust_level` | integer | MUST | 1–4 (§7) |
| `attestation` | object | MAY | Required when `trust_level` ≥ 3. `{ "type": string, "document": string }`, e.g. `type: "aws-nitro-enclave"`. |
| `supersedes` | string | MAY | The `receipt_id` this receipt corrects. The old receipt remains valid as a record. Consumers SHOULD prefer the newest in a chain. |

Unknown members in `body` MUST be preserved (they are covered by the signature). Consumers
MUST reject a body whose `spec_version` major version they don't support.

### 4.2 `claim`

| Field | Type | Req. | Meaning |
|---|---|---|---|
| `action` | string | MUST | Action name (§9.1), e.g. `"x.post.publish"`. |
| `target` | string | MUST | Where the work should land, in the form the action's profile defines (a repo slug, an account handle, a URL). |
| `params` | object | MUST | Action-specific parameters, per the profile. It MUST NOT contain content bodies. Use fingerprints (§4.4). May be `{}`. |
| `claimed_at` | timestamp | MUST | When the agent says the work happened. |
| `client_claim_id` | string | SHOULD | The submitter's idempotency key. |
| `claim_digest` | string | MUST | base64url(SHA-256(JCS(claim without `claim_digest`))). It binds the claim as submitted. |

### 4.3 `observation`

| Field | Type | Req. | Meaning |
|---|---|---|---|
| `verifier` | object | MUST | `{ "id": string, "version": string, "code_hash"?: string }`. `id` + `version` name the profile (§9). `code_hash` is REQUIRED at trust level ≥ 3 and identifies the exact build that ran. |
| `observed_at` | timestamp | MUST | When the decisive read of the destination happened. |
| `deadline_at` | timestamp | MUST | The latest time the verifier would wait for the outcome (§6.2). |
| `attempts` | integer | MUST | Number of reads of the destination. |
| `facts` | object | MUST | Verifier-defined, schema-constrained (§9.2). It MUST follow §4.4. |

### 4.4 Facts, fingerprints and privacy

`facts` records **what is needed to re-check the outcome and nothing more**:

- Allowed: destination identifiers (post ID, commit SHA, message ID), timestamps, status codes,
  counts, booleans, and **fingerprints**.
- **Not allowed:** content bodies (email text, post text, file contents), personal data beyond what
  the claim's `target` already names, and credentials of any kind.
- **Fingerprint:** `sha256:` + base64url(SHA-256(normalised content)), where *normalised* means: Unicode NFC,
  line endings converted to LF, trailing whitespace on each line removed, and leading or trailing blank lines
  removed. A profile MAY define a stricter normalisation, and if it does it MUST say so.

## 5. Signature

### 5.1 Algorithm

```
message   = "POAW-RECEIPT-V0" || 0x0A || JCS(body)      // domain-separated
signature = Ed25519-Sign(issuer_private_key, message)    // RFC 8032, pure Ed25519
```

```json
"signature": { "alg": "Ed25519", "key_id": "<§5.2>", "value": "<base64url 64-byte signature>" }
```

`signature.key_id` MUST equal `body.issuer.key_id`. The domain prefix stops a receipt signature
from being valid as a signature over any other protocol's message.

### 5.2 Key IDs and key discovery

- `key_id = "ed25519:" + base64url(SHA-256(raw 32-byte public key))`
- An issuer publishes its keys at `https://<issuer-domain>/.well-known/poaw-keys.json`:
  ```json
  { "keys": [ { "key_id": "ed25519:…", "public_key": "<base64url 32 bytes>",
                "valid_from": "…Z", "revoked_at": null } ],
    "anchor_addresses": ["0x…"], "anchor_schemas": ["0x<EAS schema UID>"] }
  ```
  `anchor_addresses` and `anchor_schemas` are what an anchor check (§8.4) accepts. An attestation from any other
  address, or under any other schema, does not anchor this issuer's log.
- A receipt is **signature-valid** if the key exists, the signature checks out, and
  `valid_from ≤ issued_at < revoked_at` (or `revoked_at` is null). A receipt issued after the key's
  `revoked_at` MUST be treated as invalid. Receipts issued earlier stay valid, and the log anchor (§8)
  proves they existed before the revocation.

## 6. Verdicts

### 6.1 Values

| `verdict.value` | Meaning | Counts toward reputation? |
|---|---|---|
| `verified` | The destination shows the claimed outcome, matching every field the profile requires, observed no later than `claimed_at` + the profile's tolerance. | Yes, positively |
| `late` | The outcome is present and matches, but it appeared after `claimed_at` + tolerance (and before `deadline_at`). | Yes, mildly negatively |
| `mismatch` | The destination shows an outcome for the target, but a required field differs (e.g. a different content fingerprint, the wrong branch). | Yes, negatively |
| `failed` | The verifier could read the destination, and the outcome was not present by `deadline_at`. | Yes, negatively |
| `unverifiable` | The verifier could not determine the outcome (§6.3). | **No.** It is never evidence for or against the agent |

### 6.2 Rules

1. **Fail toward `unverifiable`, never toward `verified`.** Any error, timeout, missing permission,
   rate limit or ambiguity MUST yield `unverifiable`, never `verified`.
2. **Blame only on evidence.** `failed` and `mismatch` REQUIRE a successful read of the destination.
   A destination that couldn't be read yields `unverifiable`, not `failed`. The agent is never penalised for the verifier's blind spot.
3. `verified`, `late`, `mismatch` and `failed` MUST carry facts sufficient to re-check them (§4.4).
4. Verdicts are **decided deterministically** from the claim, the facts and the profile's match rules.
   A language model MAY help turn free text into a structured claim, but MUST NOT decide a verdict.

### 6.3 Reason codes

`verdict.reason_code` SHOULD be present for everything except `verified`, and MUST be present for `unverifiable`:

| Code | Used with | Meaning |
|---|---|---|
| `not_found` | failed | The destination was read, and no matching outcome existed by the deadline |
| `content_mismatch` | mismatch | The fingerprint differs from the claim |
| `target_mismatch` | mismatch | The outcome exists, but under a different target (account, branch, recipient) |
| `observed_after_tolerance` | late | Present, but after the tolerance window |
| `no_connection` | unverifiable | The issuer holds no access to the destination for this target |
| `permission_denied` | unverifiable | Access exists but doesn't cover this read |
| `rate_limited` | unverifiable | The destination throttled every read until the deadline |
| `destination_unavailable` | unverifiable | The destination errored or timed out until the deadline |
| `unsupported_action` | unverifiable | No verifier profile exists for `claim.action` |
| `claim_ambiguous` | unverifiable | The claim lacks the fields the profile needs |
| `verifier_error` | unverifiable | An internal failure in the verifier |

## 7. Trust levels

| Level | Name | The issuer additionally provides | A checker can confirm |
|---|---|---|---|
| 1 | Signed | §5 signature | The issuer stated this, and it hasn't been altered |
| 2 | Anchored | §8 inclusion proof + anchor | …and it existed no later than the anchor time. It can't be backdated or silently deleted |
| 3 | Attested | `attestation` + `observation.verifier.code_hash` | …and a specific, published verifier build produced the observation inside a hardware enclave |
| 4 | Web-proven | a zero-knowledge TLS proof inside `attestation` | …and the facts came from the destination's TLS session, without trusting hardware |

`trust_level` is the issuer's claim about which of these it provides. Checkers MUST compute the
**achieved** level from what actually verifies, and MUST report the lower of the two.

## 8. Log and anchoring

### 8.1 Leaves

`leaf_hash = SHA-256( 0x00 || JCS({ "body": body, "signature": signature }) )`

The log is an RFC 6962-style Merkle tree. Interior nodes are `SHA-256( 0x01 || left || right )`.

### 8.2 `proof`

```json
"proof": {
  "log_id": "<base64url SHA-256 of the log's public identifier>",
  "leaf_index": 88213,
  "tree_size": 88240,
  "root_hash": "<base64url>",
  "inclusion": ["<base64url>", "…"],
  "anchor": { "chain": "eip155:8453", "scheme": "eas", "uid": "0x…", "tx_hash": "0x…", "tree_size": 88240 }
}
```

`anchor` MAY be absent (trust level 1, or level 2 before the anchor lands). Absence is a limitation of the
proof. It does not make the receipt invalid.

### 8.3 Checking inclusion

The checker recomputes `leaf_hash`, then runs the RFC 6962 audit-path verification with
`leaf_index`, `tree_size` and `inclusion`, and MUST obtain exactly `root_hash`.

### 8.4 Checking the anchor (scheme `eas`)

The anchor is an Ethereum Attestation Service attestation on `anchor.chain`, from an attester address
the issuer publishes in `poaw-keys.json` (`"anchor_addresses": [...]`). Its data MUST decode (per the
issuer's published schema) to a `(log_id, tree_size, root_hash, …)` that equals `proof.log_id`,
`anchor.tree_size` and a root the checker can connect to `proof.root_hash`:

- If `anchor.tree_size == proof.tree_size`, the roots MUST be equal.
- Otherwise the issuer MUST supply an RFC 6962 **consistency proof** between the two sizes, and the checker MUST verify it.

The attestation's block timestamp is the receipt's **proven-by time**.

## 9. Actions and verifier profiles

### 9.1 Action names

`<domain>.<object>.<event>`, lowercase ASCII, e.g. `github.commit.push`, `github.pr.open`,
`github.checks.pass`, `http.url.status`, `x.post.publish`, `gmail.message.send`. New actions are added by
publishing a profile. An action name is never reused with a different meaning.

### 9.2 Profiles

Each verifier publishes a profile (a document plus a JSON Schema) defining:

1. **Accepted claim shape:** the `target` format and the `params` schema.
2. **Facts schema:** exactly which `facts` fields it records (under §4.4).
3. **Match rules:** the precise comparison that yields `verified`, `mismatch` and `failed`.
4. **Tolerance and deadline:** the default windows for `late` and for giving up.
5. **Required access:** the minimum read-only permission at the destination.

A profile is identified by `id` + `version`. Any change to (1)–(4) is a new version. A receipt is always
judged by the version recorded in it.

## 10. Checking a receipt (summary for implementers)

1. Parse. Reject an unknown major `spec_version`.
2. Resolve `issuer.key_id` from the issuer's key set, check the validity window, and verify the §5 signature.
3. Recompute `claim.claim_digest`.
4. If `proof` is present, verify inclusion (§8.3), and the anchor if present (§8.4).
5. If `trust_level ≥ 3`, verify `attestation` against the platform's root of trust, and check that `code_hash`
   matches a published verifier build.
6. Report: signature ✓/✗, inclusion ✓/✗/absent, anchor ✓/✗/absent (with proven-by time), **achieved** trust
   level, and the verdict. A checker MUST NOT present a receipt as valid if step 2 fails.

## 11. ERC-8004 mapping (informative)

When published to an ERC-8004 Validation Registry, `validationResponse` SHOULD use:
`verified` → 100, `late` → 50, `mismatch` → 0, `failed` → 0, and `unverifiable` → **no response is posted**.
The evidence URI SHOULD resolve to the full receipt including `proof`. This mapping is provisional until
the ERC-8004 draft stabilises.

## 12. Security considerations

- **A receipt proves what the issuer observed, not absolute truth.** Trust levels 3 and 4 narrow what the issuer could fake.
- **Key compromise:** revoke the key in `poaw-keys.json`. Receipts anchored before the revocation remain provable (§5.2).
- **Log forks:** an issuer showing different roots to different parties is detected by consistency proofs
  against the public anchor. Checkers SHOULD verify against the anchor, not only the issuer's API.
- **Replay:** `receipt_id` is unique per issuer, and `claim_digest` binds the exact claim.
- **Privacy:** §4.4 is normative. A receipt carrying content bodies does not conform.

## 13. Test vectors

`vectors/` holds receipts with expected checker outcomes: valid at each trust level, tampered body,
wrong key, revoked key, bad inclusion path, anchor/root mismatch, every verdict value and every reason code.
Every conforming implementation MUST produce the expected outcome for every vector.
