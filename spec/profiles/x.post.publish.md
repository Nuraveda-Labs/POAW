# `x.post.publish` v1

The claimed post exists on X, was written by the account the target handle is connected as, and (optionally) its text
matches a fingerprint the agent supplies.

## Claim shape

- **target:** `@handle` (1–15 of `A–Z a–z 0–9 _`, with the `@`)
- **params:**

| Field | Type | Required | Meaning |
|---|---|---|---|
| `post_id` | string of 1–20 digits | yes | The post's ID |
| `text_sha256` | string, 64 lowercase hex | no | The text fingerprint (below) |

**Text fingerprint:** lowercase hex SHA-256 of the UTF-8 bytes of `NFC(text).strip()`, where `strip()` removes
leading and trailing whitespace. The agent hashes the text it posted, the verifier hashes the text X returns, and
only the result of the comparison is recorded.

## Reads

`GET https://api.x.com/2/tweets/{post_id}?tweet.fields=author_id,created_at,text,entities,note_tweet`, with the
issuer's own read credential.

The text compared is rebuilt from the response as the author wrote it: the full text of a long post (`note_tweet`)
when present, shortened links replaced by their `expanded_url`, links X appends for attached media removed, and HTML
entities (`&amp;`, `&lt;`, `&gt;`) decoded.

## Binding the handle to an account

The issuer resolves `target` to the X user ID of an account connected to the claim's workspace (compared
case-insensitively). A handle that isn't connected gives `unverifiable` / `no_connection`. The post's `author_id`
must equal that user ID, so a post by anyone else can't be claimed.

## Facts

`{post_id, found, author_id?, created_at?, text_sha256_matched?}`. Never the text.

## Match rules

| Destination shows | Verdict |
|---|---|
| The post, by the bound account, and the text fingerprint matches when given | `verified`, `appeared_at` = `created_at` |
| The post, by a different account | `mismatch` / `target_mismatch` |
| The post, by the bound account, with a different text fingerprint | `mismatch` / `content_mismatch` |
| HTTP 404, or a `resource-not-found` error | `failed` / `not_found`, retried until the deadline |
| HTTP 401/403, or another error in place of the post (e.g. a protected account) | `unverifiable` / `permission_denied` |
| HTTP 402 (the reading app's API credits are exhausted) | `unverifiable` / `destination_unavailable` |
| HTTP 429 | retried, then `unverifiable` / `rate_limited` |
| HTTP 5xx, other statuses, timeouts | retried, then `unverifiable` / `destination_unavailable` |
| A malformed target or params | `unverifiable` / `claim_ambiguous` |

## Windows

**Tolerance:** 10 minutes. **Deadline:** 30 minutes after `claimed_at`.

## Required access

An app credential that can read public posts (X API v2 post lookup), and the target handle connected to the
workspace (read scopes `tweet.read` and `users.read`), which is what binds the handle to a user ID. Nothing is posted.
