# `slack.message.post` v1

A message with exactly the claimed timestamp exists in the claimed channel, and (optionally) its text matches a
fingerprint the agent supplies.

## Claim shape

- **target:** `slack://<team_id>/<channel_id>`, with a team ID `T…` and a public (`C…`) or private (`G…`) channel ID,
  uppercase. Direct messages are out of scope.
- **params:**

| Field | Type | Required | Meaning |
|---|---|---|---|
| `ts` | string, `^[0-9]{10}\.[0-9]{6}$` | yes | The message timestamp Slack returned when it was posted |
| `text_sha256` | string, 64 lowercase hex | no | The text fingerprint, defined as for [`x.post.publish`](x.post.publish.md) |

## Reads

1. `GET https://slack.com/api/conversations.history?channel=<channel_id>&latest=<ts>&oldest=<ts>&inclusive=true&limit=1`
2. Only if (1) holds no message with that `ts` (a threaded reply isn't in the channel history):
   `GET https://slack.com/api/conversations.replies?channel=<channel_id>&ts=<ts>&limit=1`

Both use the connected workspace's user token. A message matches only when its `ts` equals the claimed `ts` exactly.

## Binding the target to a connection

The issuer uses the connection for `team_id` in the claim's workspace. With none, the claim is
`unverifiable` / `no_connection`. A credential bound to a different team is never used.

## Facts

`{team_id, channel_id, ts, found, text_sha256_matched?}`. Never the text.

## Match rules

| Destination shows | Verdict |
|---|---|
| The message, and the text fingerprint matches when given | `verified`, `appeared_at` = the time encoded in `ts` |
| The message, with a different text fingerprint | `mismatch` / `content_mismatch` |
| `ok: true` and no message with that `ts` in either read (or `thread_not_found`) | `failed` / `not_found`, retried until the deadline |
| `channel_not_found`, `not_in_channel`, `missing_scope` | `unverifiable` / `permission_denied` |
| `invalid_auth`, `token_revoked`, `token_expired`, `not_authed`, `account_inactive` | `unverifiable` / `no_connection` |
| `ratelimited`, or HTTP 429 | retried, then `unverifiable` / `rate_limited` |
| HTTP 5xx, other errors, timeouts | retried, then `unverifiable` / `destination_unavailable` |
| A malformed target or params | `unverifiable` / `claim_ambiguous` |

The text fingerprint matches if it equals the hash of the message `text` as Slack returns it, or of that text with
Slack's three escapes (`&amp;`, `&lt;`, `&gt;`) decoded. Other Slack markup (links, mentions) is compared as returned.

## Windows

**Tolerance:** 10 minutes. **Deadline:** 30 minutes after `claimed_at`.

## Required access

A Slack user token with `channels:history` (public channels) and `groups:history` (private channels) for a user
who can see the channel. Nothing is posted.
