# Verifier profiles

One document per action (SPEC §9.2): the accepted claim shape, the facts recorded, the match rules, the tolerance and
deadline, and the read-only access the verifier needs. A receipt is judged by the profile version recorded in
`observation.verifier`. Any change to the claim shape, facts, match rules or windows is a new version.

| Action | Version | Profile |
|---|---|---|
| `github.commit.push` | 1 | [github.commit.push.md](github.commit.push.md) |
| `github.pr.open` | 1 | [github.pr.open.md](github.pr.open.md) |
| `github.checks.pass` | 1 | [github.checks.pass.md](github.checks.pass.md) |
| `x.post.publish` | 1 | [x.post.publish.md](x.post.publish.md) |
| `slack.message.post` | 1 | [slack.message.post.md](slack.message.post.md) |

Common to every profile:

- A verifier only reads. It never posts, edits or deletes at the destination.
- Anything the verifier can't read (no connection, missing permission, throttling or errors until the deadline) gives
  `unverifiable` with a reason code (SPEC §6.3), never `verified`, `failed` or `mismatch`.
- `failed` with `not_found` is retried until the deadline, since the outcome may not have appeared yet.
- `late` means the outcome matched but appeared after `claimed_at` + tolerance (SPEC §6.1).
- `params` are strict: unknown keys and wrong types are rejected at intake, because params are copied into public
  receipts.
