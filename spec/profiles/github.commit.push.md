# `github.commit.push` v1

The claimed commit exists on the remote and the claimed branch contains it.

## Claim shape

- **target:** `owner/repo`
- **params:**

| Field | Type | Required | Meaning |
|---|---|---|---|
| `sha` | string, 40 lowercase hex | yes | The full commit SHA |
| `branch` | string | yes | The branch that must contain it |

## Reads

1. `GET https://api.github.com/repos/{owner}/{repo}/commits/{sha}`
2. `GET https://api.github.com/repos/{owner}/{repo}/compare/{sha}...{branch}`

If (1) is 404, `GET https://api.github.com/repos/{owner}/{repo}` decides whether the repository is readable at all.

## Facts

`{sha, branch, commit_found, branch_found?, branch_contains_sha?}`. No file contents.

## Match rules

| Destination shows | Verdict |
|---|---|
| Compare status `identical` or `ahead` (the branch contains `sha`) | `verified` |
| Commit found, branch doesn't contain it (`behind`, `diverged`) or the branch is missing | `mismatch` / `target_mismatch` |
| Commit 404 (or 422) in a readable repository | `failed` / `not_found`, retried until the deadline |
| Commit 404 and the repository isn't readable | `unverifiable` / `no_connection` without a token, else `permission_denied` |
| 401/403 | `permission_denied` (retried, then `unverifiable`) |
| 429, or 403 with `x-ratelimit-remaining: 0` | `rate_limited` (retried, then `unverifiable`) |
| Other errors or timeouts | `destination_unavailable` (retried, then `unverifiable`) |
| Target not `owner/repo`, bad `sha` or empty `branch` | `unverifiable` / `claim_ambiguous` |

A mismatch is decided on the first read that shows it.

## Windows

- **Tolerance:** 10 minutes. **Deadline:** 15 minutes after `claimed_at`.
- `appeared_at` isn't derived (commit dates are set by the author), so this action gives `verified`, not `late`.

## Required access

Read-only repository access: `contents:read` and `metadata:read`.
