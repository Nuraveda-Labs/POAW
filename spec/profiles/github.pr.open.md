# `github.pr.open` v1

The claimed pull request exists, optionally against the claimed base branch and at the claimed head commit.

## Claim shape

- **target:** `owner/repo`
- **params:**

| Field | Type | Required | Meaning |
|---|---|---|---|
| `number` | integer ≥ 1 | yes | The pull request number |
| `base` | string | no | The base branch it must target |
| `head_sha` | string | no | The head commit it must be at |

## Reads

`GET https://api.github.com/repos/{owner}/{repo}/pulls/{number}`

## Facts

`{number, pr_found, state?, base?, head_sha?}`. No titles, descriptions or diffs.

## Match rules

| Destination shows | Verdict |
|---|---|
| The pull request, with `base` and `head_sha` matching when given | `verified`, `appeared_at` = its `created_at` |
| A different base branch | `mismatch` / `target_mismatch` |
| A different head commit | `mismatch` / `content_mismatch` |
| 404 | `failed` / `not_found`, retried until the deadline |
| 401/403, 429 or other errors | retried, then `unverifiable` with `permission_denied`, `rate_limited` or `destination_unavailable` |
| Target not `owner/repo` or `number` not a positive integer | `unverifiable` / `claim_ambiguous` |

`state` is recorded but not matched: a pull request that was opened and has since closed or merged still verifies.

## Windows

**Tolerance:** 10 minutes. **Deadline:** 15 minutes after `claimed_at`.

## Required access

Read-only `pull_requests:read` and `metadata:read`.
