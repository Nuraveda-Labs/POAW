# `github.checks.pass` v1

Every check run on the claimed commit completed without failing.

## Claim shape

- **target:** `owner/repo`
- **params:**

| Field | Type | Required | Meaning |
|---|---|---|---|
| `sha` | string, 40 lowercase hex | yes | The commit whose checks passed |

## Reads

`GET https://api.github.com/repos/{owner}/{repo}/commits/{sha}/check-runs?per_page=100`

## Facts

`{sha, check_runs, failing?}`: the number of check runs and the sorted names of the failing ones. No logs or output.

## Match rules

| Destination shows | Verdict |
|---|---|
| At least one check run, all `completed`, every conclusion `success`, `neutral` or `skipped` | `verified` |
| All completed, and any other conclusion (e.g. `failure`, `cancelled`, `timed_out`) | `mismatch` / `content_mismatch` |
| No check runs | `failed` / `not_found`, retried until the deadline |
| Any run not yet completed | retried; still running at the deadline gives `unverifiable` / `destination_unavailable` |
| 401/403, 429 or other errors | retried, then `unverifiable` with `permission_denied`, `rate_limited` or `destination_unavailable` |
| Target not `owner/repo` or bad `sha` | `unverifiable` / `claim_ambiguous` |

## Windows

**Tolerance:** 1 hour. **Deadline:** 2 hours after `claimed_at`.

## Required access

Read-only `checks:read` and `metadata:read`.
