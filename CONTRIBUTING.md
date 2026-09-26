# Contributing

Thank you for helping. A few things are different from most repositories.

Questions before you start? Ask on [Discord](https://discord.gg/9yhJs3EdCx) (#contributing, or #support for help).

## This repository is published from upstream

Releases here are snapshot commits exported from the maintainers' working repository. Pull requests are welcome;
an accepted change is applied upstream and appears here in the next release, so a merged PR may show up as part of a
release commit rather than as your original commit. Your authorship is kept in the release notes.

## Sign-off (DCO)

Every commit must carry a `Signed-off-by:` line (`git commit -s`), certifying the
[Developer Certificate of Origin](https://developercertificate.org/).

Contributions are also made under the [Contributor License Agreement](CLA.md) with Nuraveda Lab, the copyright holder:
you keep your copyright, and Nuraveda Lab may distribute your contribution under the Project's licences or others.
Tick the box in the pull request template to agree.

## What makes a good change

- Keep the principles in the README intact: destination evidence only; errors are `unverifiable`, never `verified`.
- Spec changes need a conformance vector and, if they break compatibility, a `spec_version` bump with a migration note.
- Run the tests in the package you touched (`uv run --extra test pytest -q`) and, for the spec,
  `uv run tools/generate_vectors.py --check`.
