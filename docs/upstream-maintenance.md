# Upstream maintenance

This repository remains a compatible fork of
[`chenxiaolong/my-avbroot-setup`](https://github.com/chenxiaolong/my-avbroot-setup).
The fork carries PixeneOS ROM compatibility and a reviewed module catalog;
reusable helper behavior can be considered for upstream as a small, separate
change. This document records the comparison basis and the current known
dispositions. It does not authorize an upstream push or PR.

## Current comparison

As of 2026-11-12, compare this branch with immutable upstream commit
`394725b276a585bc93443dd49438b5ad3ae93588` (`Update Python dependencies`,
2026-11-04). That commit is the upstream master used by the current helper pin
and by this cleanup. No upstream merge or rebase was performed.

At cleanup snapshot `b7869172a29a20ba96ee9995b96bb117c2cfc5f9`, the fork had
161 commits after this upstream base and no upstream-only commits; the tree
comparison was 103 files changed, 21,705 insertions, and 221 deletions. This
is the dated comparison for the cleanup snapshot, not a promise that later
consumer or fork work leaves those figures unchanged.

Reproduce the commit and tree comparison with:

```sh
git rev-list --count 394725b276a585bc93443dd49438b5ad3ae93588..b7869172a29a20ba96ee9995b96bb117c2cfc5f9
git diff --shortstat 394725b276a585bc93443dd49438b5ad3ae93588 b7869172a29a20ba96ee9995b96bb117c2cfc5f9
```

The compatible-fork strategy's older "about 21 commits" and `+594 / -175`
figures described a 2026-07-18 historical snapshot. They are not current
figures. The detailed per-hunk disposition remains useful as history, but its
opening baseline must not be read as a present-day delta.

## Disposition for the cleanup work

| Change | Disposition | Reason |
|---|---|---|
| Explicit adapter extension manifest, digest-before-import checks, catalog overlay, and locked construction | Candidate generic helper behavior | The extension contract is explicit and reuses the existing data-only catalog, resolver, and lock checks. It may be proposed upstream after independent review; no upstream contribution is prepared here. |
| Native `patch.py --release-url` option | Candidate generic helper behavior | It removes a consumer source rewrite while preserving the old output-name default. It is separable from PixeneOS release identity policy. |
| PixeneOS catalog manifests, signer roots, artifact locks, ROM/device rules, and local adapter policy | Fork-specific | These encode PixeneOS trust and product policy and remain owned by this fork/consumer. |
| Existing compatible-sepolicy, ODM, and CIL fallback behavior | Fork-specific unless upstream maintainers agree to a narrower design | These remain coupled to non-Pixel ROM support and explicit compatibility policy. |
| Formatter-only churn, weaker license wording, raw-argument logging | Drop | These are unrelated or regressions and should not be carried forward. |

The candidate labels are a maintenance assessment, not a statement that
upstream has accepted or reviewed these changes. Generic changes should stay
small, isolated, and compatible with upstream's existing module CLI. The
catalog remains data-only; manifests, profiles, and locks never choose Python
imports. See `docs/module-adapter-extensions.md` for the exact extension
boundary.

## Maintenance steps

1. Fetch upstream and compare changes against its exact commit, not a moving
   branch name.
2. Keep the fork's catalog, trust roots, and ROM/device policy while adapting
   any upstream changes.
3. Re-run catalog, resolver, lock, patch-boundary, and legacy CLI checks after
   helper changes.
4. Update this comparison and the dated disposition when the upstream base or
   fork delta changes.
5. Promote a generic candidate only on a dedicated upstream topic branch and
   only after the repository owner authorizes that target.
