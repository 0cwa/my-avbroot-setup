# Maintainers — `0cwa/my-avbroot-setup`

This repository is a **compatible fork** of [`chenxiaolong/my-avbroot-setup`](https://github.com/chenxiaolong/my-avbroot-setup). Its purpose is to host LineageOS / non-Pixel ROM compatibility work for the [`PixeneOS`](https://github.com/0cwa/PixeneOS) build pipeline while staying close enough to upstream that hunks can be promoted to upstream PRs as they mature.

The fork strategy, the per-hunk disposition for the current delta against upstream, and the draft upstream-PR descriptions all live under [`docs/`](./docs/):

- **[`docs/upstream-strategy.md`](./docs/upstream-strategy.md)** — relationship to upstream; rebase / branching policy; what stays here vs goes upstream.
- **[`docs/upstream-disposition.md`](./docs/upstream-disposition.md)** — per-hunk decomposition of the historical `+594 / -175` delta vs upstream, with U (upstream) / F (fork-only) / D (drop) dispositions.
- **[`docs/upstream-maintenance.md`](./docs/upstream-maintenance.md)** — dated comparison against immutable upstream `394725b`; the current maintenance assessment and named generic/fork-specific dispositions.
- **[`docs/upstream-prs/`](./docs/upstream-prs/)** — one file per planned upstream PR with the draft description and the cherry-pick recipe.

The `+594 / -175` figures in the older disposition are a historical 2026-07-18
snapshot, not the present branch delta. Use `docs/upstream-maintenance.md` for
current comparison commands and the current scope split. The cleanup adds a
narrow explicit extension contract and native release URL option; neither has
been sent upstream.

## Pointers back to PixeneOS

PixeneOS is the consumer of this fork. The execution queue (tickets `ROMCOMPAT-1..4`, `META-3`) lives in PixeneOS, not here:

- PixeneOS ADR for this fork strategy: [`docs/planning/decisions/ADR-0002-compatible-fork-of-my-avbroot-setup.md`](https://github.com/0cwa/PixeneOS/blob/main/docs/planning/decisions/ADR-0002-compatible-fork-of-my-avbroot-setup.md).
- PixeneOS ticket index: [`docs/tickets/INDEX.md`](https://github.com/0cwa/PixeneOS/blob/main/docs/tickets/INDEX.md).

If you are reviewing an upstream PR sourced from this fork, the disposition doc is the explanation for why each hunk was scoped the way it was.
