# Agent guidance

- Preserve this repository's role as a compatible fork of
  `chenxiaolong/my-avbroot-setup`. Do not merge or rebase upstream as part of
  routine feature work.
- Keep PixeneOS-specific catalog contents, ROM/device policy, signer roots,
  artifact locks, and compatibility rules in the fork. Keep generic helper
  behavior small and independently reviewable.
- Before changing fork policy, consult `docs/upstream-maintenance.md` and
  `docs/upstream-disposition.md`. The latter's July 2026 counts describe a
  historical state and are not current comparison figures.
- Generic changes that may be useful upstream should be isolated and reviewed
  against the immutable upstream revision named in the maintenance document.
  Do not push to or open a PR against upstream without authorization.
- For adapter changes, preserve data-only catalog schemas 1 and 2, v1-to-v2
  migration, artifact lock verification, and the exact legacy CLI order.
  Adapter code must be statically trusted or supplied through the explicit,
  digest-checked extension contract in `docs/module-adapter-extensions.md`.
- Do not treat lifecycle metadata as permission to execute installer scripts.
- Use the project formatter and targeted tests. See `pyproject.toml` and the
  relevant `tests/test_*.py` modules.
