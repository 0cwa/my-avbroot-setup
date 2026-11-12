# Explicit adapter extensions

Local consumers can pass a digest-pinned adapter extension to both
`module-tool resolve` and `patch.py`. This keeps the helper's checked-in
`lib/modules/registry.py` unchanged. Without `--adapter-extension`, the helper
uses the same built-in catalog, locked adapters, and legacy CLI registry as
before.

The extension is a small TOML trust declaration, not a plugin search path:

```toml
schema_version = 1
catalog_directories = ['modules/manifests']

[[adapters]]
id = 'example-module'
kind = 'locked'
source = 'modules/example_adapter.py'
sha256 = '<lowercase SHA-256 of the exact source file>'
target = 'ExampleModule'
verification_schemes = ['sha256']
trusted_signers = []
digest_required = true
```

Every adapter entry has exactly the fields shown. `source` and each catalog
directory are relative to the extension file, must stay beneath its directory,
and may not traverse symlinks. The helper validates the complete extension and
checks every source digest before importing any extension code. IDs must be
unique and cannot replace built-in registrations. The `target` is an explicit
class or factory name in the hash-checked file; a factory must return the
required class type.

`catalog_directories` adds TOML manifests to the built-in catalog. Those
manifests still use catalog schema 1 or 2 and the normal migration, resolver,
lock, compatibility, and verification checks. Catalog data never supplies an
import path. The extension's verification schemes, trusted signers, and digest
requirement must exactly match the corresponding manifest.

There are three adapter kinds:

- `legacy-cli` loads a `LegacyCliModule` class or factory and adds its
  explicitly registered arguments to `patch.py`. It does not add a catalog
  registration.
- `locked` loads a `Module` class or factory for selected catalog entries. The
  constructor receives the normal `LockedAdapterContext`.
- `catalog-legacy` is for an existing, reviewed `LegacyCliModule` class or
  factory that is also selected through the catalog. The helper keeps its
  legacy arguments and wraps it for locked construction. The factory's
  `from_args` method is called only after the context module ID matches, with a
  nonempty selection marker for the class's module argument; the wrapper also
  retains the verified context. This bridge is for classes whose `from_args`
  method uses that argument only as a presence check.

The catalog-legacy wrapper does not infer that environment-variable paths are
the artifacts represented by the lock. An adapter can instead read its
payloads through the verified context's artifact handles; ModOS's current
Shizuku and exFAT catalog adapters use that path and validate their artifact
IDs, roles, digests, and sizes. A consumer that retains environment-backed
payload paths must keep those paths bound to verified artifact bytes or retain
its independent verification before injection. A locked selection provides
module identity/version, profile and ROM scope, lock digest, selection
fingerprint, compatibility decision, trusted signers, and verified artifact
handles. A class still needs to enforce any runtime preconditions in its
`requirements()` and `inject()` methods.

The helper does not execute installer scripts or infer installer support from
catalog lifecycle metadata.

## Locked injection reports

A `catalog-legacy` adapter must support the locked injection result contract as
well as context-aware payload reads. When selected through the catalog, its
`inject()` must return `lib.modules.report.AdapterPatchResult` containing the
actual changed or verified-installed Android paths in sorted, unique order.
The wrapper passes that result through; it does not infer writes or invent an
empty success result for an older adapter that returns `None`. The patch runner
rejects a missing result before repacking or generating output.

Filesystem paths in a product image are image-relative. Report them in their
mounted Android namespace (for example `/product/app/...`). Optional per-path
statuses must come from actual install results; a file replacement is not a
newly created file. Legacy CLI selection may retain its prior return behavior.
