# Module preparation CLI

`module-tool.py` exposes the deterministic preparation stages used before OTA
mutation. It does not inject files into an OTA and does not execute archive
members or installer hooks.

Run it through the repository's Python environment:

```bash
python3 module-tool.py --help
```

## Network boundary

The checked-in artifact lock is the only input to normal artifact acquisition.
`artifacts fetch` contacts only the immutable HTTPS URLs and redirect origins
recorded in that lock. Catalog listing, lock verification, artifact
verification, archive inspection, and profile resolution are local-only.

Floating release metadata is reserved for:

```bash
python3 module-tool.py lock update <module>
```

Lock-update providers form a reviewed static registry; a module ID can never be
used as a Python import path. This Phase 1 foundation has no provider and fails
that command clearly. A later provider must emit a canonical, reviewable lock
diff. Normal build and verification commands never fall back to a floating
endpoint when a lock or cache object is missing or invalid.

## Catalog

```bash
python3 module-tool.py catalog list
python3 module-tool.py catalog list --format json
```

This reads only `lib/modules/manifests/`, validates the complete catalog, and
prints modules in canonical ID order. JSON is canonical schema v2 even when a
checked-in manifest was deterministically migrated from schema v1. Listing
does not load an executable adapter or select a module.

## Artifact locks

Validate both the strict lock schema and its canonical JSON serialization:

```bash
python3 module-tool.py lock verify --lock locks/artifacts.lock.json
```

On success, the command prints the canonical lock JSON. It does not contact the
network or verify cache objects; those are separate stages. A lock pins each
artifact's immutable URL, permitted redirect origins, version, exact byte size,
SHA-256, and any APK or archive identity policy.

`lock update` accepts `--output` and repeatable `--version-code` options for
future reviewed providers. Their meaning is provider-specific, and no provider
is available in this phase.

## Fetch and verify

Populate a content-addressed cache from locked immutable URLs:

```bash
python3 module-tool.py artifacts fetch \
    --lock locks/artifacts.lock.json \
    --cache .artifact-cache
```

Limit either operation to one or more lock modules with repeated `--module`:

```bash
python3 module-tool.py artifacts verify \
    --lock locks/artifacts.lock.json \
    --cache .artifact-cache \
    --module example-module
```

Fetches use bounded temporary files, enforce the locked size while streaming,
verify SHA-256 before placement, fsync, atomically rename, and then reverify the
cache object. An existing cache object is always reverified and is never
silently replaced after a mismatch.

Verification is local-only. It rechecks size and SHA-256, applies the locked
hostile-archive policy, and verifies locked APK package name, versionCode, and
single signer with `apksigner` and `apkanalyzer`. Missing verification tools are
a hard failure. Both commands print a JSON array of content-addressed paths in
canonical lock order.

## Safe archive inspection

Inspect a ZIP-compatible container without extracting or executing it:

```bash
python3 module-tool.py artifacts inspect artifact.zip \
    --allow path/to/required-member \
    --allow another/required-member
```

Every `--allow` name must exist exactly once. Inspection validates every member,
streams file contents to force CRC and truncation checks, and prints sizes,
CRC-32 values, and SHA-256 digests as JSON. It never calls `extractall` or any
installer entry point. The defaults can be reduced with:

- `--max-members`
- `--max-member-size`
- `--max-total-size`
- `--max-expansion-ratio`
- `--max-streamed-bytes`

The inspector rejects absolute or drive-prefixed paths, backslashes, control
characters, unsafe components, duplicate raw or normalized names, non-regular
types, encrypted members, unsupported compression, unsafe physical layout,
excess limits, failed CRCs, truncation, and missing allowlisted members.

## Profile resolution

Resolve an explicit local profile against catalog compatibility and policy:

```bash
python3 module-tool.py resolve \
    --profile profiles/lineage.toml \
    --lock locks/artifacts.lock.json \
    --format json
```

Resolution validates dependencies, conflicts, ROM status, root mode, ABI/API,
declared providers and capabilities, legal output scope, and lock-bound critical
acknowledgements. Unknown or ambiguous data fails closed. Output includes the
selected modules, structured decisions and warnings, output scope, and a stable
fingerprint. Resolution does not fetch artifacts or mutate an OTA.

## Failure behavior

Input, policy, cache, archive, and resolution failures exit with status 2 and a
concise diagnostic. The CLI does not reinterpret an unavailable local input as
permission to contact a different endpoint.
