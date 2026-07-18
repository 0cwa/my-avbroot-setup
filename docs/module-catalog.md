# Module catalog

`lib/modules/manifests/` is the declarative catalog for patches understood by
this repository. Manifests are loaded in canonical module-ID order and describe
support status, artifact kind, verification policy, compatibility, dependencies,
conflicts, and structured warnings or incompatibility reasons.

List the catalog without loading any patch adapter:

```bash
python3 -m lib.modules.catalog
python3 -m lib.modules.catalog --format json
```

The catalog is intentionally separate from artifact acquisition and patch
execution. A manifest adapter is an opaque identifier resolved through a
static internal registry; it is not a Python import path. Only that trusted
registry contains constructor module/class targets. Planned and incompatible
entries cannot register adapters or become enabled by default.

Verification fields describe the checks that the registered adapter is expected
to enforce when it is constructed. The catalog loader checks that this metadata
matches the internal adapter registration, but it does not verify, acquire, or
trust an artifact by itself. Current adapters expect chenxiaolong's SSH signature
key, identified by its stable SHA-256 fingerprint.

Compatibility value `unknown` means that a ROM, root mode, or architecture has
not yet been established by the catalog. Value `any` is reserved for evidence
that no restriction applies. Either value must appear alone rather than being
combined with specific compatibility tokens.

This is the first stage of a broader patch format. It preserves the existing
`--module-<name>` command-line interface and does not fetch artifacts. A later
stage can add immutable URLs, digests, signer identities, and content-addressed
caching without coupling network access to OTA modification.

Magisk modules, recovery flashable ZIPs, and other root-patcher archives are not
executed automatically. Their installer scripts expect privileged runtime or
recovery environments and may perform arbitrary operations. Supporting one
requires a reviewed native adapter, an explicit compatibility classification,
and a verification policy; otherwise the catalog must mark it planned or
incompatible with a structured reason.
