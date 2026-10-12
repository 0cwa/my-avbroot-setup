# Development avbroot care-map candidate

This source patch accompanies the helper's strict runtime care-map integration.
It is a reviewable local development candidate, not a chenxiaolong-signed release
or an entry in ModOS's existing production executable lock.

The provenance receipt records the exact upstream base, candidate source
revision, patch and Cargo.lock hashes, toolchain, build command and measured
binary digest. The optimized binary is not checked into this repository.

Rebuild in a new working checkout:

```sh
git clone https://github.com/chenxiaolong/avbroot.git avbroot-candidate
cd avbroot-candidate
git checkout --detach e805505affb042ed5ecb2e74cf5da3b465fb4e5d
git apply /path/to/this/tools/care-map/avbroot-runtime-care-map.patch
cargo build --release --locked -p avbroot --no-default-features
cargo test --locked -p avbroot --no-default-features
```

The candidate retains OTA/payload/partition/AVB verification and adds explicit
expected-map verification with deterministic block-write coverage. The helper
proves actual filesystem property identity. `--verification-report` is written
only on complete verification success. Modified images are fully recompressed,
including avbroot's implicit system certificate change, so newly cared data
blocks have deterministic final writes. Explicit AVB trust requires a signed
header; an unsigned header cannot satisfy an expected key or key digest.

Build fingerprints and executable hashes are sensitive to toolchain/build
inputs: a different local build must record its own source/toolchain/binary
receipt rather than pretending to match the supplied measured artifact.
A source-build receipt establishes what was built; it is not an upstream
publisher signature or device acceptance. Keep this development provenance
separate from the existing signed executable policy until a reviewed promotion
path is available.
