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

## Source-built development runner

`build_and_run.py` provides a separate development authorization path. It never
changes the production executable lock and does not present a locally compiled
binary as a vendor-signed artifact. Use it only from the explicitly selected
local-unpublished development workflow, after the reviewed source candidate has
passed real source/output acceptance.

```sh
python3 tools/care-map/build_and_run.py \
  --modos-repo /path/to/reviewed/ModOS \
  --bootstrap-workdir /path/to/authenticated-tools \
  --build-workdir /path/to/work/new-candidate-build \
  -- --runtime-care-map --input source.zip --output output.zip \
  --verify-public-key-avb source-avb_pkmd.bin --verify-cert-ota trusted-lineage-ota.pem \
  --sign-key-avb existing-avb.key --sign-key-ota existing-ota.key --sign-cert-ota existing-ota.pem \
  --patch-arg=--rootless --patch-arg=--clear-vbmeta-flags --skip-custota-tool
```

The build directory must not exist. The builder reads the fixed tracked-clean
`source-build.json` and patch from the captured helper Git commit, verifies the
patch digest, obtains a fresh checkout at the exact upstream base, applies the
verified patch bytes through stdin, verifies Cargo.lock, and builds with the
pinned Rust toolchain using `cargo build --release --locked`. Cargo/rustup state
defaults underneath the task build directory; explicitly selected task caches
can be passed with `--cargo-home` and `--rustup-home`. The build environment keeps
proxy/CA configuration but excludes signing secrets, GitHub credentials and
compiler overrides. This path assumes a trusted compiler, host and dependency
cache; it is a development source authorization path, not a replacement for the
vendor artifact trust policy.

The parent captures the fresh binary digest and size in memory and constructs
an exact ToolRunner argv prefix. Each avbroot invocation uses the existing
ModOS `open_sealed_executable` implementation to check those exact bytes and
execute a write-sealed memfd. The transport uses `/usr/bin/python3` on Linux,
with file-descriptor execution and fcntl seals; helper execution retains the
caller's Python environment. AFSR and Custota tools continue through ModOS's
existing authenticated executable bootstrap. The caller cannot override the
helper's ToolRunner prefix. Selected bootstrap source files must remain tracked
and clean; the helper's established patch.py compatibility transform is allowed.

`--prepare-only` emits the freshly derived prefix as JSON to stdout for a trusted
parent that must run multiple commands with the same build. Compiler/git logs go
to stderr. Capture that live build result in the parent and pass it directly to
commands; do not read a saved prefix or a mutable receipt as authorization.
`build-receipt.json` is evidence only. The builder refuses an existing build
directory, and the runner never consults receipts, environment digests, or the
historical measured binary digest in `avbroot-build-provenance.json`.

Building or preparing a prefix does not establish first boot, OTA persistence,
microG runtime behavior, or permission to publish. Keep device acceptance and
publication gates in their existing owning workflow.

Cold task Cargo/rustup homes are supported: toolchain installation disables
rustup self-update, then the builder resolves and invokes the pinned toolchain's
actual Cargo/Rustc binaries. Global proxy executables and caller compiler overrides
do not select the build compiler. Run the explicit network smoke independently
of default unit discovery to exercise empty homes and a tiny offline build:

```sh
python3 tests/cold_source_toolchain_smoke.py --workdir /path/to/work/cold-rust-smoke
```
