# Worklane 1 — care-map provenance RFC (research-only; release blocked)

**Status (2026-10-12):** Prototype and 24 synthetic tests completed **offline**, but **no Rust avbroot patch, no real-image integration test, no signed OTA, and no release authorization**. This is an interface proposal, not a production helper change. ModOS issue [#114](https://github.com/0cwa/ModOS/issues/114) remains open. Never enable the dormant production source-digest exception based on this RFC.

## Authenticated source and root cause

The original LineageOS pdx235 2026-10-09 signed OTA is publisher-authenticated against the independent LineageOS key and official API; exact SHA-256:
`b2b4269738df1d3092de49bde6c7d0ffcb62ae19b342213a819187c30b7ab1f8`.

In the original signed images, all six partitions (`odm,product,system,system_ext,vendor,vendor_dlkm`) have Sony Android 15 `ro.<partition>.build.fingerprint` properties, matching the original signed care map. The AVB descriptor `com.android.build.<partition>.fingerprint` is instead LineageOS Android 16. This is explained by [dated sysprop.mk](https://github.com/LineageOS/android_build/blob/e5aaa62172df0f321e68133fa30f42316376bfe8/core/sysprop.mk) using `PRODUCT_BUILD_PROP_OVERRIDES`, versus [dated Makefile](https://github.com/LineageOS/android_build/blob/e5aaa62172df0f321e68133fa30f42316376bfe8/core/Makefile) using `BUILD_FINGERPRINT_FROM_FILE`. [avbroot 3.34.1](https://github.com/chenxiaolong/avbroot/blob/v3.34.1/avbroot/src/format/care_map.rs) incorrectly assumes the AVB value is the runtime identity, and reconstructs one contiguous range.

Dated [AOSP releasetools](https://github.com/LineageOS/android_build/blob/e5aaa62172df0f321e68133fa30f42316376bfe8/tools/releasetools/add_img_to_target_files.py) uses actual partition build props and clips Android sparse **RAW/FILL** meaningful chunks at the AVB footer's original data boundary; **DONT_CARE** chunks are excluded. This sparse-container metadata is not necessarily recoverable from expanded payload raw images. A filesystem allocation map is not an equivalent substitute.

[update_verifier.cpp](https://github.com/LineageOS/android_bootable_recovery/blob/acd99f7c48e0229eaedd40aa3e2adcbabe2dc283/update_verifier/update_verifier.cpp) selects care-map entries by checking *runtime* `GetProperty(id)` against the map fingerprint. Mismatched entries are skipped, and a totally empty selection can lead to skipped block verification.

## Conservative sufficient proof for reusing signed sparse ranges

Let `S_p` be the independently authenticated source care-map block ranges and `D_p` the 4096-byte protected filesystem blocks whose contents differ between extracted original and final partition images. Require **`D_p ⊆ S_p`** and retain `S_p` exactly. Additional mandatory requirements:

1. Authenticate exact source publisher/signature, pinned source ZIP digest, signed payload manifest and original signed care map **before** source handling; never bootstrap trust from an embedded certificate alone.
2. Source map entries must be unique, complete, have genuine `ro.<partition>.build.fingerprint` IDs, valid nonempty fingerprints, and ordered nonoverlapping positive ranges inside the AVB data extent. Cover every required dynamic partition exactly.
3. Original map fingerprints must match **actual original filesystem build.props** from signed raw images. Output fingerprints must come from **actual final filesystem build.props**, never AVB descriptors. Missing/conflicting/unsupported properties fail closed.
4. Verify source and final **whole-image** SHA-256 hashes and sizes against separately signature-verified payload manifests. Require equal image layout, equal protected data extents, and `hashtree.image_size == AVB_footer.original_image_size` on each side.
5. Compare every protected block of final vs source, rejecting **any** change outside the original signed sparse care ranges. Do not invent, narrow, ignore, or blindly expand ranges. Final candidate care map must match the independently recomputed entire partition set, property IDs, fingerprints **and ranges**.
6. Continue output signer-pinned whole-file OTA/payload signatures, partition-hash verification, independently configured output AVB signing key, AVB tree/descriptors and vbmeta flags, recovery certificate, and first-boot checks. Never waive those cryptographic or runtime checks.

This rule is intentionally **restrictive**: changed out-of-range blocks, changed partition sizes, non-ext4 images, unverified source maps and new sparse allocations are hard failures, pending a separately justified AOSP-compatible regeneration method. AVB/FEC/footer changes outside protected data may be handled only by the existing independent cryptographic verification.

## Prototype boundary and status

A standalone research-only Python prototype implements strict protobuf parsing, range checks, streamed image SHA-256 and block differences, exact sparse range preservation, final property reading via read-only `debugfs`, and candidate map recomputation. Local tests (24) cover valid overrides, sparse ranges, malformed records, changed in/out-of-range blocks, changed sizes, bad image digests, AVB-footer changes, wrong identities, missing partitions, and extractor failures. The prototype and complete root-cause/design report are supplied as downloadable artifacts with the Worklane 1 investigation, **not connected to this helper's production entrypoints**. This draft PR intentionally contains only the reviewed interface RFC.

**Do not interpret synthetic tests as real-device, cryptographic or Rust tests.** The current `avbroot 3.34.1 ota verify` still derives AVB fingerprints and contiguous ranges, so will reject a corrected map. A provenance-aware *expected-map computation* in avbroot or an equivalently cryptographically bound verified helper boundary is required before implementation can produce and strictly verify an output OTA.

## Cross-lane handoff

**Worklane 3:** supply original signed care map, authenticated manifest partition list, original manifest-verified raw images, original verified `ro.<partition>.build.fingerprint` locations, and exact AVB hashtree + footer sizes. Keep the existing source/output **identity-preservation guard** unless an actual property change is separately reviewed. Require physical first-boot getprops and update_verifier/verity/snapuserd logs for all six partitions.

**Worklane 4:** bind candidate output raw images to the **verified signed output manifest**, extract final build props, run `D⊆S` proof, compare the candidate protobuf map **exactly** to the proof output, and retain all output cryptographic checks (expected OTA signer and configured AVB signer). Fail before sidecar/report/publication on any evidence gap. The output verifier needs an independently verified source-map provenance mode; never change stock strict verification into an arbitrary tolerance rule.

**Proof output contract:** source OTA SHA-256, original signed map SHA-256, source + final image SHA-256 and sizes, verified hashtree/footer data size, source and final filesystem fingerprint identity for each partition, raw care range string, and changed protected block count. Only emit success after manifest and image evidence has been verified; callers must not inject untrusted expected hashes.

## Unresolved guarantees / release gate

- Exact original AOSP sparse RAW/FILL/DONT_CARE boundaries cannot be reconstructed from raw payload bytes; preserving authenticated ranges is a conservative sufficient condition, not general regeneration.
- Inspecting image build.props does not prove the device's **effective runtime** getprops or update_verifier execution. Real boot and OTA persistence acceptance remain required.
- No audited ext4 extractor validation on exact signed source/final images, target-files `META/misc_info.txt`, or physical boot evidence is available here.
- No verified Rust integration and no provenance-aware avbroot verifier currently exists. AVB public test keys and insecure vbmeta flags remain separate blockers.
- Production source digest pin stays empty. No source exception activation, branch merge, OTA build/publication, or upstream maintainer contact is authorized.

**Disposition:** Sound conservative design and passing synthetic prototype tests, but **integration and release blocked**.

## Mandatory pre-sign / post-sign separation

At patch time the proof is **provisional**: the patch engine can hash generated raw images and compare protected blocks, but those expected output hashes are not yet bound to any signed OTA. After the output OTA has been signed, independently verify its configured OTA signer, payload signatures, configured AVB signer and descriptor chain, recovery certificate, and signed payload partition hashes; **re-extract every final image and repeat the same fingerprint / changed-block / sparse-range proof against the authenticated source**. Only this signed-output postflight proof can allow sidecars, reports, or publication. Never trust pre-sign expected hashes as final signed-manifest evidence.

## 2026-10-12 executable research candidate and Worklane 3 integration

This isolated draft now contains a **self-contained research implementation** in `research/care_map_prototype.py` plus the standalone `research/care_map_candidate.py --json` adapter. These are **NOT imported, installed, called, or approved by the helper's production patch.py**. Both synthetic Worklane 3 exchange schemas are supported: `modos-care-map-conformance-v1` (RAW/FILL/DONT_CARE extent reconstruction) and `modos-care-map-provenance-v1` (six-partition protected data-diff/signed-map preservation). The latter uses JSON-provided source/final image bytes and **caller-supplied mock filesystem fingerprints/manifest digests**, so it cannot authenticate any signer or final image on its own. It exists solely to run an independent candidate conformance suite and help define an eventual Rust proof-bound verifier.

Run `python3 -m unittest discover -s tests -p 'test_worklane1_*.py' -v` from repository root. **54 synthetic unit tests passed locally** in a separate research checkout, including a sweep of every protected synthetic block against the original sparse-care-set membership, canonical range-decimal rejection, source/updated manifest digests, AVB-only fingerprint substitution, missing/duplicate partitions, and separate suffix changes. The byte-exact 1,086-byte authenticated source map reconstructed from independent recorded ranges has SHA-256 `e903a2c0e4a71aaadf757d7d479a6be2ca80939a084c1832796db61c75e6e147`. This does not claim a fresh signed archive verification.

Worklane 3 may use `CARE_MAP_CONFORMANCE_REQUIRE_CANDIDATE=1 CARE_MAP_CANDIDATE_CMD='python3 research/care_map_candidate.py --json'` and `CARE_MAP_PROVENANCE_REQUIRED=1 CARE_MAP_PROVENANCE_CMD='python3 research/care_map_candidate.py --json'` in a **test workspace containing both suites**. W3's independent reference implementation is *never imported* by this candidate. A separate future nonpublishing test with real, independently authenticated final images must use `debugfs_build_fingerprint()` and verified signed manifests, not this synthetic test-only adapter.

Do not promote this prototype, enable an exception, or interpret a green synthetic contract suite as OTA/runtime safety. The stock avbroot v3.34.1 verifier still computes wrong AVB-only fingerprints and contiguous ranges.
