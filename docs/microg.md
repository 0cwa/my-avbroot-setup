# microG locked module

The `microg` adapter injects the official microG Services and Companion APKs
as privileged product apps. It does not patch Android framework code and does
not execute installer scripts.

The reviewed v1 target is LineageOS API 36. Current LineageOS contains
restricted microG signature spoofing for `com.google.android.gms` and
`com.android.vending` when the packages are signed by the official microG
release certificate. GrapheneOS is intentionally incompatible with this module.

## Updating the lock

Updates are explicit:

```bash
python3 module-tool.py lock update microg \
  --release-tag v0.3.15.250932 \
  --output locks/microg-v0.3.15.250932.json
```

The provider accepts only the two custom-ROM APK names from the selected
official GitHub release, requires GitHub's SHA-256 asset digests, and records
the official microG APK signer. Normal fetch/verify then rechecks file size,
SHA-256, package name, versionCode, and the single APK signer.

The adapter also pins the reviewed release and exact package/version identities,
so advancing the lock alone cannot silently change privileged-app policy.
A version update must review the upstream privileged/default-permission changes
and update the adapter constants/tests.

v1 installs:

- `com.google.android.gms` (GmsCore)
- `com.android.vending` (microG Companion)

GsfProxy, F-Droid, Aurora Store, framework patches, Magisk modules, and runtime
signature-spoofing hooks are deliberately out of scope.
