# microG locked module

The `microg` adapter injects official microG Services and Companion APKs as
privileged product apps. It does not patch Android framework code or execute
installer scripts.

The reviewed target is LineageOS API 36. It relies on LineageOS's restricted
signature spoofing for official microG-signed `com.google.android.gms` and
`com.android.vending`. GrapheneOS is intentionally incompatible.

## Reviewed release

The checked-in lock pins microG `v0.3.15.250932`:

- `com.google.android.gms` versionCode `250932030`
- `com.android.vending` versionCode `84022630`

Normal locked-artifact fetch/verify checks exact size, SHA-256, package name,
versionCode, and the single official microG APK signer before the adapter sees
the files. The adapter also pins the reviewed module release and package
identities.

Updates intentionally require a code review of the lock, adapter release
constants, and privileged/default-permission policy. There is no floating or
microG-specific lock-update command.

GsfProxy, F-Droid, Aurora Store, framework patches, Magisk modules, runtime
signature-spoofing hooks, and opinionated microG preference defaults are out of
scope.
