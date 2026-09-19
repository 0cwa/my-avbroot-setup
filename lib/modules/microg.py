# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Locked, non-executing microG image adapter for current LineageOS."""

from collections.abc import Iterable
from pathlib import Path
from typing import Final

from lib.filesystem import CpioFs, ExtFs, ExtInstallRequest
from lib.modules import Module, ModuleRequirements
from lib.modules.registry import MICROG_APK_SIGNER_SHA256
from lib.modules.report import AdapterPatchResult
from lib.modules.verified import LockedAdapterContext, VerifiedArtifact


MODULE_ID: Final = 'microg'
RELEASE: Final = 'v0.3.15.250932'
GMSCORE_ARTIFACT_ID: Final = 'gmscore-apk'
COMPANION_ARTIFACT_ID: Final = 'companion-apk'
GMSCORE_VERSION_CODE: Final = 250932030
COMPANION_VERSION_CODE: Final = 84022630

GMSCORE_PATH: Final = '/product/priv-app/GmsCore/GmsCore.apk'
COMPANION_PATH: Final = '/product/priv-app/FakeStore/FakeStore.apk'
GMSCORE_PRIVAPP_PATH: Final = (
    '/product/etc/permissions/privapp-permissions-com.google.android.gms.xml'
)
GMSCORE_DEFAULT_PERMISSIONS_PATH: Final = (
    '/product/etc/default-permissions/default-permissions-com.google.android.gms.xml'
)
GMSCORE_SYSCONFIG_PATH: Final = (
    '/product/etc/sysconfig/sysconfig-com.google.android.gms.xml'
)
MICROG_CONFIG_PATH: Final = '/product/etc/microg.xml'
COMPANION_PRIVAPP_PATH: Final = (
    '/product/etc/permissions/privapp-permissions-com.android.vending.xml'
)
COMPANION_DEFAULT_PERMISSIONS_PATH: Final = (
    '/product/etc/default-permissions/default-permissions-com.android.vending.xml'
)

INJECTED_PATHS: Final = tuple(sorted((
    GMSCORE_PATH,
    COMPANION_PATH,
    GMSCORE_PRIVAPP_PATH,
    GMSCORE_DEFAULT_PERMISSIONS_PATH,
    GMSCORE_SYSCONFIG_PATH,
    MICROG_CONFIG_PATH,
    COMPANION_PRIVAPP_PATH,
    COMPANION_DEFAULT_PERMISSIONS_PATH,
)))

_EXPECTED_SIGNERS: Final = (
    ('apk-signer-sha256', MICROG_APK_SIGNER_SHA256),
)
_ALLOWED_SCOPES: Final = (
    'local-unpublished',
    'private',
    'shared',
    'published',
)

GMSCORE_PRIVAPP_XML: Final = b'''<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <privapp-permissions package="com.google.android.gms">
        <permission name="android.permission.FAKE_PACKAGE_SIGNATURE"/>
        <permission name="android.permission.CHANGE_DEVICE_IDLE_TEMP_WHITELIST"/>
        <permission name="android.permission.FOREGROUND_SERVICE"/>
        <permission name="android.permission.INSTALL_LOCATION_PROVIDER"/>
        <permission name="android.permission.LOCATION_HARDWARE"/>
        <permission name="android.permission.MANAGE_USB"/>
        <permission name="android.permission.MODIFY_PHONE_STATE"/>
        <permission name="android.permission.NETWORK_SCAN"/>
        <permission name="android.permission.PROVIDE_REMOTE_CREDENTIALS"/>
        <permission name="android.permission.PROVIDE_DEFAULT_ENABLED_CREDENTIAL_SERVICE"/>
        <permission name="android.permission.READ_CONTACTS"/>
        <permission name="android.permission.START_ACTIVITIES_FROM_BACKGROUND"/>
        <permission name="android.permission.UPDATE_APP_OPS_STATS"/>
        <permission name="android.permission.UPDATE_DEVICE_STATS"/>
        <permission name="android.permission.WATCH_APPOPS"/>
        <permission name="android.permission.INTERACT_ACROSS_PROFILES"/>
        <permission name="android.permission.INTERACT_ACROSS_USERS"/>
    </privapp-permissions>
</permissions>
'''

GMSCORE_DEFAULT_PERMISSIONS_XML: Final = b'''<?xml version="1.0" encoding="utf-8"?>
<exceptions>
    <exception package="com.google.android.gms">
        <permission name="android.permission.BODY_SENSORS" fixed="false"/>
        <permission name="android.permission.GET_ACCOUNTS" fixed="false"/>
        <permission name="android.permission.READ_CONTACTS" fixed="false"/>
        <permission name="android.permission.WRITE_CONTACTS" fixed="false"/>
        <permission name="android.permission.ACCESS_COARSE_LOCATION" fixed="false"/>
        <permission name="android.permission.ACCESS_FINE_LOCATION" fixed="false"/>
        <permission name="android.permission.RECEIVE_SMS" fixed="false" whitelisted="true"/>
        <permission name="android.permission.READ_PHONE_STATE" fixed="false"/>
        <permission name="android.permission.READ_EXTERNAL_STORAGE" fixed="false"/>
        <permission name="android.permission.WRITE_EXTERNAL_STORAGE" fixed="false"/>
        <permission name="android.permission.CAMERA" fixed="false"/>
        <permission name="android.permission.POST_NOTIFICATIONS" fixed="false"/>
        <permission name="android.permission.SYSTEM_ALERT_WINDOW" fixed="false"/>
    </exception>
</exceptions>
'''

GMSCORE_SYSCONFIG_XML: Final = b'''<?xml version="1.0" encoding="utf-8"?>
<config>
    <allow-in-power-save package="com.google.android.gms"/>
    <allow-in-data-usage-save package="com.google.android.gms"/>
    <allow-unthrottled-location package="com.google.android.gms"/>
</config>
'''

MICROG_CONFIG_XML: Final = b'''<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<map>
    <boolean name="checkin_enable_service" value="false"/>
    <boolean name="gcm_enable_mcs_service" value="false"/>
    <boolean name="auth_manager_trust_google" value="true"/>
    <boolean name="auth_manager_visible" value="true"/>
    <boolean name="safetynet_enabled" value="false"/>
    <boolean name="droidguard_enabled" value="false"/>
    <boolean name="location_wifi_mls" value="true"/>
    <boolean name="location_wifi_moving" value="true"/>
    <boolean name="location_wifi_learning" value="true"/>
    <boolean name="location_cell_mls" value="true"/>
    <boolean name="location_cell_learning" value="true"/>
    <boolean name="location_geocoder_nominatim" value="true"/>
    <boolean name="exposure_scanner_enabled" value="false"/>
    <boolean name="wifi_mls" value="true"/>
    <boolean name="cell_mls" value="true"/>
    <boolean name="wifi_learning" value="true"/>
    <boolean name="cell_learning" value="true"/>
    <boolean name="wifi_moving" value="true"/>
    <boolean name="nominatim_enabled" value="true"/>
    <boolean name="vending_licensing" value="true"/>
    <boolean name="vending_licensing_purchase_free_apps" value="true"/>
    <boolean name="vending_billing" value="true"/>
    <boolean name="vending_asset_delivery" value="true"/>
    <boolean name="vending_device_sync" value="true"/>
</map>
'''

COMPANION_PRIVAPP_XML: Final = b'''<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <privapp-permissions package="com.android.vending">
        <permission name="android.permission.FAKE_PACKAGE_SIGNATURE"/>
        <permission name="android.permission.REQUEST_INSTALL_PACKAGES"/>
        <permission name="android.permission.DELETE_PACKAGES"/>
        <permission name="android.permission.INSTALL_PACKAGES"/>
        <permission name="android.permission.INTERACT_ACROSS_PROFILES"/>
        <permission name="android.permission.INTERACT_ACROSS_USERS"/>
    </privapp-permissions>
</permissions>
'''

COMPANION_DEFAULT_PERMISSIONS_XML: Final = b'''<?xml version="1.0" encoding="utf-8"?>
<exceptions>
    <exception package="com.android.vending">
        <permission name="android.permission.FAKE_PACKAGE_SIGNATURE" fixed="false"/>
        <permission name="android.permission.GET_ACCOUNTS" fixed="false"/>
        <permission name="android.permission.ACCESS_COARSE_LOCATION" fixed="false"/>
        <permission name="android.permission.POST_NOTIFICATIONS" fixed="false"/>
    </exception>
</exceptions>
'''


class MicroGAdapterError(ValueError):
    """The reviewed microG adapter contract was violated."""


def _read_artifact(artifact: VerifiedArtifact) -> bytes:
    with artifact.open() as source:
        data = source.read(artifact.size + 1)
    if len(data) != artifact.size:
        raise MicroGAdapterError(
            f'verified artifact changed size while reading: {artifact.id}'
        )
    return data


def _require_apk(
    artifact: VerifiedArtifact,
    *,
    artifact_id: str,
    package_name: str,
    version_code: int,
) -> None:
    if (
        artifact.id != artifact_id
        or artifact.kind != 'apk'
        or artifact.role != 'injection-input'
        or artifact.apk_package_name != package_name
        or artifact.apk_version_code != version_code
        or artifact.apk_signer_sha256 != MICROG_APK_SIGNER_SHA256
        or artifact.archive_members
        or artifact.license != 'Apache-2.0'
        or artifact.source_offer_required
        or artifact.corresponding_source_artifact is not None
        or artifact.allowed_output_scopes != _ALLOWED_SCOPES
    ):
        raise MicroGAdapterError(
            f'locked microG artifact has an unexpected identity or policy: '
            f'{artifact.id}'
        )


class MicroGModule(Module):
    """Install official microG Services and Companion as product priv-apps."""

    def __init__(self, context: LockedAdapterContext) -> None:
        if not isinstance(context, LockedAdapterContext):
            raise TypeError('microG adapter requires a LockedAdapterContext')
        if context.module_id != MODULE_ID or context.module_version != RELEASE:
            raise MicroGAdapterError('microG adapter received the wrong module version')
        if context.rom_family != 'lineageos':
            raise MicroGAdapterError('microG adapter supports only LineageOS')
        if context.decision.rom_status != 'experimental':
            raise MicroGAdapterError('LineageOS microG must remain experimental')
        if context.decision.module != MODULE_ID:
            raise MicroGAdapterError('microG compatibility decision is mismatched')
        if context.trusted_signers != _EXPECTED_SIGNERS:
            raise MicroGAdapterError('microG adapter trust root is not exact')

        by_id = {artifact.id: artifact for artifact in context.artifacts}
        if len(by_id) != len(context.artifacts) or set(by_id) != {
            COMPANION_ARTIFACT_ID,
            GMSCORE_ARTIFACT_ID,
        }:
            raise MicroGAdapterError(
                'microG lock must contain exactly Services and Companion APKs'
            )

        companion = by_id[COMPANION_ARTIFACT_ID]
        gmscore = by_id[GMSCORE_ARTIFACT_ID]
        _require_apk(
            companion,
            artifact_id=COMPANION_ARTIFACT_ID,
            package_name='com.android.vending',
            version_code=COMPANION_VERSION_CODE,
        )
        _require_apk(
            gmscore,
            artifact_id=GMSCORE_ARTIFACT_ID,
            package_name='com.google.android.gms',
            version_code=GMSCORE_VERSION_CODE,
        )
        self._companion_apk = _read_artifact(companion)
        self._gmscore_apk = _read_artifact(gmscore)

    def requirements(self) -> ModuleRequirements:
        return ModuleRequirements(set(), {'product'}, False)

    def inject(
        self,
        boot_fs: dict[str, CpioFs],
        ext_fs: dict[str, ExtFs],
        sepolicies: Iterable[Path],
        compatible_sepolicy: bool = False,
    ) -> AdapterPatchResult:
        del boot_fs, sepolicies, compatible_sepolicy
        if 'product' not in ext_fs:
            raise MicroGAdapterError('microG adapter requires the product filesystem')
        product = ext_fs['product']
        requests = (
            ExtInstallRequest(
                '/product/priv-app/GmsCore', 'Directory', 0o755, 0, 0
            ),
            ExtInstallRequest(
                GMSCORE_PATH, 'RegularFile', 0o644, 0, 0, self._gmscore_apk
            ),
            ExtInstallRequest(
                '/product/priv-app/FakeStore', 'Directory', 0o755, 0, 0
            ),
            ExtInstallRequest(
                COMPANION_PATH, 'RegularFile', 0o644, 0, 0, self._companion_apk
            ),
            ExtInstallRequest(
                GMSCORE_PRIVAPP_PATH,
                'RegularFile',
                0o644,
                0,
                0,
                GMSCORE_PRIVAPP_XML,
            ),
            ExtInstallRequest(
                GMSCORE_DEFAULT_PERMISSIONS_PATH,
                'RegularFile',
                0o644,
                0,
                0,
                GMSCORE_DEFAULT_PERMISSIONS_XML,
            ),
            ExtInstallRequest(
                GMSCORE_SYSCONFIG_PATH,
                'RegularFile',
                0o644,
                0,
                0,
                GMSCORE_SYSCONFIG_XML,
            ),
            ExtInstallRequest(
                MICROG_CONFIG_PATH,
                'RegularFile',
                0o644,
                0,
                0,
                MICROG_CONFIG_XML,
            ),
            ExtInstallRequest(
                COMPANION_PRIVAPP_PATH,
                'RegularFile',
                0o644,
                0,
                0,
                COMPANION_PRIVAPP_XML,
            ),
            ExtInstallRequest(
                COMPANION_DEFAULT_PERMISSIONS_PATH,
                'RegularFile',
                0o644,
                0,
                0,
                COMPANION_DEFAULT_PERMISSIONS_XML,
            ),
        )
        results = product.install(requests)
        status_by_path = {
            str(result.path): result.status
            for result in results
            if str(result.path) in INJECTED_PATHS
        }
        if set(status_by_path) != set(INJECTED_PATHS):
            raise MicroGAdapterError(
                'filesystem installer returned incomplete microG results'
            )
        return AdapterPatchResult(
            INJECTED_PATHS,
            tuple((path, status_by_path[path]) for path in INJECTED_PATHS),
        )
