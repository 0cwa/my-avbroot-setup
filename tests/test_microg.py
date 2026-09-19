# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

from pathlib import Path
import tempfile
import unittest

from lib.filesystem import ExtInstallResult
from lib.modules.microg import (
    COMPANION_ARTIFACT_ID,
    COMPANION_PATH,
    COMPANION_VERSION_CODE,
    GMSCORE_ARTIFACT_ID,
    GMSCORE_PATH,
    GMSCORE_VERSION_CODE,
    INJECTED_PATHS,
    MICROG_CONFIG_PATH,
    MicroGAdapterError,
    MicroGModule,
    RELEASE,
)
from lib.modules.registry import MICROG_APK_SIGNER_SHA256
from lib.modules.resolver import CompatibilityDecision
from lib.modules.verified import LockedAdapterContext, VerifiedArtifact


class RecordingProduct:
    def __init__(self) -> None:
        self.requests = None

    def install(self, requests):
        self.requests = tuple(requests)
        return tuple(
            ExtInstallResult(Path(request.path), 'created')
            for request in self.requests
        )


def artifact(
    artifact_id: str,
    package_name: str,
    version_code: int,
    payload: bytes,
):
    source = tempfile.TemporaryFile()
    source.write(payload)
    source.flush()
    source.seek(0)
    return VerifiedArtifact(
        id=artifact_id,
        kind='apk',
        role='injection-input',
        version=str(version_code),
        size=len(payload),
        sha256='00' * 32,
        apk_package_name=package_name,
        apk_version_code=version_code,
        apk_signer_sha256=MICROG_APK_SIGNER_SHA256,
        archive_members=(),
        archive_apk_signers=(),
        license='Apache-2.0',
        source_offer_required=False,
        corresponding_source_artifact=None,
        allowed_output_scopes=(
            'local-unpublished',
            'private',
            'shared',
            'published',
        ),
        _source=source,
    )


def context(rom_family='lineageos'):
    companion = artifact(
        COMPANION_ARTIFACT_ID,
        'com.android.vending',
        COMPANION_VERSION_CODE,
        b'companion',
    )
    gmscore = artifact(
        GMSCORE_ARTIFACT_ID,
        'com.google.android.gms',
        GMSCORE_VERSION_CODE,
        b'gmscore',
    )
    ctx = LockedAdapterContext(
        module_id='microg',
        module_version=RELEASE,
        profile_id='lineage-pdx235',
        rom_family=rom_family,
        output_scope='published',
        lock_sha256='11' * 32,
        selection_fingerprint='22' * 32,
        decision=CompatibilityDecision(
            module='microg',
            rom_status='experimental',
            reason={'code': 'pdx235-validation-pending', 'message': 'pending'},
            warnings=(),
        ),
        trusted_signers=(
            ('apk-signer-sha256', MICROG_APK_SIGNER_SHA256),
        ),
        artifacts=(companion, gmscore),
    )
    return ctx


def close_context(ctx):
    for item in ctx.artifacts:
        item._source.close()


class MicroGAdapterTest(unittest.TestCase):
    def test_injects_reviewed_product_privapp_layout(self) -> None:
        ctx = context()
        self.addCleanup(close_context, ctx)
        module = MicroGModule(ctx)
        product = RecordingProduct()
        report = module.inject({}, {'product': product}, ())
        by_path = {str(request.path): request for request in product.requests}
        self.assertEqual(set(INJECTED_PATHS), set(report.injected_paths))
        self.assertEqual(b'gmscore', by_path[GMSCORE_PATH].data)
        self.assertEqual(b'companion', by_path[COMPANION_PATH].data)
        self.assertIn(MICROG_CONFIG_PATH, by_path)
        self.assertEqual({'product'}, module.requirements().ext_images)

    def test_grapheneos_is_rejected_by_adapter(self) -> None:
        ctx = context('grapheneos')
        self.addCleanup(close_context, ctx)
        with self.assertRaisesRegex(MicroGAdapterError, 'only LineageOS'):
            MicroGModule(ctx)

    def test_wrong_signer_is_rejected(self) -> None:
        ctx = context()
        self.addCleanup(close_context, ctx)
        bad = ctx.artifacts[0]
        object.__setattr__(bad, 'apk_signer_sha256', 'ff' * 32)
        with self.assertRaisesRegex(MicroGAdapterError, 'unexpected identity'):
            MicroGModule(ctx)


if __name__ == '__main__':
    unittest.main()
