# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

from pathlib import Path
import tempfile
import unittest

from lib.filesystem import ExtInstallResult
from lib.modules.locks import load_canonical_lock
from lib.modules.microg import (
    COMPANION_ARTIFACT_ID,
    COMPANION_PATH,
    COMPANION_VERSION_CODE,
    GMSCORE_ARTIFACT_ID,
    GMSCORE_PATH,
    GMSCORE_VERSION_CODE,
    INJECTED_PATHS,
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
            reason={'code': 'lineage-validation-pending', 'message': 'pending'},
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
        self.assertEqual({'product'}, module.requirements().ext_images)

    def test_checked_in_lock_matches_reviewed_release(self) -> None:
        lock, _ = load_canonical_lock(
            Path('locks/microg-v0.3.15.250932.json')
        )
        self.assertEqual(('microg',), tuple(module.id for module in lock.modules))
        module = lock.modules[0]
        self.assertEqual(RELEASE, module.version)
        by_id = {artifact.id: artifact for artifact in module.artifacts}
        self.assertEqual(
            {'companion-apk', 'gmscore-apk'},
            set(by_id),
        )
        expected = {
            'companion-apk': (
                'com.android.vending',
                COMPANION_VERSION_CODE,
                4639851,
                'a973e0235a2829773a4faf36d235d5f703d1c04a2adff674ebaa535a2e78f937',
            ),
            'gmscore-apk': (
                'com.google.android.gms',
                GMSCORE_VERSION_CODE,
                105948577,
                '52597e77fd25fdd347574d0457ed1936a4b9561cf4c8d34e7ac8dd8191dfd4b9',
            ),
        }
        for artifact_id, (package, version, size, digest) in expected.items():
            artifact = by_id[artifact_id]
            self.assertEqual(package, artifact.apk.package_name)
            self.assertEqual(version, artifact.apk.version_code)
            self.assertEqual(MICROG_APK_SIGNER_SHA256, artifact.apk.signer_sha256)
            self.assertEqual(size, artifact.size)
            self.assertEqual(digest, artifact.sha256)
            self.assertEqual(
                (
                    'https://github.com',
                    'https://release-assets.githubusercontent.com',
                ),
                artifact.allowed_origins,
            )

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
