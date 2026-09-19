# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

from pathlib import Path
import tempfile
import unittest

from lib.modules.locks import load_canonical_lock
from lib.modules.providers.microg import update_microg_lock
from lib.modules.registry import MICROG_APK_SIGNER_SHA256


TAG = 'v0.3.15.250932'
GMS_DIGEST = '52' * 32
COMPANION_DIGEST = 'a9' * 32


def release_fixture():
    return {
        'tag_name': TAG,
        'draft': False,
        'prerelease': False,
        'assets': [
            {
                'name': 'com.google.android.gms-250932030.apk',
                'size': 105948577,
                'digest': f'sha256:{GMS_DIGEST}',
                'browser_download_url': (
                    'https://github.com/microg/GmsCore/releases/download/'
                    f'{TAG}/com.google.android.gms-250932030.apk'
                ),
            },
            {
                'name': 'com.android.vending-84022630.apk',
                'size': 4639851,
                'digest': f'sha256:{COMPANION_DIGEST}',
                'browser_download_url': (
                    'https://github.com/microg/GmsCore/releases/download/'
                    f'{TAG}/com.android.vending-84022630.apk'
                ),
            },
            {
                'name': 'com.google.android.gms-250932030-hw.apk',
                'size': 1,
                'digest': f'sha256:{"11" * 32}',
                'browser_download_url': (
                    'https://github.com/microg/GmsCore/releases/download/'
                    f'{TAG}/com.google.android.gms-250932030-hw.apk'
                ),
            },
        ],
    }


class MicroGProviderTest(unittest.TestCase):
    def test_explicit_release_generates_canonical_two_apk_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'microg.lock.json'
            lock = update_microg_lock(
                output=output,
                release_tag=TAG,
                release_fetcher=lambda _: release_fixture(),
            )
            loaded, _ = load_canonical_lock(output)
            self.assertEqual(lock, loaded)
            self.assertEqual(('microg',), tuple(m.id for m in lock.modules))
            module = lock.modules[0]
            self.assertEqual(TAG, module.version)
            self.assertEqual(
                ('companion-apk', 'gmscore-apk'),
                tuple(a.id for a in module.artifacts),
            )
            by_id = {artifact.id: artifact for artifact in module.artifacts}
            self.assertEqual(
                'com.android.vending',
                by_id['companion-apk'].apk.package_name,
            )
            self.assertEqual(84022630, by_id['companion-apk'].apk.version_code)
            self.assertEqual(
                'com.google.android.gms',
                by_id['gmscore-apk'].apk.package_name,
            )
            self.assertEqual(250932030, by_id['gmscore-apk'].apk.version_code)
            for artifact in module.artifacts:
                self.assertEqual(
                    MICROG_APK_SIGNER_SHA256,
                    artifact.apk.signer_sha256,
                )
                self.assertEqual('Apache-2.0', artifact.legal.license)
                self.assertIn('published', artifact.legal.allowed_output_scopes)

    def test_draft_release_fails_closed(self) -> None:
        release = release_fixture()
        release['draft'] = True
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'selected release'):
                update_microg_lock(
                    output=Path(temporary) / 'lock.json',
                    release_tag=TAG,
                    release_fetcher=lambda _: release,
                )

    def test_missing_custom_rom_asset_fails_closed(self) -> None:
        release = release_fixture()
        release['assets'] = [
            asset
            for asset in release['assets']
            if asset['name'] != 'com.android.vending-84022630.apk'
        ]
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'exactly one custom-ROM'):
                update_microg_lock(
                    output=Path(temporary) / 'lock.json',
                    release_tag=TAG,
                    release_fetcher=lambda _: release,
                )

    def test_wrong_download_url_fails_closed(self) -> None:
        release = release_fixture()
        release['assets'][0]['browser_download_url'] = 'https://example.com/x.apk'
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'asset metadata is invalid'):
                update_microg_lock(
                    output=Path(temporary) / 'lock.json',
                    release_tag=TAG,
                    release_fetcher=lambda _: release,
                )


if __name__ == '__main__':
    unittest.main()
