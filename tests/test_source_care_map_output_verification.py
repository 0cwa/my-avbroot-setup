# SPDX-FileCopyrightText: 2026 PixeneOS contributors
# SPDX-License-Identifier: GPL-3.0-only

"""Fail-closed checks for OTAs regenerated after a source care-map exception."""

from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

from lib import external
import patch as patch_script


class SourceCareMapOutputVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.primary = self.root / 'rootless.zip'
        self.secondary = self.root / 'magisk.zip'
        self.cert = self.root / 'output-ota.crt'
        self.key = external.SigningKey(self.root / 'output-avb.key', 'AVB_PASS', None)
        self.expected_key = self.root / 'expected-output-avb-pkmd.bin'

    def _args(self, *, paired: bool = False) -> SimpleNamespace:
        return SimpleNamespace(
            input=self.root / 'original.zip',
            output=self.primary,
            patch_arg=['--rootless'],
            secondary_output=self.secondary if paired else None,
            secondary_patch_arg=['--magisk'] if paired else [],
            sign_cert_ota=self.cert,
        )

    @staticmethod
    def _write_zip(path: Path, *, map_value: bytes | None = b'valid') -> None:
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('META-INF/com/android/metadata', 'pre-device=pdx235\n')
            if map_value is not None:
                archive.writestr('care_map.pb', map_value)

    @staticmethod
    def _encode_fixture(unused_key: external.SigningKey, output: Path) -> None:
        output.write_bytes(b'configured-signing-key-public-identity')

    def test_derived_output_key_passed_to_strict_verifier(self) -> None:
        self._write_zip(self.primary)
        self._write_zip(self.secondary)
        with (
            mock.patch.object(
                external, 'encode_output_avb_public_key',
                side_effect=self._encode_fixture,
            ) as encode,
            mock.patch.object(external, 'verify_ota') as verify,
            mock.patch.object(
                patch_script.care_map_compat, 'verify_fingerprint_identity_preserved'
            ) as fingerprint_guard,
        ):
            patch_script._verify_outputs_after_source_care_map_exception(
                self._args(paired=True), self.key, self.root,
            )

        encode.assert_called_once_with(self.key, self.expected_key)
        self.assertEqual([
            mock.call(self.primary, self.expected_key, self.cert),
            mock.call(self.secondary, self.expected_key, self.cert),
        ], verify.call_args_list)
        for call in verify.call_args_list:
            self.assertNotIn('allow_source_care_map_mismatch', call.kwargs)
        self.assertEqual([
            mock.call(self.root / 'original.zip', self.primary),
            mock.call(self.root / 'original.zip', self.secondary),
        ], fingerprint_guard.call_args_list)

    def test_missing_care_map_is_rejected_without_verification(self) -> None:
        self._write_zip(self.primary, map_value=None)
        with (
            mock.patch.object(
                external, 'encode_output_avb_public_key',
                side_effect=self._encode_fixture,
            ),
            mock.patch.object(external, 'verify_ota') as verify,
            self.assertRaisesRegex(RuntimeError, 'care_map.pb'),
        ):
            patch_script._verify_outputs_after_source_care_map_exception(
                self._args(), self.key, self.root,
            )
        verify.assert_not_called()

    def test_empty_care_map_is_rejected(self) -> None:
        self._write_zip(self.primary, map_value=b'')
        with (
            mock.patch.object(
                external, 'encode_output_avb_public_key',
                side_effect=self._encode_fixture,
            ),
            mock.patch.object(external, 'verify_ota') as verify,
            self.assertRaisesRegex(RuntimeError, 'care_map.pb'),
        ):
            patch_script._verify_outputs_after_source_care_map_exception(
                self._args(), self.key, self.root,
            )
        verify.assert_not_called()

    def test_output_wrong_avb_signer_fails_strict_verification(self) -> None:
        self._write_zip(self.primary)
        with (
            mock.patch.object(
                external, 'encode_output_avb_public_key',
                side_effect=self._encode_fixture,
            ),
            mock.patch.object(
                external, 'verify_ota',
                side_effect=subprocess.CalledProcessError(1, ['avbroot', 'ota', 'verify']),
            ) as verify,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            patch_script._verify_outputs_after_source_care_map_exception(
                self._args(), self.key, self.root,
            )
        verify.assert_called_once_with(self.primary, self.expected_key, self.cert)

    def test_wrong_output_ota_certificate_fails_strict_verification(self) -> None:
        self._write_zip(self.primary)
        with (
            mock.patch.object(
                external, 'encode_output_avb_public_key',
                side_effect=self._encode_fixture,
            ),
            mock.patch.object(
                external, 'verify_ota',
                side_effect=subprocess.CalledProcessError(1, ['avbroot', 'ota', 'verify']),
            ) as verify,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            patch_script._verify_outputs_after_source_care_map_exception(
                self._args(), self.key, self.root,
            )
        verify.assert_called_once_with(self.primary, self.expected_key, self.cert)

    def test_duplicate_care_maps_are_rejected_before_verification(self) -> None:
        self._write_zip(self.primary)
        with zipfile.ZipFile(self.primary, 'a') as archive:
            archive.writestr('care_map.pb', b'second-copy')
        with (
            mock.patch.object(
                external, 'encode_output_avb_public_key',
                side_effect=self._encode_fixture,
            ),
            mock.patch.object(external, 'verify_ota') as verify,
            self.assertRaisesRegex(RuntimeError, 'unique, nonempty'),
        ):
            patch_script._verify_outputs_after_source_care_map_exception(
                self._args(), self.key, self.root,
            )
        verify.assert_not_called()

    def test_secondary_verification_failure_precedes_any_sidecars(self) -> None:
        args = self._args(paired=True)
        args.input = self.root / 'original.zip'
        args.verify_public_key_avb = self.root / 'original-pkmd.bin'
        args.verify_cert_ota = self.root / 'original-ota.crt'
        args.sign_key_avb = self.key.key
        args.sign_key_ota = self.root / 'output-ota.key'
        args.pass_avb_env_var = 'AVB_PASS'
        args.pass_ota_env_var = None
        args.pass_avb_file = None
        args.pass_ota_file = None
        args.skip_custota_tool = True
        args.compatible_sepolicy = False
        args.allow_source_care_map_mismatch = True

        def patch_outputs(*unused) -> None:
            self._write_zip(self.primary)
            self._write_zip(self.secondary)

        def verify_ota(ota, *_args, **_kwargs) -> bool:
            if ota == self.secondary:
                raise subprocess.CalledProcessError(1, ['avbroot', 'ota', 'verify'])
            return ota == args.input

        with (
            mock.patch.object(patch_script.modules, 'all_modules', return_value=[]),
            mock.patch.object(patch_script, '_patch_ota_outputs',
                              side_effect=patch_outputs) as patch_outputs_call,
            mock.patch.object(external, 'verify_ota',
                              side_effect=verify_ota) as verify,
            mock.patch.object(external, 'encode_output_avb_public_key',
                              side_effect=self._encode_fixture),
            mock.patch.object(
                patch_script.care_map_compat, 'verify_fingerprint_identity_preserved'
            ) as fingerprint_guard,
            mock.patch.object(external, 'generate_csig') as csig,
            mock.patch.object(external, 'generate_update_info') as metadata,
            mock.patch.object(patch_script, 'write_patch_report') as report,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            patch_script._run(args, self.root, None, ())

        patch_outputs_call.assert_called_once()
        self.assertEqual(3, verify.call_count)  # source, primary, secondary
        fingerprint_guard.assert_called_once_with(args.input, self.primary)
        csig.assert_not_called()
        metadata.assert_not_called()
        report.assert_not_called()

    def test_secondary_identity_drift_blocks_sidecars_and_report(self) -> None:
        args = self._args(paired=True)
        args.verify_public_key_avb = self.root / 'source-pkmd.bin'
        args.verify_cert_ota = self.root / 'source-ota.crt'
        args.sign_key_avb = self.key.key
        args.sign_key_ota = self.root / 'output-ota.key'
        args.pass_avb_env_var = 'AVB_PASS'
        args.pass_ota_env_var = None
        args.pass_avb_file = None
        args.pass_ota_file = None
        args.skip_custota_tool = False
        args.compatible_sepolicy = False
        args.allow_source_care_map_mismatch = True

        def patch_outputs(*unused) -> None:
            self._write_zip(self.primary)
            self._write_zip(self.secondary)

        def check_identity(source: Path, output: Path) -> None:
            self.assertEqual(args.input, source)
            if output == self.secondary:
                raise RuntimeError('regenerated care_map.pb changes runtime fingerprint')

        with (
            mock.patch.object(patch_script.modules, 'all_modules', return_value=[]),
            mock.patch.object(patch_script, '_patch_ota_outputs',
                              side_effect=patch_outputs) as patch_outputs_call,
            mock.patch.object(external, 'verify_ota',
                              side_effect=lambda ota, *_a, **_k: ota == args.input) as verify,
            mock.patch.object(external, 'encode_output_avb_public_key',
                              side_effect=self._encode_fixture),
            mock.patch.object(
                patch_script.care_map_compat, 'verify_fingerprint_identity_preserved',
                side_effect=check_identity,
            ) as fingerprint_guard,
            mock.patch.object(external, 'generate_csig') as csig,
            mock.patch.object(external, 'generate_update_info') as metadata,
            mock.patch.object(patch_script, 'write_patch_report') as report,
            self.assertRaisesRegex(RuntimeError, 'runtime fingerprint'),
        ):
            patch_script._run(args, self.root, None, ())

        patch_outputs_call.assert_called_once()
        self.assertEqual(3, verify.call_count)
        self.assertEqual([
            mock.call(args.input, self.primary),
            mock.call(args.input, self.secondary),
        ], fingerprint_guard.call_args_list)
        csig.assert_not_called()
        metadata.assert_not_called()
        report.assert_not_called()

    def test_output_key_encoding_uses_signing_passphrase_and_no_shell(self) -> None:
        with (
            mock.patch.object(external, '_run_command',
                              side_effect=lambda args: self.expected_key.write_bytes(b'pkmd')) as run,
        ):
            external.encode_output_avb_public_key(self.key, self.expected_key)
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ['avbroot', 'key', 'encode-avb'])
        self.assertEqual(command[command.index('--key') + 1], self.key.key)
        self.assertEqual(command[command.index('--output') + 1], self.expected_key)
        self.assertEqual(command[command.index('--pass-env-var') + 1], 'AVB_PASS')

    def test_missing_derived_key_fails_closed(self) -> None:
        with (
            mock.patch.object(external, '_run_command'),
            self.assertRaisesRegex(RuntimeError, 'nonempty output AVB public key'),
        ):
            external.encode_output_avb_public_key(self.key, self.expected_key)


if __name__ == '__main__':
    unittest.main()
