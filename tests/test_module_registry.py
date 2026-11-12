# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

import argparse
from contextlib import redirect_stdout
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from lib import modules
from lib.modules.alterinstaller import AlterInstallerModule
from lib.modules.bcr import BCRModule
from lib.modules.custota import CustotaModule
from lib.modules.fdroid_privileged_extension import (
    FDroidPrivilegedExtensionModule,
)
from lib.modules.microg import MicroGModule
from lib.modules.msd import MSDModule
from lib.modules.oemunlockonboot import OEMUnlockOnBootModule
from lib.modules.registry import (
    AdapterRegistration,
    LOCKED_ADAPTERS,
    locked_adapter_factories,
    module_argument_dest,
)
import patch as patch_script
from lib.modules.extensions import ExtensionError, load_adapter_extension
from lib.modules.verified import construct_locked_adapters


EXPECTED_MODULES = [
    'alterinstaller',
    'bcr',
    'custota',
    'msd',
    'oemunlockonboot',
]
EXPECTED_CONSTRUCTORS = [
    AlterInstallerModule,
    BCRModule,
    CustotaModule,
    MSDModule,
    OEMUnlockOnBootModule,
]


class ModuleRegistryTest(unittest.TestCase):
    def tearDown(self) -> None:
        modules.all_modules.cache_clear()

    def test_locked_registry_is_separate_from_legacy_modules(self) -> None:
        self.assertEqual(
            ['fdroid-privileged-extension', 'microg'],
            [registration.id for registration in LOCKED_ADAPTERS],
        )
        self.assertEqual(
            {
                'fdroid-privileged-extension': FDroidPrivilegedExtensionModule,
                'microg': MicroGModule,
            },
            locked_adapter_factories(),
        )

    def test_locked_registry_rejects_callable_that_is_not_module_class(self) -> None:
        registration = AdapterRegistration(
            id='locked-test',
            constructor_module='lib.modules.locked-test',
            constructor_name='constructor',
            verification_schemes=('sha256',),
            trusted_signers=(),
            digest_required=True,
        )
        fake_module = mock.Mock()
        fake_module.constructor = mock.Mock(return_value=object())

        with (
            mock.patch(
                'lib.modules.registry.import_module',
                return_value=fake_module,
            ),
            self.assertRaisesRegex(RuntimeError, 'Invalid locked module constructor'),
        ):
            locked_adapter_factories((registration,))

        fake_module.constructor.assert_not_called()

    def test_exact_legacy_registry_order(self) -> None:
        registry = modules.all_modules()
        self.assertEqual(EXPECTED_MODULES, [module.NAME for module in registry])
        self.assertEqual(EXPECTED_CONSTRUCTORS, registry)

    def test_exact_legacy_cli_order(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, str(repository_root / 'patch.py'), '--help'],
            check=True,
            capture_output=True,
            text=True,
            cwd=repository_root,
        )

        positions = []
        for name in EXPECTED_MODULES:
            module_option = f'--module-{name} '
            signature_option = f'--module-{name}-sig '
            module_position = result.stdout.index(module_option)
            signature_position = result.stdout.index(signature_option)
            self.assertLess(module_position, signature_position)
            positions.extend([module_position, signature_position])

        self.assertEqual(sorted(positions), positions)

    def test_legacy_help_ignores_corrupt_locked_only_catalog(self) -> None:
        modules.all_modules.cache_clear()
        output = io.StringIO()
        with (
            mock.patch(
                'lib.modules.catalog.load_catalog',
                side_effect=RuntimeError('corrupt locked-only manifest'),
            ) as load,
            mock.patch.object(sys, 'argv', ['patch.py', '--help']),
            redirect_stdout(output),
            self.assertRaises(SystemExit) as raised,
        ):
            patch_script.parse_args()

        self.assertEqual(0, raised.exception.code)
        self.assertIn('--module-bcr', output.getvalue())
        load.assert_not_called()

    def test_hyphenated_locked_id_has_a_safe_destination(self) -> None:
        self.assertEqual('module_test_module', module_argument_dest('test-module'))

    def test_explicit_extension_constructs_locked_adapter_without_registry_mutation(self) -> None:
        source = '''
from lib.modules import Module, ModuleRequirements
class FixtureAdapter(Module):
    def __init__(self, context): self.context = context
    def requirements(self): return ModuleRequirements(set(), set(), False)
    def inject(self, boot_fs, ext_fs, sepolicies, compatible_sepolicy=False): return None
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter_path = root / 'adapter.py'
            adapter_path.write_text(source, encoding='UTF-8')
            digest = hashlib.sha256(adapter_path.read_bytes()).hexdigest()
            extension_path = root / 'extension.toml'
            extension_path.write_text(
                f'''schema_version = 1
catalog_directories = []

[[adapters]]
id = 'fixture-adapter'
kind = 'locked'
source = 'adapter.py'
sha256 = '{digest}'
target = 'FixtureAdapter'
verification_schemes = ['sha256']
trusted_signers = []
digest_required = true
''',
                encoding='UTF-8',
            )
            extension = load_adapter_extension(extension_path)
            self.assertIsNotNone(extension)
            self.assertEqual(EXPECTED_MODULES, [module.NAME for module in modules.all_modules()])
            selection = mock.Mock()
            selection.contexts = [mock.Mock(module_id='fixture-adapter')]
            built = construct_locked_adapters(selection, extension.locked_factories)
            self.assertEqual(['fixture-adapter'], [module_id for module_id, _ in built])
            self.assertEqual('fixture-adapter', built[0][1].context.module_id)

    def test_extension_hash_fails_before_module_code_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / 'imported'
            source_path = root / 'adapter.py'
            source_path.write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).touch()\n",
                encoding='UTF-8',
            )
            extension_path = root / 'extension.toml'
            extension_path.write_text(
                '''schema_version = 1
catalog_directories = []
[[adapters]]
id = 'fixture-adapter'
kind = 'locked'
source = 'adapter.py'
sha256 = '0000000000000000000000000000000000000000000000000000000000000000'
target = 'FixtureAdapter'
verification_schemes = ['sha256']
trusted_signers = []
digest_required = true
''',
                encoding='UTF-8',
            )
            with self.assertRaisesRegex(ExtensionError, 'digest mismatch'):
                load_adapter_extension(extension_path)
            self.assertFalse(marker.exists())

    def test_legacy_extension_factory_adds_only_explicit_consumer_arguments(self) -> None:
        source = '''
def _module_class():
    import argparse
    from lib.modules import LegacyCliModule, MissingArgs, ModuleRequirements
    class ConsumerModule(LegacyCliModule):
        NAME = 'consumer-fixture'
        @classmethod
        def add_args(cls, parser): parser.add_argument('--module-consumer-fixture')
        @classmethod
        def from_args(cls, args): raise MissingArgs()
        def requirements(self): return ModuleRequirements(set(), set(), False)
        def inject(self, boot_fs, ext_fs, sepolicies, compatible_sepolicy=False): return None
    return ConsumerModule
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / 'adapter.py'
            source_path.write_text(source, encoding='UTF-8')
            digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
            extension_path = root / 'extension.toml'
            extension_path.write_text(
                f'''schema_version = 1
catalog_directories = []
[[adapters]]
id = 'consumer-fixture'
kind = 'legacy-cli'
source = 'adapter.py'
sha256 = '{digest}'
target = '_module_class'
verification_schemes = ['sha256']
trusted_signers = []
digest_required = true
''',
                encoding='UTF-8',
            )
            output = io.StringIO()
            with (
                mock.patch.object(sys, 'argv', [
                    'patch.py', '--adapter-extension', str(extension_path), '--help'
                ]),
                redirect_stdout(output),
                self.assertRaises(SystemExit) as raised,
            ):
                patch_script.parse_args()
            self.assertEqual(0, raised.exception.code)
            self.assertIn('--module-consumer-fixture', output.getvalue())
            self.assertEqual(EXPECTED_MODULES, [module.NAME for module in modules.all_modules()])

    def test_legacy_signature_defaults_to_zip_dot_sig(self) -> None:
        args = argparse.Namespace(
            module_bcr=Path('BCR-release.zip'),
            module_bcr_sig=None,
        )
        with mock.patch.object(modules, 'verify_ssh_sig') as verify:
            module = BCRModule.from_args(args)

        self.assertEqual(Path('BCR-release.zip'), module.zip)
        verify.assert_called_once_with(
            Path('BCR-release.zip'),
            Path('BCR-release.zip.sig'),
            modules.SSH_PUBLIC_KEY_CHENXIAOLONG,
        )

    def test_native_release_url_reaches_update_info_generator(self) -> None:
        output = Path('/fixture-output.zip')
        with (
            mock.patch.object(
                patch_script,
                'get_ota_metadata',
                return_value={'pre-device': 'fixture'},
            ),
            mock.patch.object(patch_script.external, 'generate_update_info') as generate,
        ):
            patch_script._generate_update_info(
                output,
                'https://downloads.example/release.zip',
            )
        generate.assert_called_once_with(
            Path('/fixture.json'),
            'https://downloads.example/release.zip',
        )


if __name__ == '__main__':
    unittest.main()
