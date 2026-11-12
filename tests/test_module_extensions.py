# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

import tomlkit

from lib.modules.extensions import load_adapter_extension
from lib.modules.locks import write_lock
from lib.modules.verified import construct_locked_adapters
from tests.test_resolver import lock_for, module, profile


class AdapterExtensionIntegrationTest(unittest.TestCase):
    def test_real_module_tool_resolution_and_locked_construction(self) -> None:
        source = '''
from lib.modules import Module, ModuleRequirements
class FixtureAdapter(Module):
    def __init__(self, context): self.context = context
    def requirements(self): return ModuleRequirements(set(), set(), False)
    def inject(self, boot_fs, ext_fs, sepolicies, compatible_sepolicy=False): return None
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_dir = root / 'manifests'
            manifest_dir.mkdir()
            source_path = root / 'adapter.py'
            source_path.write_text(source, encoding='UTF-8')
            digest = hashlib.sha256(source_path.read_bytes()).hexdigest()

            manifest = module('extension-fixture').model_dump(mode='json')
            def without_none(value):
                if isinstance(value, dict):
                    return {key: without_none(item) for key, item in value.items() if item is not None}
                if isinstance(value, list):
                    return [without_none(item) for item in value]
                return value
            manifest = without_none(manifest)
            manifest['verification'] = {
                'schemes': ['sha256'],
                'trust_roots': [],
                'digest_required': True,
                'enforced_by': 'adapter',
            }
            (manifest_dir / 'extension-fixture.toml').write_text(
                tomlkit.dumps(manifest), encoding='UTF-8'
            )
            extension_path = root / 'extension.toml'
            extension_path.write_text(
                f'''schema_version = 1
catalog_directories = ['manifests']

[[adapters]]
id = 'extension-fixture'
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
            lock_path = root / 'lock.json'
            write_lock(lock_path, lock_for('extension-fixture'))
            profile_path = root / 'profile.toml'
            profile_path.write_text(
                tomlkit.dumps(profile('extension-fixture').model_dump(mode='json')),
                encoding='UTF-8',
            )

            helper_root = Path(__file__).resolve().parents[1]
            result = subprocess.run(
                [
                    sys.executable,
                    str(helper_root / 'module-tool.py'),
                    'resolve',
                    '--profile', str(profile_path),
                    '--lock', str(lock_path),
                    '--adapter-extension', str(extension_path),
                    '--format', 'json',
                ],
                cwd=helper_root,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn('extension-fixture', result.stdout)

            extension = load_adapter_extension(extension_path)
            selection = type('Selection', (), {
                'contexts': [type('Context', (), {'module_id': 'extension-fixture'})()]
            })()
            constructed = construct_locked_adapters(
                selection,
                extension.locked_factories,
            )
            self.assertEqual('extension-fixture', constructed[0][1].context.module_id)

    def test_catalog_legacy_factory_is_wrapped_for_locked_context(self) -> None:
        source = '''
from lib.modules import LegacyCliModule, MissingArgs, ModuleRequirements
def _module_class():
    class ExistingAdapter(LegacyCliModule):
        NAME = 'shizuku-fixture'
        @classmethod
        def add_args(cls, parser): pass
        @classmethod
        def from_args(cls, args):
            if getattr(args, 'module_shizuku_fixture', None) is None:
                raise MissingArgs()
            return cls()
        def requirements(self): return ModuleRequirements(set(), set(), False)
        def inject(self, boot_fs, ext_fs, sepolicies, compatible_sepolicy=False): return 'injected'
    return ExistingAdapter
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
id = 'shizuku-fixture'
kind = 'catalog-legacy'
source = 'adapter.py'
sha256 = '{digest}'
target = '_module_class'
verification_schemes = ['sha256']
trusted_signers = []
digest_required = true
''',
                encoding='UTF-8',
            )
            extension = load_adapter_extension(extension_path)
            adapter = extension.locked_factories['shizuku-fixture'](
                SimpleNamespace(module_id='shizuku-fixture')
            )
            self.assertEqual('injected', adapter.inject({}, {}, []))
            self.assertEqual('shizuku-fixture', extension.legacy_modules[0].NAME)


if __name__ == '__main__':
    unittest.main()
