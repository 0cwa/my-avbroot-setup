# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from lib.modules.catalog import CatalogError, load_catalog
from lib.modules.registry import AdapterRegistration


MANIFEST = """
schema_version = 1
id = '{id}'
name = '{name}'
status = 'supported'
adapter = '{adapter}'
default_enabled = false
artifact_kinds = ['native-image-module-zip']
dependencies = []
conflicts = []
warnings = []
reasons = []

[verification]
schemes = ['ssh-signature']
trusted_signers = ['test-signer']
digest_required = false
enforced_by = 'adapter'

[compatibility]
rom_families = ['unknown']
root_modes = ['unknown']
architectures = ['unknown']
"""


def registration(id: str) -> AdapterRegistration:
    return AdapterRegistration(
        id=id,
        constructor_module=f'lib.modules.{id}',
        constructor_name=f'{id.title()}Module',
        verification_schemes=('ssh-signature',),
        trusted_signers=('test-signer',),
        digest_required=False,
    )


class ModuleCatalogTest(unittest.TestCase):
    def write_manifest(
        self,
        directory: Path,
        filename: str,
        *,
        id: str,
        adapter: str,
        name: str | None = None,
    ) -> None:
        content = MANIFEST.format(
            id=id,
            adapter=adapter,
            name=name or id,
        )
        (directory / filename).write_text(
            textwrap.dedent(content),
            encoding='UTF-8',
        )

    def test_catalog_is_ordered_by_canonical_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'zeta.toml', id='zeta', adapter='zeta'
            )
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )

            catalog = load_catalog(
                directory,
                registrations=(registration('alpha'), registration('zeta')),
            )

            self.assertEqual(['alpha', 'zeta'], [m.id for m in catalog.modules])

    def test_duplicate_ids_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            self.write_manifest(
                directory, 'zeta.toml', id='alpha', adapter='alpha'
            )

            with self.assertRaisesRegex(CatalogError, 'Duplicate module ID'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_unknown_adapter_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='arbitrary-import'
            )

            with self.assertRaisesRegex(CatalogError, 'unknown adapter'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_invalid_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='Alpha', adapter='alpha'
            )

            with self.assertRaisesRegex(CatalogError, 'Invalid module manifest'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_json_is_stable_and_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            catalog = load_catalog(
                directory,
                registrations=(registration('alpha'),),
            )

            first = catalog.as_json()
            second = load_catalog(
                directory,
                registrations=(registration('alpha'),),
            ).as_json()

            self.assertEqual(first, second)
            self.assertTrue(first.endswith('\n'))
            self.assertEqual('alpha', json.loads(first)['modules'][0]['id'])

    def test_text_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            catalog = load_catalog(
                directory,
                registrations=(registration('alpha'),),
            )

            self.assertEqual(
                'ID\tSTATUS\tDEFAULT\tARTIFACT KINDS\n'
                'alpha\tsupported\tno\tnative-image-module-zip\n',
                catalog.as_text(),
            )

    def test_missing_supported_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )

            with self.assertRaisesRegex(CatalogError, 'Missing supported'):
                load_catalog(
                    directory,
                    registrations=(registration('alpha'), registration('zeta')),
                )

    def test_renamed_legacy_adapter_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'renamed.toml', id='renamed', adapter='alpha'
            )

            with self.assertRaisesRegex(CatalogError, 'must match its adapter'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_duplicate_adapter_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            self.write_manifest(
                directory, 'zeta.toml', id='zeta', adapter='alpha'
            )

            with self.assertRaisesRegex(CatalogError, 'Duplicate module adapter'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_duplicate_internal_registration_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )

            with self.assertRaisesRegex(CatalogError, 'Duplicate internal adapter'):
                load_catalog(
                    directory,
                    registrations=(registration('alpha'), registration('alpha')),
                )

    def test_strict_scalar_validation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    'default_enabled = false',
                    "default_enabled = 'false'",
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'Invalid module manifest'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_blank_signer_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    "trusted_signers = ['test-signer']",
                    "trusted_signers = ['   ']",
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'Invalid module manifest'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_unknown_must_be_sole_compatibility_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    "rom_families = ['unknown']",
                    "rom_families = ['unknown', 'lineageos']",
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'Invalid module manifest'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_verification_expectation_must_match_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    "trusted_signers = ['test-signer']",
                    "trusted_signers = ['different-signer']",
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'verification expectation'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_standalone_catalog_does_not_import_adapter_modules(self) -> None:
        code = """
import sys
from lib.modules.catalog import load_catalog

load_catalog()
loaded = sorted(
    name for name in sys.modules
    if name in {
        'lib.modules.alterinstaller',
        'lib.modules.bcr',
        'lib.modules.custota',
        'lib.modules.msd',
        'lib.modules.oemunlockonboot',
    }
)
if loaded:
    raise SystemExit(f'Adapter modules imported during listing: {loaded}')
"""
        subprocess.run([sys.executable, '-c', code], check=True)


if __name__ == '__main__':
    unittest.main()
