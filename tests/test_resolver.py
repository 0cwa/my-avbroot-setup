# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

import hashlib
import unittest

from lib.modules.catalog import ModuleCatalog, ModuleSpec
from lib.modules.locks import ArtifactLock, ArtifactLockFile, ModuleLock
from lib.modules.resolver import (
    ResolutionError,
    ResolutionProfile,
    resolve_profile as _resolve_profile,
)


LOCK_DIGEST = 'a' * 64


def module_data(id: str) -> dict[str, object]:
    return {
        'schema_version': 2,
        'id': id,
        'name': id,
        'status': 'supported',
        'adapter': id,
        'lifecycle': 'static-image',
        'defaults': {'helper_enabled': False, 'pixene_profile_enabled': False},
        'acknowledgement_required': False,
        'artifact_kinds': ['apk'],
        'verification': {
            'schemes': ['sha256'],
            'trust_roots': [],
            'digest_required': True,
            'enforced_by': 'adapter',
        },
        'compatibility': {
            'roms': {'lineageos': {'status': 'supported'}},
            'root_modes': ['rootless'],
            'architectures': ['arm64-v8a'],
        },
        'capabilities': {
            'requires': {
                'selective_signature_spoofing': False,
                'product_priv_app': False,
                'custom_init_selinux': False,
                'abis': ['arm64-v8a'],
                'min_api': 34,
                'max_api': 36,
            },
            'provides': {
                'root': [],
                'zygisk': [],
                'selective_signature_spoing': False,
                'product_priv_app': False,
                'custom_init_selinux': False,
            },
        },
        'legal': {
            'license': 'Apache-2.0',
            'source_url': 'https://example.com/source',
            'source_offer_required': False,
            'upstream_only_fetching': True,
            'local_only': True,
            'cache_policy': 'read-write',
            'allowed_output_scopes': ['local-unpublished'],
        },
        'dependencies': [],
        'conflicts': [],
        'warnings': [],
        'reasons': [],
    }


def module(id: str, mutate=None) -> ModuleSpec:
    data = module_data(id)
    # Correct spelling kept here so accidental extra catalog keys fail tests.
    data['capabilities']['provides']['selective_signature_spoofing'] = (
        data['capabilities']['provides'].pop('selective_signature_spoing')
    )
    if mutate:
        mutate(data)
    return ModuleSpec.model_validate(data)


def profile(*modules: str, **updates) -> ResolutionProfile:
    data = {
        'schema_version': 1,
        'id': 'lineage-fixture',
        'rom_family': 'lineageos',
        'root_mode': 'rootless',
        'abi': 'arm64-v8a',
        'api_level': 35,
        'output_scope': 'local-unpublished',
        'enabled_modules': list(modules),
        'capabilities': {
            'root_providers': [],
            'zygisk_providers': [],
            'selective_signature_spoofing': False,
            'product_priv_app': False,
            'custom_init_selinux': False,
        },
        'acknowledgements': [],
    }
    data.update(updates)
    return ResolutionProfile.model_validate(data)


def lock_for(*module_ids: str) -> ArtifactLockFile:
    ids = tuple(sorted(set(module_ids))) or ('fixture-lock',)
    modules = []
    for module_id in ids:
        payload = module_id.encode('UTF-8')
        artifact = ArtifactLock(
            id='payload',
            kind='other',
            immutable_url=f'https://downloads.example/{module_id}/payload.bin',
            allowed_origins=('https://downloads.example',),
            version='1',
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        )
        modules.append(ModuleLock(
            id=module_id,
            version='1',
            artifacts=(artifact,),
        ))
    return ArtifactLockFile(schema_version=1, modules=tuple(modules))


def resolve_profile(
    catalog: ModuleCatalog,
    selected_profile: ResolutionProfile,
    lock: ArtifactLockFile | None = None,
    lock_sha256: str = LOCK_DIGEST,
):
    if lock is None:
        lock = lock_for(*selected_profile.enabled_modules)
    return _resolve_profile(catalog, selected_profile, lock, lock_sha256)


class ResolverTest(unittest.TestCase):
    def test_profile_tokens_are_canonical(self) -> None:
        for update in (
            {'id': 'lineage\nfixture'},
            {'rom_family': 'LineageOS'},
            {'abi': 'arm64 v8a'},
        ):
            with self.subTest(update=update), self.assertRaisesRegex(
                ValueError,
                'invalid profile token',
            ):
                profile('alpha', **update)

        with self.assertRaisesRegex(ValueError, 'Extra inputs are not permitted'):
            profile('alpha', lock_sha256=LOCK_DIGEST)

    def test_duplicate_catalog_ids_fail_closed(self) -> None:
        with self.assertRaisesRegex(ResolutionError, 'duplicate module IDs: alpha'):
            resolve_profile(
                ModuleCatalog((module('alpha'), module('alpha'))),
                profile('alpha'),
            )

    def test_resolution_is_deterministic_and_sorted(self) -> None:
        catalog = ModuleCatalog((module('zeta'), module('alpha')))
        selected = profile('zeta', 'alpha')
        first = resolve_profile(catalog, selected)
        second = resolve_profile(catalog, selected)
        self.assertEqual(('alpha', 'zeta'), first.selected_modules)
        self.assertEqual(first.as_json(), second.as_json())

    def test_fingerprint_is_canonical_and_ignores_unselected_catalog(self) -> None:
        alpha = module('alpha')
        zeta = module('zeta')
        first = resolve_profile(
            ModuleCatalog((zeta, alpha)),
            profile('zeta', 'alpha'),
        )
        second = resolve_profile(
            ModuleCatalog((alpha, module('unused'), zeta)),
            profile('alpha', 'zeta'),
        )
        self.assertEqual(first.fingerprint, second.fingerprint)

        changed_profile = resolve_profile(
            ModuleCatalog((alpha, zeta)),
            profile('alpha', 'zeta', id='another-profile'),
        )
        self.assertNotEqual(first.fingerprint, changed_profile.fingerprint)

        changed_lock = resolve_profile(
            ModuleCatalog((alpha, zeta)),
            profile('alpha', 'zeta'),
            lock_sha256='b' * 64,
        )
        self.assertNotEqual(first.fingerprint, changed_lock.fingerprint)

    def test_selected_modules_must_exist_in_artifact_lock(self) -> None:
        with self.assertRaisesRegex(ResolutionError, 'absent from the artifact lock'):
            resolve_profile(
                ModuleCatalog((module('alpha'),)),
                profile('alpha'),
                lock_for('other'),
            )

    def test_unknown_or_incompatible_rom_fails_closed(self) -> None:
        catalog = ModuleCatalog((module('alpha'),))
        with self.assertRaisesRegex(ResolutionError, 'no known status'):
            resolve_profile(catalog, profile('alpha', rom_family='grapheneos'))

        incompatible = module(
            'alpha',
            lambda data: data['compatibility']['roms'].update({
                'lineageos': {
                    'status': 'incompatible',
                    'reason': {'code': 'not-supported', 'message': 'No.'},
                }
            }),
        )
        with self.assertRaisesRegex(ResolutionError, 'incompatible'):
            resolve_profile(ModuleCatalog((incompatible,)), profile('alpha'))

        any_rom = module('alpha', lambda data: data['compatibility'].update({
            'roms': {'any': {'status': 'supported'}},
        }))
        with self.assertRaisesRegex(ResolutionError, 'ROM family is unknown'):
            resolve_profile(
                ModuleCatalog((any_rom,)),
                profile('alpha', rom_family='unknown'),
            )

    def test_experimental_rom_is_reported_with_reason(self) -> None:
        experimental = module(
            'alpha',
            lambda data: data['compatibility']['roms'].update({
                'lineageos': {
                    'status': 'experimental',
                    'reason': {
                        'code': 'testing-pending',
                        'message': 'Tests pending.',
                    },
                }
            }),
        )
        result = resolve_profile(ModuleCatalog((experimental,)), profile('alpha'))
        self.assertEqual('experimental', result.decisions[0].rom_status)
        self.assertEqual('testing-pending', result.decisions[0].reason['code'])

    def test_missing_dependency_and_symmetric_conflict_fail(self) -> None:
        alpha = module('alpha', lambda data: data.update({'dependencies': ['beta']}))
        beta = module('beta')
        with self.assertRaisesRegex(ResolutionError, 'unselected dependencies'):
            resolve_profile(ModuleCatalog((alpha, beta)), profile('alpha'))

        alpha = module('alpha', lambda data: data.update({'conflicts': ['beta']}))
        with self.assertRaisesRegex(ResolutionError, 'conflicts'):
            resolve_profile(ModuleCatalog((alpha, beta)), profile('alpha', 'beta'))

        # Conflict declarations are symmetric at resolution time even if the
        # selected module encountered first does not declare the conflict.
        beta = module('beta', lambda data: data.update({'conflicts': ['alpha']}))
        with self.assertRaisesRegex(ResolutionError, 'alpha conflicts with.*beta'):
            resolve_profile(
                ModuleCatalog((beta, module('alpha'))),
                profile('beta', 'alpha'),
            )

    def test_dependency_cycle_fails_closed(self) -> None:
        alpha = module('alpha', lambda data: data.update({'dependencies': ['beta']}))
        beta = module('beta', lambda data: data.update({'dependencies': ['alpha']}))
        with self.assertRaisesRegex(
            ResolutionError,
            r'dependency cycle: alpha -> beta -> alpha',
        ):
            resolve_profile(ModuleCatalog((alpha, beta)), profile('alpha', 'beta'))

    def test_unknown_capabilities_and_provider_ambiguity_fail(self) -> None:
        unknown = module('alpha', lambda data: data['capabilities']['requires'].update({
            'abis': ['unknown']
        }))
        with self.assertRaisesRegex(ResolutionError, 'unknown ABI'):
            resolve_profile(ModuleCatalog((unknown,)), profile('alpha'))

        any_abi = module('alpha', lambda data: data['capabilities']['requires'].update({
            'abis': ['any']
        }))
        with self.assertRaisesRegex(ResolutionError, 'ABI capability is unknown'):
            resolve_profile(
                ModuleCatalog((any_abi,)),
                profile('alpha', abi='unknown'),
            )

        any_root = module(
            'alpha',
            lambda data: data['capabilities']['requires'].update({
                'root_provider': 'any'
            }),
        )
        ambiguous = profile('alpha', capabilities={
            'root_providers': ['magisk', 'kernelsu'],
            'zygisk_providers': [],
            'selective_signature_spoofing': False,
            'product_priv_app': False,
            'custom_init_selinux': False,
        })
        with self.assertRaisesRegex(ResolutionError, 'ambiguous'):
            resolve_profile(ModuleCatalog((any_root,)), ambiguous)

        with self.assertRaisesRegex(ResolutionError, 'ambiguous'):
            resolve_profile(ModuleCatalog((any_root,)), profile('alpha'))

    def test_selected_dependencies_provide_capabilities_but_not_other_modules(self) -> None:
        consumer = module(
            'consumer',
            lambda data: (
                data.update({'dependencies': ['provider']}),
                data['capabilities']['requires'].update({
                    'product_priv_app': True,
                }),
            ),
        )
        provider = module(
            'provider',
            lambda data: data['capabilities']['provides'].update({
                'product_priv_app': True,
            }),
        )
        result = resolve_profile(
            ModuleCatalog((consumer, provider)),
            profile('consumer', 'provider'),
        )
        self.assertEqual(('consumer', 'provider'), result.selected_modules)

        missing_edge = module(
            'consumer',
            lambda data: data['capabilities']['requires'].update({
                'product_priv_app': True,
            }),
        )
        with self.assertRaisesRegex(ResolutionError, 'product priv-app'):
            resolve_profile(
                ModuleCatalog((missing_edge, provider)),
                profile('consumer', 'provider'),
            )

        self_provider = module('self-provider', lambda data: (
            data['capabilities']['requires'].update({'product_priv_app': True}),
            data['capabilities']['provides'].update({'product_priv_app': True}),
        ))
        with self.assertRaisesRegex(ResolutionError, 'product priv-app'):
            resolve_profile(
                ModuleCatalog((self_provider,)),
                profile('self-provider'),
            )

    def test_output_scope_is_enforced(self) -> None:
        with self.assertRaisesRegex(ResolutionError, 'forbids output scope'):
            resolve_profile(
                ModuleCatalog((module('alpha'),)),
                profile('alpha', output_scope='published'),
            )

    def test_critical_acknowledgement_binds_lock_and_scope(self) -> None:
        def make_critical(data):
            data['acknowledgement_required'] = True
            data['warnings'] = [{
                'code': 'critical-risk',
                'severity': 'critical',
                'message': 'Review.',
            }]

        critical = module('alpha', make_critical)
        lock_digest = 'a' * 64
        with self.assertRaisesRegex(ResolutionError, 'lock-bound acknowledgement'):
            resolve_profile(ModuleCatalog((critical,)), profile('alpha'))

        accepted = profile(
            'alpha',
            acknowledgements=[{
                'module': 'alpha',
                'lock_sha256': lock_digest,
                'output_scope': 'local-unpublished',
            }],
        )
        self.assertEqual(
            ('alpha',),
            resolve_profile(ModuleCatalog((critical,)), accepted).selected_modules,
        )

        wrong_scope = profile(
            'alpha',
            acknowledgements=[{
                'module': 'alpha',
                'lock_sha256': lock_digest,
                'output_scope': 'private',
            }],
        )
        with self.assertRaisesRegex(ResolutionError, 'stale or wrong-scope'):
            resolve_profile(ModuleCatalog((critical,)), wrong_scope)

        wrong_lock = profile(
            'alpha',
            acknowledgements=[{
                'module': 'alpha',
                'lock_sha256': 'b' * 64,
                'output_scope': 'local-unpublished',
            }],
        )
        with self.assertRaisesRegex(ResolutionError, 'stale or wrong-scope'):
            resolve_profile(ModuleCatalog((critical,)), wrong_lock)

    def test_acknowledgements_must_bind_selected_critical_modules(self) -> None:
        lock_digest = 'b' * 64
        unused = profile(
            'alpha',
            acknowledgements=[{
                'module': 'unused',
                'lock_sha256': lock_digest,
                'output_scope': 'local-unpublished',
            }],
        )
        with self.assertRaisesRegex(ResolutionError, 'unselected modules: unused'):
            resolve_profile(ModuleCatalog((module('alpha'),)), unused)

        unnecessary = profile(
            'alpha',
            acknowledgements=[{
                'module': 'alpha',
                'lock_sha256': lock_digest,
                'output_scope': 'local-unpublished',
            }],
        )
        with self.assertRaisesRegex(ResolutionError, 'do not require'):
            resolve_profile(ModuleCatalog((module('alpha'),)), unnecessary)


if __name__ == '__main__':
    unittest.main()
