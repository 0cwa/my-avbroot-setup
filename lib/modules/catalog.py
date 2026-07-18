# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Declarative catalog for image-native patch modules.

Catalog loading is intentionally data-only. Adapter identifiers are resolved by
``lib.modules.all_modules()`` through a static internal registry; manifests can
never name an arbitrary Python object to import.
"""

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import re
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StringConstraints,
    field_validator,
    model_validator,
)
import tomlkit

from lib.modules.registry import (
    AdapterRegistration,
    INTERNAL_ADAPTERS,
    MODULE_ID_PATTERN,
)


COMPATIBILITY_TOKEN_PATTERN = re.compile(r'^[a-z][a-z0-9_-]*$')
MANIFESTS_DIR = Path(__file__).with_name('manifests')
StrictString = Annotated[str, StringConstraints(strict=True)]
NonBlankString = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, pattern=r'.*\S.*'),
]


class CatalogError(ValueError):
    """The module catalog is incomplete, ambiguous, or unsafe to load."""


class CatalogModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra='forbid',
        frozen=True,
    )


class VerificationPolicy(CatalogModel):
    schemes: tuple[
        Literal['sha256', 'ssh-signature', 'apk-signature', 'none'],
        ...,
    ] = Field(min_length=1)
    trusted_signers: tuple[NonBlankString, ...] = ()
    digest_required: StrictBool = False
    enforced_by: Literal['adapter']

    @model_validator(mode='after')
    def validate_policy(self) -> Self:
        if len(self.schemes) != len(set(self.schemes)):
            raise ValueError('verification schemes must be unique')
        if len(self.trusted_signers) != len(set(self.trusted_signers)):
            raise ValueError('trusted signers must be unique')
        if 'none' in self.schemes and len(self.schemes) != 1:
            raise ValueError('verification scheme "none" cannot be combined')
        if 'ssh-signature' in self.schemes and not self.trusted_signers:
            raise ValueError('SSH signature verification requires a trusted signer')
        if self.digest_required and 'sha256' not in self.schemes:
            raise ValueError('digest_required requires the sha256 scheme')
        return self


class Compatibility(CatalogModel):
    rom_families: tuple[StrictString, ...] = Field(min_length=1)
    root_modes: tuple[
        Literal['rootless', 'rooted', 'any', 'unknown'],
        ...,
    ] = Field(min_length=1)
    architectures: tuple[StrictString, ...] = Field(min_length=1)

    @field_validator('rom_families', 'architectures')
    @classmethod
    def validate_tokens(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if value != 'any' and not COMPATIBILITY_TOKEN_PATTERN.fullmatch(value):
                raise ValueError(f'invalid compatibility token: {value!r}')
        if len(values) != len(set(values)):
            raise ValueError('compatibility tokens must be unique')
        if ({'any', 'unknown'} & set(values)) and len(values) != 1:
            raise ValueError('any or unknown must be the sole compatibility token')
        return values

    @field_validator('root_modes')
    @classmethod
    def validate_root_modes(
        cls,
        values: tuple[Literal['rootless', 'rooted', 'any', 'unknown'], ...],
    ) -> tuple[Literal['rootless', 'rooted', 'any', 'unknown'], ...]:
        if len(values) != len(set(values)):
            raise ValueError('root modes must be unique')
        if ({'any', 'unknown'} & set(values)) and len(values) != 1:
            raise ValueError('any or unknown must be the sole compatibility token')
        return values


class Warning(CatalogModel):
    code: StrictString
    severity: Literal['info', 'warning']
    message: NonBlankString

    @field_validator('code')
    @classmethod
    def validate_code(cls, value: str) -> str:
        if not MODULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f'invalid warning code: {value!r}')
        return value


class Reason(CatalogModel):
    code: StrictString
    message: NonBlankString

    @field_validator('code')
    @classmethod
    def validate_code(cls, value: str) -> str:
        if not MODULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f'invalid reason code: {value!r}')
        return value


class ModuleSpec(CatalogModel):
    schema_version: Literal[1]
    id: StrictString
    name: NonBlankString
    status: Literal['supported', 'planned', 'incompatible']
    adapter: StrictString | None = None
    default_enabled: StrictBool = False
    artifact_kinds: tuple[
        Literal[
            'native-image-module-zip',
            'magisk-module-zip',
            'recovery-flashable-zip',
            'root-patcher-module-zip',
            'apk',
            'other',
        ],
        ...,
    ] = Field(min_length=1)
    verification: VerificationPolicy
    compatibility: Compatibility
    dependencies: tuple[StrictString, ...] = ()
    conflicts: tuple[StrictString, ...] = ()
    warnings: tuple[Warning, ...] = ()
    reasons: tuple[Reason, ...] = ()

    @field_validator('id')
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not MODULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f'invalid module ID: {value!r}')
        return value

    @field_validator('dependencies', 'conflicts')
    @classmethod
    def validate_module_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not MODULE_ID_PATTERN.fullmatch(value):
                raise ValueError(f'invalid module ID reference: {value!r}')
        if len(values) != len(set(values)):
            raise ValueError('module ID references must be unique')
        return values

    @model_validator(mode='after')
    def validate_state(self) -> Self:
        if self.status == 'supported' and self.adapter is None:
            raise ValueError('supported modules require an adapter')
        if self.status != 'supported' and self.adapter is not None:
            raise ValueError('non-supported modules cannot register an adapter')
        if self.status != 'supported' and self.default_enabled:
            raise ValueError('non-supported modules cannot be enabled by default')
        if self.status == 'supported' and 'none' in self.verification.schemes:
            raise ValueError('supported modules require artifact verification')
        if self.status == 'incompatible' and not self.reasons:
            raise ValueError('incompatible modules require a structured reason')
        if len(self.artifact_kinds) != len(set(self.artifact_kinds)):
            raise ValueError('artifact kinds must be unique')
        warning_codes = [warning.code for warning in self.warnings]
        if len(warning_codes) != len(set(warning_codes)):
            raise ValueError('warning codes must be unique')
        reason_codes = [reason.code for reason in self.reasons]
        if len(reason_codes) != len(set(reason_codes)):
            raise ValueError('reason codes must be unique')
        if self.id in self.dependencies or self.id in self.conflicts:
            raise ValueError('a module cannot depend on or conflict with itself')
        if set(self.dependencies) & set(self.conflicts):
            raise ValueError('a module dependency cannot also be a conflict')
        return self


class ModuleCatalog:
    def __init__(self, modules: Sequence[ModuleSpec]) -> None:
        self.modules = tuple(modules)

    @property
    def supported(self) -> tuple[ModuleSpec, ...]:
        return tuple(module for module in self.modules if module.status == 'supported')

    def as_dict(self) -> dict[str, object]:
        return {
            'schema_version': 1,
            'modules': [
                module.model_dump(mode='json')
                for module in self.modules
            ],
        }

    def as_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True) + '\n'

    def as_text(self) -> str:
        lines = ['ID\tSTATUS\tDEFAULT\tARTIFACT KINDS']
        for module in self.modules:
            kinds = ','.join(module.artifact_kinds)
            enabled = 'yes' if module.default_enabled else 'no'
            lines.append(f'{module.id}\t{module.status}\t{enabled}\t{kinds}')
        return '\n'.join(lines) + '\n'


def load_catalog(
    directory: Path = MANIFESTS_DIR,
    registrations: Sequence[AdapterRegistration] = INTERNAL_ADAPTERS,
) -> ModuleCatalog:
    registration_by_id: dict[str, AdapterRegistration] = {}
    for registration in registrations:
        if not MODULE_ID_PATTERN.fullmatch(registration.id):
            raise CatalogError(
                f'Invalid internal adapter registration: {registration.id!r}'
            )
        if registration.id in registration_by_id:
            raise CatalogError(
                f'Duplicate internal adapter registration: {registration.id}'
            )
        registration_by_id[registration.id] = registration

    paths = sorted(directory.glob('*.toml'), key=lambda path: path.name)
    if not paths:
        raise CatalogError(f'No module manifests found in: {directory}')

    specs: list[ModuleSpec] = []
    seen_ids: set[str] = set()
    seen_adapters: set[str] = set()

    for path in paths:
        try:
            raw = tomlkit.loads(path.read_text(encoding='UTF-8')).unwrap()
            spec = ModuleSpec.model_validate(raw)
        except Exception as e:
            raise CatalogError(f'Invalid module manifest: {path}: {e}') from e

        if spec.id in seen_ids:
            raise CatalogError(f'Duplicate module ID: {spec.id}')
        if path.stem != spec.id:
            raise CatalogError(
                f'Manifest filename must match module ID: {path.name} != {spec.id}.toml'
            )
        if spec.adapter is not None:
            if spec.adapter not in registration_by_id:
                raise CatalogError(
                    f'Module {spec.id!r} uses unknown adapter: {spec.adapter!r}'
                )
            if spec.adapter in seen_adapters:
                raise CatalogError(
                    f'Duplicate module adapter registration: {spec.adapter}'
                )
            if spec.id != spec.adapter:
                raise CatalogError(
                    f'Legacy module ID must match its adapter: '
                    f'{spec.id!r} != {spec.adapter!r}'
                )

            registration = registration_by_id[spec.adapter]
            expectation = spec.verification
            if (
                expectation.schemes != registration.verification_schemes
                or expectation.trusted_signers != registration.trusted_signers
                or expectation.digest_required != registration.digest_required
            ):
                raise CatalogError(
                    f'Module {spec.id!r} verification expectation does not '
                    f'match its internal adapter'
                )

            seen_adapters.add(spec.adapter)

        seen_ids.add(spec.id)
        specs.append(spec)

    missing_adapters = set(registration_by_id) - seen_adapters
    if missing_adapters:
        raise CatalogError(
            'Missing supported module manifests for internal adapters: '
            f'{", ".join(sorted(missing_adapters))}'
        )

    for spec in specs:
        unknown = (set(spec.dependencies) | set(spec.conflicts)) - seen_ids
        if unknown:
            raise CatalogError(
                f'Module {spec.id!r} references unknown modules: '
                f'{", ".join(sorted(unknown))}'
            )

    # IDs, not filesystem or locale ordering, define the public registry order.
    specs.sort(key=lambda spec: spec.id)
    return ModuleCatalog(specs)


def main() -> None:
    parser = argparse.ArgumentParser(description='List image patch module metadata')
    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )
    args = parser.parse_args()

    catalog = load_catalog()
    if args.format == 'json':
        print(catalog.as_json(), end='')
    else:
        print(catalog.as_text(), end='')


if __name__ == '__main__':
    main()
