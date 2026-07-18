# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Static, data-only registry of trusted internal module adapters."""

import dataclasses
from importlib import import_module
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lib.modules import LegacyCliModule


MODULE_ID_PATTERN = re.compile(r'^[a-z][a-z0-9-]*$')

SSH_SIGNER_CHENXIAOLONG = \
    'ssh-ed25519-sha256:Ct0HoRyrFLrnF9W+A/BKEiJmwx7yWkgaW/JvghKrboA'


@dataclasses.dataclass(frozen=True)
class AdapterRegistration:
    id: str
    constructor_module: str
    constructor_name: str
    verification_schemes: tuple[str, ...]
    trusted_signers: tuple[str, ...]
    digest_required: bool


def _chenxiaolong_adapter(
    id: str,
    constructor_name: str,
) -> AdapterRegistration:
    return AdapterRegistration(
        id=id,
        constructor_module=f'lib.modules.{id}',
        constructor_name=constructor_name,
        verification_schemes=('ssh-signature',),
        trusted_signers=(SSH_SIGNER_CHENXIAOLONG,),
        digest_required=False,
    )


# Order is public CLI compatibility. These identifiers are opaque and cannot
# name Python modules or objects.
INTERNAL_ADAPTERS = (
    _chenxiaolong_adapter('alterinstaller', 'AlterInstallerModule'),
    _chenxiaolong_adapter('bcr', 'BCRModule'),
    _chenxiaolong_adapter('custota', 'CustotaModule'),
    _chenxiaolong_adapter('msd', 'MSDModule'),
    _chenxiaolong_adapter('oemunlockonboot', 'OEMUnlockOnBootModule'),
)


def legacy_cli_module_types() -> tuple[type['LegacyCliModule'], ...]:
    """Resolve only the statically reviewed legacy CLI module classes."""
    from lib.modules import LegacyCliModule

    result: list[type[LegacyCliModule]] = []
    seen: set[str] = set()
    for registration in INTERNAL_ADAPTERS:
        if not MODULE_ID_PATTERN.fullmatch(registration.id):
            raise RuntimeError(f'Invalid internal module ID: {registration.id!r}')
        if registration.id in seen:
            raise RuntimeError(
                f'Duplicate internal module ID: {registration.id!r}'
            )
        seen.add(registration.id)

        adapter_module = import_module(registration.constructor_module)
        constructor = getattr(adapter_module, registration.constructor_name, None)
        if (
            not isinstance(constructor, type)
            or not issubclass(constructor, LegacyCliModule)
            or constructor.NAME != registration.id
        ):
            raise RuntimeError(
                f'Invalid legacy CLI module constructor: '
                f'{registration.constructor_module}.'
                f'{registration.constructor_name}'
            )
        result.append(constructor)

    return tuple(result)


def module_argument_dest(module_id: str) -> str:
    if not MODULE_ID_PATTERN.fullmatch(module_id):
        raise ValueError(f'Invalid module ID: {module_id!r}')
    dest_id = module_id.replace('-', '_')
    return f'module_{dest_id}'


def module_signature_argument_dest(module_id: str) -> str:
    return f'{module_argument_dest(module_id)}_sig'
