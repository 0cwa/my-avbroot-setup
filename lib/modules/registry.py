# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Static, data-only registry of trusted internal module adapters."""

import dataclasses
import re


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


def module_argument_dest(module_id: str) -> str:
    if not MODULE_ID_PATTERN.fullmatch(module_id):
        raise ValueError(f'Invalid module ID: {module_id!r}')
    dest_id = module_id.replace('-', '_')
    return f'module_{dest_id}'


def module_signature_argument_dest(module_id: str) -> str:
    return f'{module_argument_dest(module_id)}_sig'
