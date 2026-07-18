# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Deterministic, atomic reports for the locked patch boundary."""

import dataclasses
import json
import os
from pathlib import Path, PurePosixPath
import tempfile

from lib.modules.verified import VerifiedSelection


@dataclasses.dataclass(frozen=True)
class AdapterPatchResult:
    injected_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if len(self.injected_paths) != len(set(self.injected_paths)):
            raise ValueError('locked adapter reported duplicate injected paths')
        if tuple(sorted(self.injected_paths)) != self.injected_paths:
            raise ValueError('injected paths must use canonical order')
        for value in self.injected_paths:
            path = PurePosixPath(value)
            contains_control = any(
                ord(character) < 0x20 or ord(character) == 0x7f
                for character in value
            )
            if (
                not value.startswith('/')
                or value == '/'
                or value.startswith('//')
                or '\\' in value
                or contains_control
                or path.as_posix() != value
                or any(part in ('', '.', '..') for part in path.parts[1:])
            ):
                raise ValueError(f'invalid injected Android path: {value!r}')


def build_patch_report(
    selection: VerifiedSelection,
    results: tuple[tuple[str, AdapterPatchResult], ...],
) -> dict[str, object]:
    result_by_module = {module_id: result for module_id, result in results}
    if len(result_by_module) != len(results):
        raise ValueError('duplicate locked adapter result')
    if set(result_by_module) != set(selection.resolution.selected_modules):
        raise ValueError('locked adapter results do not match the resolution')

    artifacts: list[dict[str, object]] = []
    signers: list[dict[str, str]] = []
    injected_paths: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for context in selection.contexts:
        for signer_type, value in context.trusted_signers:
            signers.append({
                'module': context.module_id,
                'type': signer_type,
                'value': value,
            })
        for artifact in context.artifacts:
            artifacts.append({
                'module': context.module_id,
                'artifact': artifact.id,
                'kind': artifact.kind,
                'role': artifact.role,
                'version': artifact.version,
                'size': artifact.size,
                'sha256': artifact.sha256,
                'license': artifact.license,
                'allowed_output_scopes': list(artifact.allowed_output_scopes),
            })
            if artifact.apk_signer_sha256 is not None:
                signers.append({
                    'module': context.module_id,
                    'artifact': artifact.id,
                    'type': 'apk-signer-sha256',
                    'value': artifact.apk_signer_sha256,
                })
            for member, signer in artifact.archive_apk_signers:
                signers.append({
                    'module': context.module_id,
                    'artifact': artifact.id,
                    'member': member,
                    'type': 'apk-signer-sha256',
                    'value': signer,
                })
        for warning in context.decision.warnings:
            warnings.append({'module': context.module_id, **warning})
        for path in result_by_module[context.module_id].injected_paths:
            if path in seen_paths:
                raise ValueError(
                    f'multiple locked adapters injected the same path: {path}'
                )
            seen_paths.add(path)
            injected_paths.append({'module': context.module_id, 'path': path})

    resolution = selection.resolution
    return {
        'schema_version': 1,
        'profile': resolution.profile.id,
        'rom_family': resolution.profile.rom_family,
        'output_scope_policy': resolution.profile.output_scope,
        'lock_sha256': resolution.lock_sha256,
        'selection_fingerprint': resolution.fingerprint,
        'selected_modules': list(resolution.selected_modules),
        'artifacts': artifacts,
        'signers': signers,
        'compatibility_decisions': [
            decision.model_dump(mode='json')
            for decision in resolution.decisions
        ],
        'warnings': warnings,
        'injected_paths': injected_paths,
    }


def write_patch_report(path: Path, report: dict[str, object]) -> None:
    """Write canonical JSON using fsync plus same-directory atomic rename."""

    data = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('UTF-8')
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f'.{path.name}.',
        suffix='.tmp',
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
