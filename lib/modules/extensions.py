# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Explicit, digest-pinned adapter extensions for local consumers.

The extension file is the trust decision. Catalogs, profiles, and locks only
refer to opaque adapter IDs and never select Python import targets.
"""

from dataclasses import dataclass
import hashlib
import importlib.util
import re
import stat
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import tomlkit

from lib.modules.registry import (
    AdapterRegistration,
    INTERNAL_ADAPTERS,
    LOCKED_ADAPTERS,
    MODULE_ID_PATTERN,
)


SHA256_PATTERN = re.compile(r'^[0-9a-f]{64}$')
EXTENSION_SCHEMA = 1


class ExtensionError(ValueError):
    """An adapter extension is malformed or fails its trust checks."""


@dataclass(frozen=True)
class AdapterExtension:
    path: Path
    catalog_directories: tuple[Path, ...]
    catalog_registrations: tuple[AdapterRegistration, ...]
    legacy_modules: tuple[type[Any], ...]
    locked_factories: dict[str, type[Any]]


def _safe_path(base: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ExtensionError(f'{label} must be a relative file path')
    relative = Path(value)
    if any(part in ('', '.', '..') for part in relative.parts):
        raise ExtensionError(f'{label} contains an unsafe path')
    candidate = base / relative
    try:
        cursor = base
        for part in relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ExtensionError(f'{label} cannot traverse a symlink')
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(base.resolve(strict=True))
        mode = candidate.lstat().st_mode
    except ExtensionError:
        raise
    except (OSError, ValueError) as error:
        raise ExtensionError(f'{label} is unavailable or escapes its directory') from error
    if stat.S_ISLNK(mode):
        raise ExtensionError(f'{label} cannot be a symlink')
    return resolved


def _load_source(path: Path, digest: object, module_key: str) -> ModuleType:
    if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
        raise ExtensionError('adapter source digest must be lowercase SHA-256')
    source = path.read_bytes()
    actual = hashlib.sha256(source).hexdigest()
    if actual != digest:
        raise ExtensionError(f'adapter source digest mismatch: {path.name}')
    spec = importlib.util.spec_from_file_location(module_key, path)
    if spec is None or spec.loader is None:
        raise ExtensionError(f'adapter source cannot be imported: {path.name}')
    module = importlib.util.module_from_spec(spec)
    # Execute the same bytes that were hashed so a file swap between checking
    # and import cannot substitute different adapter code.
    sys.modules[module_key] = module
    try:
        code = compile(source, str(path), 'exec')
        exec(code, module.__dict__)
    except Exception:
        sys.modules.pop(module_key, None)
        raise
    return module


def _catalog_legacy_wrapper(adapter_id: str, adapter_class: type[Any]) -> type[Any]:
    from lib.modules import Module
    from pathlib import Path
    from types import SimpleNamespace

    class CatalogLegacyAdapter(Module):
        def __init__(self, context: object) -> None:
            if getattr(context, 'module_id', None) != adapter_id:
                raise ExtensionError('catalog adapter context does not match its ID')
            self.context = context
            # Catalog selection is the selection gate for this compatibility
            # bridge. Existing consumer factories use this option only to
            # distinguish selected from absent; the locked context supplies
            # the actual verified selection and artifact handles.
            argument = f'module_{adapter_id.replace("-", "_")}'
            self.adapter = adapter_class.from_args(SimpleNamespace(
                **{argument: Path('<catalog-selection>')}
            ))
            if not isinstance(self.adapter, adapter_class):
                raise ExtensionError('catalog legacy factory returned an invalid adapter')

        def requirements(self):
            return self.adapter.requirements()

        def inject(self, boot_fs, ext_fs, sepolicies, compatible_sepolicy=False):
            return self.adapter.inject(
                boot_fs,
                ext_fs,
                sepolicies,
                compatible_sepolicy,
            )

    CatalogLegacyAdapter.__name__ = f'{adapter_class.__name__}CatalogAdapter'
    return CatalogLegacyAdapter


def load_adapter_extension(path: Path | None) -> AdapterExtension | None:
    """Load explicitly listed adapters; ``None`` preserves all old defaults."""
    if path is None:
        return None
    from lib.modules import LegacyCliModule, Module

    try:
        base = path.resolve(strict=True).parent
        raw = tomlkit.loads(path.read_text(encoding='UTF-8')).unwrap()
        if not isinstance(raw, dict) or set(raw) != {
            'schema_version', 'catalog_directories', 'adapters'
        }:
            raise ValueError('extension must contain only schema_version, catalog_directories, adapters')
        if raw['schema_version'] != EXTENSION_SCHEMA:
            raise ValueError(f'unsupported extension schema: {raw["schema_version"]!r}')
        if not isinstance(raw['catalog_directories'], list) or not isinstance(raw['adapters'], list):
            raise ValueError('catalog_directories and adapters must be arrays')
    except Exception as error:
        raise ExtensionError(f'invalid adapter extension: {path}') from error

    catalog_directories = tuple(
        _safe_path(base, value, 'catalog directory')
        for value in raw['catalog_directories']
    )
    # Catalog entries are directories, unlike source and manifest files.
    for directory in catalog_directories:
        if not directory.is_dir():
            raise ExtensionError('catalog directory is not a directory')

    builtin_ids = {item.id for item in (*INTERNAL_ADAPTERS, *LOCKED_ADAPTERS)}
    # Validate every entry and every source digest before importing any code.
    preflight_ids: set[str] = set()
    for index, item in enumerate(raw['adapters']):
        if not isinstance(item, dict) or set(item) != {
            'id', 'kind', 'source', 'sha256', 'target',
            'verification_schemes', 'trusted_signers', 'digest_required',
        }:
            raise ExtensionError(f'adapter entry {index} has unknown or missing fields')
        adapter_id = item['id']
        if not isinstance(adapter_id, str) or not MODULE_ID_PATTERN.fullmatch(adapter_id):
            raise ExtensionError(f'adapter entry {index} has an invalid ID')
        if adapter_id in builtin_ids or adapter_id in preflight_ids:
            raise ExtensionError(f'duplicate adapter ID: {adapter_id}')
        preflight_ids.add(adapter_id)
        if item['kind'] not in ('legacy-cli', 'locked', 'catalog-legacy'):
            raise ExtensionError(f'unknown adapter kind: {item["kind"]!r}')
        if not isinstance(item['verification_schemes'], list) or not all(
            isinstance(value, str) and value for value in item['verification_schemes']
        ):
            raise ExtensionError('verification_schemes must be non-empty strings')
        if not isinstance(item['trusted_signers'], list) or not all(
            isinstance(value, str) and value for value in item['trusted_signers']
        ):
            raise ExtensionError('trusted_signers must be non-empty strings')
        if type(item['digest_required']) is not bool:
            raise ExtensionError('digest_required must be a boolean')
        source = _safe_path(base, item['source'], 'adapter source')
        if not source.is_file():
            raise ExtensionError('adapter source must be a regular file')
        expected = item['sha256']
        if not isinstance(expected, str) or not SHA256_PATTERN.fullmatch(expected):
            raise ExtensionError('adapter source digest must be lowercase SHA-256')
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ExtensionError(f'adapter source digest mismatch: {source.name}')

    seen_ids: set[str] = set()
    catalog_registrations: list[AdapterRegistration] = []
    legacy_modules: list[type[Any]] = []
    locked_factories: dict[str, type[Any]] = {}

    for index, item in enumerate(raw['adapters']):
        if not isinstance(item, dict) or set(item) != {
            'id', 'kind', 'source', 'sha256', 'target',
            'verification_schemes', 'trusted_signers', 'digest_required',
        }:
            raise ExtensionError(f'adapter entry {index} has unknown or missing fields')
        adapter_id = item['id']
        kind = item['kind']
        if not isinstance(adapter_id, str) or not MODULE_ID_PATTERN.fullmatch(adapter_id):
            raise ExtensionError(f'adapter entry {index} has an invalid ID')
        if adapter_id in builtin_ids or adapter_id in seen_ids:
            raise ExtensionError(f'duplicate adapter ID: {adapter_id}')
        seen_ids.add(adapter_id)
        if kind not in ('legacy-cli', 'locked', 'catalog-legacy'):
            raise ExtensionError(f'unknown adapter kind: {kind!r}')
        if not isinstance(item['verification_schemes'], list) or not all(
            isinstance(value, str) and value for value in item['verification_schemes']
        ):
            raise ExtensionError('verification_schemes must be non-empty strings')
        if not isinstance(item['trusted_signers'], list) or not all(
            isinstance(value, str) and value for value in item['trusted_signers']
        ):
            raise ExtensionError('trusted_signers must be non-empty strings')
        if type(item['digest_required']) is not bool:
            raise ExtensionError('digest_required must be a boolean')

        source = _safe_path(base, item['source'], 'adapter source')
        if not source.is_file():
            raise ExtensionError('adapter source must be a regular file')
        module = _load_source(source, item['sha256'], f'_modos_adapter_{adapter_id.replace("-", "_")}')
        target = item['target']
        if not isinstance(target, str) or not target.isidentifier():
            raise ExtensionError('adapter target must be a class or factory name')
        constructor = getattr(module, target, None)
        if kind in ('legacy-cli', 'catalog-legacy'):
            if isinstance(constructor, type):
                adapter_class = constructor
            elif callable(constructor):
                adapter_class = constructor()
            else:
                adapter_class = None
            if not isinstance(adapter_class, type) or not issubclass(adapter_class, LegacyCliModule):
                raise ExtensionError(f'legacy adapter is not a LegacyCliModule: {adapter_id}')
            if adapter_class.NAME != adapter_id:
                raise ExtensionError(f'legacy adapter NAME does not match ID: {adapter_id}')
            legacy_modules.append(adapter_class)
            if kind == 'legacy-cli':
                continue

        if isinstance(constructor, type):
            adapter_class = constructor
        elif callable(constructor):
            adapter_class = constructor()
        else:
            adapter_class = None
        if not isinstance(adapter_class, type) or not issubclass(adapter_class, Module):
            raise ExtensionError(f'locked adapter is not a Module subclass: {adapter_id}')
        registration = AdapterRegistration(
            id=adapter_id,
            constructor_module=f'_modos_adapter_{adapter_id.replace("-", "_")}',
            constructor_name=target,
            verification_schemes=tuple(item['verification_schemes']),
            trusted_signers=tuple(item['trusted_signers']),
            digest_required=item['digest_required'],
        )
        catalog_registrations.append(registration)
        if kind == 'catalog-legacy':
            locked_factories[adapter_id] = _catalog_legacy_wrapper(
                adapter_id,
                adapter_class,
            )
        else:
            locked_factories[adapter_id] = adapter_class

    return AdapterExtension(
        path=path,
        catalog_directories=catalog_directories,
        catalog_registrations=tuple(catalog_registrations),
        legacy_modules=tuple(legacy_modules),
        locked_factories=locked_factories,
    )
