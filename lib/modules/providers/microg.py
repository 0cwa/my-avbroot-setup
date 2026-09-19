# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Reviewed GitHub-release lock provider for official microG APKs."""

import json
from pathlib import Path
import re
from urllib.parse import quote
from urllib.request import Request, urlopen

from lib.modules.locks import (
    ApkIdentity,
    ArtifactLegal,
    ArtifactLock,
    ArtifactLockFile,
    ArtifactSource,
    LockError,
    ModuleLock,
    write_lock,
)
from lib.modules.registry import MICROG_APK_SIGNER_SHA256


MODULE_ID = 'microg'
REPOSITORY = 'microg/GmsCore'
REPOSITORY_URL = 'https://github.com/microg/GmsCore'
API_ORIGIN = 'https://api.github.com'
DOWNLOAD_ORIGINS = (
    'https://github.com',
    'https://release-assets.githubusercontent.com',
    'https://objects.githubusercontent.com',
)
MAX_RELEASE_METADATA_BYTES = 2 * 1024 * 1024
RELEASE_TAG_PATTERN = re.compile(r'^v[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
ASSET_PATTERNS = {
    'gmscore-apk': (
        re.compile(r'^com\.google\.android\.gms-([0-9]+)\.apk$'),
        'com.google.android.gms',
    ),
    'companion-apk': (
        re.compile(r'^com\.android\.vending-([0-9]+)\.apk$'),
        'com.android.vending',
    ),
}
OUTPUT_SCOPES = ('local-unpublished', 'private', 'shared', 'published')


def _strict_json(data: bytes) -> object:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise LockError('microG release metadata contains duplicate JSON keys')
            result[key] = value
        return result

    try:
        return json.loads(data.decode('UTF-8'), object_pairs_hook=reject_duplicates)
    except LockError:
        raise
    except Exception as error:
        raise LockError('microG release metadata is invalid JSON') from error


def _fetch_release(release_tag: str) -> dict[str, object]:
    if not RELEASE_TAG_PATTERN.fullmatch(release_tag):
        raise LockError('microG release tag is not canonical')
    url = (
        f'{API_ORIGIN}/repos/{REPOSITORY}/releases/tags/'
        f'{quote(release_tag, safe="")}'
    )
    try:
        request = Request(
            url,
            headers={
                'Accept': 'application/vnd.github+json',
                'User-Agent': 'my-avbroot-setup-microg-lock/1',
            },
        )
        with urlopen(request, timeout=60) as response:
            if response.geturl() != url:
                raise LockError('microG release metadata unexpectedly redirected')
            if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                raise LockError('microG release metadata used content encoding')
            declared = response.headers.get('Content-Length')
            if declared is not None and int(declared, 10) > MAX_RELEASE_METADATA_BYTES:
                raise LockError('microG release metadata exceeds byte limit')
            data = response.read(MAX_RELEASE_METADATA_BYTES + 1)
    except LockError:
        raise
    except Exception as error:
        raise LockError('microG release metadata fetch failed') from error
    if len(data) > MAX_RELEASE_METADATA_BYTES:
        raise LockError('microG release metadata exceeds byte limit')
    raw = _strict_json(data)
    if not isinstance(raw, dict):
        raise LockError('microG release metadata must be an object')
    return raw


def _release_assets(
    release: dict[str, object],
    release_tag: str,
) -> dict[str, tuple[str, int, int, str]]:
    if (
        release.get('tag_name') != release_tag
        or release.get('draft') is not False
        or release.get('prerelease') is not False
    ):
        raise LockError('microG release metadata does not describe the selected release')
    assets = release.get('assets')
    if not isinstance(assets, list):
        raise LockError('microG release metadata has no assets array')

    by_name: dict[str, dict[str, object]] = {}
    for raw in assets:
        if not isinstance(raw, dict) or not isinstance(raw.get('name'), str):
            raise LockError('microG release contains an invalid asset record')
        name = raw['name']
        if name in by_name:
            raise LockError('microG release contains duplicate asset names')
        by_name[name] = raw

    selected: dict[str, tuple[str, int, int, str]] = {}
    for artifact_id, (pattern, package_name) in ASSET_PATTERNS.items():
        matches = []
        for name, asset in by_name.items():
            match = pattern.fullmatch(name)
            if match:
                matches.append((name, asset, int(match.group(1))))
        if len(matches) != 1:
            raise LockError(
                f'microG release must contain exactly one custom-ROM {artifact_id}'
            )
        name, asset, version_code = matches[0]
        size = asset.get('size')
        digest = asset.get('digest')
        download_url = asset.get('browser_download_url')
        expected_url = (
            f'{REPOSITORY_URL}/releases/download/{release_tag}/{name}'
        )
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or not isinstance(digest, str)
            or not digest.startswith('sha256:')
            or not re.fullmatch(r'[0-9a-f]{64}', digest[7:])
            or download_url != expected_url
        ):
            raise LockError(f'microG release asset metadata is invalid: {artifact_id}')
        selected[artifact_id] = (
            package_name,
            version_code,
            size,
            digest[7:],
        )
    return selected


def update_microg_lock(
    *,
    output: Path,
    release_tag: str,
    release_fetcher=_fetch_release,
) -> ArtifactLockFile:
    """Resolve one explicit microG release into a canonical two-APK lock."""

    assets = _release_assets(release_fetcher(release_tag), release_tag)
    locked = []
    for artifact_id in sorted(assets):
        package_name, version_code, size, digest = assets[artifact_id]
        filename = (
            f'{package_name}-{version_code}.apk'
        )
        locked.append(ArtifactLock(
            id=artifact_id,
            kind='apk',
            role='injection-input',
            immutable_url=(
                f'{REPOSITORY_URL}/releases/download/{release_tag}/{filename}'
            ),
            allowed_origins=DOWNLOAD_ORIGINS,
            version=str(version_code),
            size=size,
            sha256=digest,
            apk=ApkIdentity(
                package_name=package_name,
                version_code=version_code,
                signer_sha256=MICROG_APK_SIGNER_SHA256,
            ),
            source=ArtifactSource(
                url=REPOSITORY_URL,
                revision=release_tag,
            ),
            legal=ArtifactLegal(
                license='Apache-2.0',
                source_offer_required=False,
                allowed_output_scopes=OUTPUT_SCOPES,
            ),
        ))

    lock = ArtifactLockFile(
        schema_version=1,
        modules=(
            ModuleLock(
                id=MODULE_ID,
                version=release_tag,
                artifacts=tuple(locked),
            ),
        ),
    )
    write_lock(output, lock)
    return lock
