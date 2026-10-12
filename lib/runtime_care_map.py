# SPDX-License-Identifier: GPL-3.0-only
"""Signed payload -> extracted image -> ext4 runtime property care-map proof.

The verifier report is emitted by avbroot only after strict cryptographic and
operation-coverage verification. It is never accepted from a caller. afsr and
avbroot use the helper's configured tool runner; no additional host tools are
introduced. Physical boot and property loading remain device acceptance work.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import zipfile

import tomlkit

from lib import care_map_compat, external

BLOCK_SIZE = 4096


def read_map(ota: Path) -> dict[str, dict[str, str]]:
    with zipfile.ZipFile(ota) as archive:
        members = [i for i in archive.infolist() if i.filename == 'care_map.pb']
        if len(members) != 1 or not 0 < members[0].file_size <= 1024 * 1024:
            raise ValueError('OTA needs one bounded nonempty care_map.pb')
        data = archive.read(members[0])
    care_map_compat._parse_care_map(data)
    result = {}
    for _, raw in care_map_compat._length_fields(data):
        fields = {number: value.decode('utf-8') for number, value in
                  care_map_compat._length_fields(raw)}
        result[fields[1]] = dict(name=fields[1], ranges=fields[2],
                                 id=fields[3], fingerprint=fields[4])
    return result


def _varint(value: int) -> bytes:
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def write_map(entries: dict[str, dict[str, str]], path: Path) -> None:
    def field(number, value):
        return _varint(number * 8 + 2) + _varint(len(value)) + value
    data = b''
    for name in sorted(entries):
        record = entries[name]
        raw = b''.join(field(i, record[key].encode()) for i, key in
                       enumerate(('name', 'ranges', 'id', 'fingerprint'), 1))
        data += field(1, raw)
    care_map_compat._parse_care_map(data)
    path.write_bytes(data)


def file_hash(path: Path) -> str:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f'image must be a regular file: {path}')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def filesystem_fingerprint(image: Path, name: str, scratch: Path) -> str:
    """Use authenticated existing tools and Android's canonical property paths."""
    scratch.mkdir()
    external.unpack_avb(image, scratch)
    raw = scratch / 'raw.img'
    with raw.open('rb') as stream:
        stream.seek(1024 + 56)
        if stream.read(2) != b'\x53\xef':
            raise ValueError(f'{name}: runtime property proof currently requires ext4')
    external.unpack_fs(raw, scratch)
    relative = ('system/build.prop' if name == 'system' else
                'build.prop' if name == 'vendor' else 'etc/build.prop')
    prop = scratch / 'fs_tree' / relative
    if any(part.is_symlink() for part in (prop, *prop.parents)) or not prop.is_file() or prop.stat().st_size > 1024 * 1024:
        raise ValueError(f'{name}: absent or unsafe canonical build.prop')
    property_id = f'ro.{name}.build.fingerprint'
    values = []
    for line in prop.read_text(encoding='utf-8').splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            if key.strip() == property_id:
                values.append(value.strip())
    if len(values) != 1 or not 1 <= len(values[0]) <= 512 or any(
        not 33 <= ord(ch) <= 126 for ch in values[0]
    ) or values[0] == 'unknown':
        raise ValueError(f'{name}: missing or ambiguous runtime fingerprint')
    return values[0]


def verify_output(ota: Path, expected: Path, public_key: Path, certificate: Path,
                  scratch: Path) -> dict[str, dict[str, str]]:
    """Authenticate first, bind each newly extracted image, then read properties."""
    scratch.mkdir()
    report = scratch / 'verified.json'
    external.verify_ota(ota, public_key, certificate,
                        expected_care_map=expected, verification_report=report)
    evidence = json.loads(report.read_text())
    if evidence.get('schema') != 'avbroot-ota-verification-v1':
        raise ValueError('unsupported authenticated verification report')
    entries = read_map(ota)
    required = evidence['required_care_map_partitions']
    if len(required) != len(set(required)) or set(required) != set(entries):
        raise ValueError('care map differs from verified required partition set')
    records = {p['name']: p for p in evidence['partitions']}
    if len(records) != len(evidence['partitions']):
        raise ValueError('duplicate verified partition evidence')
    images = scratch / 'images'
    external.unpack_ota(ota, images, sorted(entries))
    for name, entry in entries.items():
        image = images / f'{name}.img'
        record = records[name]
        if image.stat().st_size != record['image_size'] or file_hash(image) != record['image_sha256']:
            raise ValueError(f'{name}: extracted image differs from verified payload')
        extent = record['verity_data_size']
        if type(extent) is not int or extent <= 0 or extent % BLOCK_SIZE:
            raise ValueError(f'{name}: invalid protected data extent')
        values = list(map(int, entry['ranges'].split(',')))[1:]
        if max(values) > extent // BLOCK_SIZE:
            raise ValueError(f'{name}: care range exceeds protected data')
        actual = filesystem_fingerprint(image, name, scratch / name)
        if entry['fingerprint'] != actual:
            raise ValueError(f'{name}: care-map fingerprint differs from final filesystem')
    return entries


def expected_output_map(source: dict[str, dict[str, str]],
                        replacements: dict[str, Path], scratch: Path) -> Path:
    """Unchanged sparse ranges survive; replaced ext4 images care for all data.

    avbroot subsequently proves deterministic payload writes for every cared
    block. New allocations therefore need not fit the source sparse care map.
    """
    scratch.mkdir()
    entries = {name: dict(entry) for name, entry in source.items()}
    for name in sorted(set(source) & set(replacements)):
        directory = scratch / name
        directory.mkdir()
        external.unpack_avb(replacements[name], directory)
        with (directory / 'avb.toml').open('rb') as stream:
            metadata = tomlkit.load(stream)
        descriptors = [d for d in metadata['header']['descriptors']
                       if d['type'] == 'HashTree' and d['partition_name'] == name]
        if len(descriptors) != 1:
            raise ValueError(f'{name}: missing unique protected data descriptor')
        size = descriptors[0]['image_size']
        if size <= 0 or size % BLOCK_SIZE or metadata['footer']['original_image_size'] != size:
            raise ValueError(f'{name}: inconsistent protected data extent')
        entries[name]['ranges'] = f'2,0,{size // BLOCK_SIZE}'
        entries[name]['fingerprint'] = filesystem_fingerprint(
            replacements[name], name, scratch / f'{name}-properties')
        if entries[name]['fingerprint'] != source[name]['fingerprint']:
            raise ValueError(f'{name}: patched runtime identity changed')
    expected = scratch / 'expected.pb'
    write_map(entries, expected)
    return expected
