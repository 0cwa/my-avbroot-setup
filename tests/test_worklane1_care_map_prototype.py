# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic, offline research tests. Not AVB, OTA or first-boot tests."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'research'))
from care_map_prototype import (  # noqa: E402
    BLOCK_SIZE, CareMapUnsafe, ImageEvidence, PartitionEntry,
    debugfs_build_fingerprint, parse_map, parse_ranges, regenerate_with_sparse_proof,
    serialize_map, verify_output_map,
)

SONY = 'Sony/XQ-DC72/XQ-DC72:15/68.2.A.3.107/068002A003010700521798587:user/release-keys'
LINEAGE = 'Sony/lineage_pdx235/pdx235:16/BP4A.251205.006/9d767828e9:userdebug/release-keys'
NEW = 'example/new/device:16/EXAMPLE/123:userdebug/release-keys'


class CareMapPrototypeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.name = 'system'
        self.values = {}
        # Meaningful: blocks 0, 1, 4. Don't-care: blocks 2, 3, 5.
        self.range_string = '4,0,2,4,5'
        self.source_data = b''.join(bytes([n]) * BLOCK_SIZE for n in range(6))
        self.src = self._image('source.img', self.source_data, SONY)
        self.dst = self._image('output.img', self.source_data, SONY)
        self.source_map = self._map(SONY)

    def _image(self, filename, contents, fingerprint=SONY, protected_blocks=6,
               footer_original_bytes=None, manifest_image_bytes=None):
        path = self.dir / filename
        path.write_bytes(contents)
        self.values[path] = fingerprint
        return ImageEvidence(path, hashlib.sha256(contents).hexdigest(),
                             protected_blocks * BLOCK_SIZE, '/build.prop',
                             footer_original_bytes if footer_original_bytes is not None else protected_blocks * BLOCK_SIZE,
                             manifest_image_bytes if manifest_image_bytes is not None else len(contents))

    def _map(self, fingerprint=SONY, ranges=None, name=None):
        name = name or self.name
        entry = PartitionEntry(name, ranges or self.range_string,
                               f'ro.{name}.build.fingerprint', fingerprint)
        return serialize_map({name: entry})

    def _read(self, evidence, name):
        return self.values[evidence.image]

    def _regenerate(self, source=None, output=None, srcmap=None, partitions=None):
        return regenerate_with_sparse_proof(
            srcmap if srcmap is not None else self.source_map,
            source if source is not None else {self.name: self.src},
            output if output is not None else {self.name: self.dst},
            partitions if partitions is not None else {self.name}, self._read)

    def test_signed_sony_fingerprint_beats_avb_lineage_descriptor(self):
        # LINEAGE is the AVB descriptor but is deliberately NOT a runtime input.
        self.assertNotEqual(SONY, LINEAGE)
        result, changed = self._regenerate()
        self.assertEqual(SONY, parse_map(result)['system'].fingerprint)
        self.assertEqual(self.range_string, parse_map(result)['system'].ranges)
        self.assertEqual({'system': 0}, changed)
        self.assertEqual({'system': 0}, verify_output_map(
            self.source_map, result, {'system': self.src}, {'system': self.dst},
            {'system'}, self._read))

    def test_legitimate_changed_filesystem_fingerprint_in_cared_block(self):
        data = bytearray(self.source_data)
        data[BLOCK_SIZE:BLOCK_SIZE + 4] = b'PROP'
        self.dst = self._image('output.img', bytes(data), NEW)
        result, changed = self._regenerate()
        self.assertEqual(NEW, parse_map(result)['system'].fingerprint)
        self.assertEqual(1, changed['system'])
        # Worklane 3 may still conservatively disallow any identity change.

    def test_changed_content_inside_cared_range_preserves_sparse_proof(self):
        data = bytearray(self.source_data)
        data[0] ^= 1
        data[4 * BLOCK_SIZE + 4] ^= 2
        self.dst = self._image('output.img', bytes(data))
        self.assertEqual(2, self._regenerate()[1]['system'])

    def test_changed_content_outside_cared_range_fails(self):
        data = bytearray(self.source_data)
        data[3 * BLOCK_SIZE] ^= 1
        self.dst = self._image('output.img', bytes(data))
        with self.assertRaisesRegex(CareMapUnsafe, 'outside authenticated sparse'):
            self._regenerate()

    def test_hash_mismatch_catches_tampering_even_within_cared_range(self):
        self.dst.image.write_bytes(b'!' * BLOCK_SIZE + self.source_data[BLOCK_SIZE:])
        with self.assertRaisesRegex(CareMapUnsafe, 'digest differs'):
            self._regenerate()

    def test_source_hash_mismatch_fails(self):
        self.src.image.write_bytes(b'!' * BLOCK_SIZE + self.source_data[BLOCK_SIZE:])
        with self.assertRaisesRegex(CareMapUnsafe, 'digest differs'):
            self._regenerate()

    def test_avb_footer_only_change_allowed_if_output_hash_is_verified(self):
        footer = b'AVB metadata'.ljust(BLOCK_SIZE, b'\x00')
        self.src = self._image('source.img', self.source_data + footer)
        self.dst = self._image('output.img', self.source_data + footer[::-1])
        self.assertEqual(0, self._regenerate()[1]['system'])

    def test_footer_hashtree_mismatch_fails(self):
        self.dst = self._image('output.img', self.source_data,
                               footer_original_bytes=5 * BLOCK_SIZE)
        with self.assertRaisesRegex(CareMapUnsafe, 'Inconsistent signed manifest'):
            self._regenerate()

    def test_manifest_size_mismatch_fails(self):
        self.dst = self._image('output.img', self.source_data, manifest_image_bytes=100)
        with self.assertRaisesRegex(CareMapUnsafe, 'Inconsistent signed manifest'):
            self._regenerate()

    def test_protected_extent_change_fails(self):
        self.dst = self._image('output.img', self.source_data, protected_blocks=5)
        with self.assertRaisesRegex(CareMapUnsafe, 'Layout changed'):
            self._regenerate()

    def test_partition_file_length_change_fails(self):
        self.dst = self._image('output.img', self.source_data + b'X' * BLOCK_SIZE)
        with self.assertRaisesRegex(CareMapUnsafe, 'Layout changed'):
            self._regenerate()

    def test_wrong_source_fingerprint_fails(self):
        self.values[self.src.image] = LINEAGE
        with self.assertRaisesRegex(CareMapUnsafe, 'disagrees with filesystem'):
            self._regenerate()

    def test_wrong_output_identity_fails(self):
        candidate = self._map(LINEAGE)
        with self.assertRaisesRegex(CareMapUnsafe, 'Output care-map fingerprint'):
            verify_output_map(self.source_map, candidate,
                {'system': self.src}, {'system': self.dst}, {'system'}, self._read)

    def test_contiguous_output_cannot_silently_replace_sparse_map(self):
        candidate = self._map(SONY, '2,0,6')
        with self.assertRaisesRegex(CareMapUnsafe, 'ranges differ'):
            verify_output_map(self.source_map, candidate,
                {'system': self.src}, {'system': self.dst}, {'system'}, self._read)

    def test_missing_output_partition_fails(self):
        with self.assertRaisesRegex(CareMapUnsafe, 'differ'):
            self._regenerate(output={})

    def test_signer_manifest_partition_set_required(self):
        with self.assertRaisesRegex(CareMapUnsafe, 'differ'):
            self._regenerate(partitions={'system', 'product'})

    def test_duplicate_partition_name_fails(self):
        duplicate = self.source_map + self.source_map
        with self.assertRaisesRegex(CareMapUnsafe, 'duplicate'):
            parse_map(duplicate)

    def test_corrupt_and_duplicate_fields_fail(self):
        self.assertRaises(CareMapUnsafe, parse_map, b'')
        self.assertRaises(CareMapUnsafe, parse_map, b'\x0a\x05\x0a\x04x')
        self.assertRaises(CareMapUnsafe, parse_map, b'\x80\x00')
        self.assertRaises(CareMapUnsafe, parse_map, b'\x12\x01x')
        # Duplicate a real partition fingerprint field (#4), not just a bad length.
        from care_map_prototype import _wire_field
        info = (('system', 1), (self.range_string, 2),
                ('ro.system.build.fingerprint', 3), (SONY, 4))
        inner = b''.join(_wire_field(i, text.encode()) for text, i in info)
        inner += _wire_field(4, SONY.encode())
        with self.assertRaisesRegex(CareMapUnsafe, 'duplicate'):
            parse_map(_wire_field(1, inner))

    def test_malformed_ranges_fail(self):
        for bad in ('', '2,0', '3,0,1,2', '2,6,7', '2,1,1',
                    '4,0,3,2,4', '4,0,2,5,9', '2,-1,2', '2,0,a',
                    '2,00,6', '2,0,06', '02,0,6', '2,0,6,'):
            with self.subTest(bad=bad), self.assertRaises(CareMapUnsafe):
                parse_ranges(bad, 6)

    def test_sparse_bounds_and_exclusive_end(self):
        self.assertEqual(((0, 2), (4, 5)), parse_ranges(self.range_string, 6))
        self.assertEqual(((0, 6),), parse_ranges('2,0,6', 6))
        with self.assertRaises(CareMapUnsafe):
            parse_ranges('2,0,7', 6)

    def test_unknown_identity_and_wrong_property_id_fail(self):
        bad = PartitionEntry('system', self.range_string, 'bad.property', SONY)
        with self.assertRaises(CareMapUnsafe):
            parse_map(serialize_map({'system': bad}))
        bad = PartitionEntry('system', self.range_string,
                             'ro.system.build.fingerprint', 'unknown')
        with self.assertRaises(CareMapUnsafe):
            serialize_map({'system': bad})

    def test_symlink_images_fail(self):
        symlink = self.dir / 'linked.img'
        symlink.symlink_to(self.src.image)
        alt = ImageEvidence(symlink, self.src.manifest_sha256,
                            self.src.verity_data_bytes, '/build.prop',
                            self.src.footer_original_bytes, self.src.manifest_image_bytes)
        with self.assertRaisesRegex(CareMapUnsafe, 'non-symlink'):
            self._regenerate(source={'system': alt})

    def test_debugfs_missing_fails_closed(self):
        with mock.patch('care_map_prototype.subprocess.run', side_effect=FileNotFoundError()):
            with self.assertRaisesRegex(CareMapUnsafe, 'Cannot read'):
                debugfs_build_fingerprint(self.src, 'system')

    def test_debugfs_returns_real_image_property_and_rejects_duplicates(self):
        stdout = b'ro.system.build.fingerprint=' + SONY.encode() + b'\n'
        with mock.patch('care_map_prototype.subprocess.run') as run:
            run.return_value = mock.Mock(returncode=0, stdout=stdout, stderr=b'debugfs 1.47\n')
            self.assertEqual(SONY, debugfs_build_fingerprint(self.src, 'system'))
            argv = run.call_args.args[0]
            self.assertEqual(argv[:3], ['debugfs', '-R', 'cat /build.prop'])
            self.assertNotIn('-w', argv)
            run.return_value.stdout = stdout * 2
            with self.assertRaisesRegex(CareMapUnsafe, 'duplicate'):
                debugfs_build_fingerprint(self.src, 'system')


if __name__ == '__main__':
    unittest.main()