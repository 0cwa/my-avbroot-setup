# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Standalone adapter contract tests; synthetic evidence is not signed proof."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'research'))
from care_map_candidate import run  # noqa: E402
from care_map_prototype import CareMapUnsafe, PartitionEntry, serialize_map  # noqa: E402

NAMES = ('odm', 'product', 'system', 'system_ext', 'vendor', 'vendor_dlkm')
RANGES = {
    'odm': '2,0,8', 'product': '4,0,2,4,7', 'system': '4,0,3,5,8',
    'system_ext': '4,0,2,6,8', 'vendor': '2,0,8', 'vendor_dlkm': '2,0,8',
}
STOCK = 'Sony/XQ-DC72/XQ-DC72:15/68.2.A.3.107/068002A003010700521798587:user/release-keys'
LINEAGE = 'Sony/lineage_pdx235/pdx235:16/BP4A.251205.006/9d767828e9:userdebug/release-keys'
BS = 4096


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def original_map() -> bytes:
    return serialize_map({
        name: PartitionEntry(name, RANGES[name], f'ro.{name}.build.fingerprint', STOCK)
        for name in NAMES
    })


def image(i: int) -> bytes:
    return b''.join(bytes([(i * 19 + n * 7 + 1) % 256]) * BS for n in range(10))


def mutate(data: bytes, block: int) -> bytes:
    out = bytearray(data)
    out[block * BS + 97] ^= 0xc7
    return bytes(out)


def provenance_request():
    smap = original_map()
    rows = []
    for i, name in enumerate(NAMES):
        data = image(i)
        rows.append({
            'name': name,
            'source_image_b64': b64(data), 'output_image_b64': b64(data),
            'source_manifest_sha256': sha(data), 'output_manifest_sha256': sha(data),
            'source_manifest_size': len(data), 'output_manifest_size': len(data),
            'source_footer_original_size': BS * 8,
            'output_footer_original_size': BS * 8,
            'source_hashtree_image_size': BS * 8,
            'output_hashtree_image_size': BS * 8,
            'source_property_id': f'ro.{name}.build.fingerprint',
            'output_property_id': f'ro.{name}.build.fingerprint',
            'source_filesystem_fingerprint': STOCK,
            'output_filesystem_fingerprint': STOCK,
            'source_filesystem_type': 'ext4',
            'output_filesystem_type': 'ext4',
        })
    return {
        'schema': 'modos-care-map-provenance-v1',
        'block_size': BS,
        'source_care_map_b64': b64(smap),
        'candidate_output_care_map_b64': b64(smap),
        'source_care_map_sha256': sha(smap),
        'source_manifest_dynamic_partitions': list(NAMES),
        'output_manifest_dynamic_partitions': list(NAMES),
        'partitions': rows,
    }


def conformance_request():
    return {
        'schema': 'modos-care-map-conformance-v1',
        'name': 'product', 'block_size': BS,
        'original_image_size': 8 * BS,
        'sparse_total_blocks': 10,
        'sparse_chunks': [
            {'type': 'raw', 'start': 0, 'end': 2},
            {'type': 'dontcare', 'start': 2, 'end': 4},
            {'type': 'fill', 'start': 4, 'end': 5},
            {'type': 'raw', 'start': 5, 'end': 7},
            {'type': 'dontcare', 'start': 7, 'end': 9},
            {'type': 'raw', 'start': 9, 'end': 10},
        ],
        'filesystem_property_id': 'ro.product.build.fingerprint',
        'filesystem_fingerprint': STOCK,
        'avb_fingerprint': LINEAGE,
    }


class CandidateConformanceTests(unittest.TestCase):
    def test_raw_fill_dontcare_and_avb_cutoff(self):
        got = run(conformance_request())
        self.assertEqual(got['ranges'], '4,0,2,4,7')
        self.assertEqual(got['fingerprint'], STOCK)
        self.assertNotEqual(got['fingerprint'], LINEAGE)

    def test_contiguous_unsparsed(self):
        req = conformance_request()
        req['sparse_total_blocks'] = req['sparse_chunks'] = None
        self.assertEqual(run(req)['ranges'], '2,0,8')

    def test_fingerprint_from_filesystem_changes_without_avb_change(self):
        req = conformance_request()
        req['filesystem_fingerprint'] = 'test/output:fingerprint'
        self.assertEqual(run(req)['fingerprint'], 'test/output:fingerprint')

    def test_adjacent_meaningful_extents_merge(self):
        req = conformance_request()
        req['sparse_chunks'][2]['type'] = 'raw'
        self.assertEqual(run(req)['ranges'], '4,0,2,4,7')
        req['sparse_chunks'][1]['type'] = 'fill'
        self.assertEqual(run(req)['ranges'], '2,0,7')

    def test_invalid_source_fields_rejected(self):
        cases = {
            'wrong-property': ('filesystem_property_id', 'ro.vendor.build.fingerprint'),
            'empty-fingerprint': ('filesystem_fingerprint', ''),
            'wrong-blocksize': ('block_size', 512),
            'bool-blocksize': ('block_size', True),
            'bad-name': ('name', 'Product;rm -rf'),
            'bad-image-size': ('original_image_size', 10 * BS + 1),
            'wrong-schema': ('schema', 'not-conformance-v1'),
            'total-blocks-short': ('sparse_total_blocks', 7),
        }
        for case, (key, value) in cases.items():
            with self.subTest(case=case):
                req = conformance_request()
                req[key] = value
                with self.assertRaises((CareMapUnsafe, TypeError)):
                    run(req)

    def test_gaps_overlap_outofbounds_unknown_zero_length_fail(self):
        for case in ('overlap', 'gap', 'truncated', 'zero', 'unknown', 'outofbounds', 'nocared'):
            with self.subTest(case=case):
                req = conformance_request()
                if case == 'overlap': req['sparse_chunks'][1]['start'] = 1
                if case == 'gap': req['sparse_chunks'][1]['start'] = 3
                if case == 'truncated': req['sparse_chunks'].pop()
                if case == 'zero': req['sparse_chunks'][1]['end'] = 2
                if case == 'unknown': req['sparse_chunks'][1]['type'] = 'other'
                if case == 'outofbounds': req['sparse_chunks'][-1]['end'] = 11
                if case == 'nocared':
                    req['sparse_chunks'] = [{'type': 'dontcare', 'start': 0, 'end': 10}]
                with self.assertRaises((CareMapUnsafe, TypeError)):
                    run(req)


class CandidateProvenanceTests(unittest.TestCase):
    @staticmethod
    def rec(req, name):
        return next(r for r in req['partitions'] if r['name'] == name)

    def update_image(self, req, name, block, *, signed=True, side='output'):
        record = self.rec(req, name)
        data = mutate(base64.b64decode(record[f'{side}_image_b64']), block)
        record[f'{side}_image_b64'] = b64(data)
        if signed:
            record[f'{side}_manifest_sha256'] = sha(data)

    def test_six_partition_clean_proof(self):
        result = run(provenance_request())
        self.assertEqual(result['schema'], 'modos-care-map-preservation-proof-v1')
        self.assertTrue(result['candidate_care_map_matches_source_semantics'])
        self.assertEqual([r['name'] for r in result['partitions']], list(NAMES))
        self.assertEqual([r['changed_protected_blocks'] for r in result['partitions']], [0] * 6)

    def test_every_partition_cared_block_change(self):
        req = provenance_request()
        for name, block in {
            'odm': 0, 'product': 4, 'system': 6,
            'system_ext': 6, 'vendor': 7, 'vendor_dlkm': 2,
        }.items():
            self.update_image(req, name, block)
        result = run(req)
        self.assertEqual([r['changed_protected_blocks'] for r in result['partitions']], [1] * 6)

    def test_footer_change_allowed_only_with_updated_image_digest(self):
        req = provenance_request()
        self.update_image(req, 'product', 8)
        result = run(req)
        self.assertEqual(0, result['partitions'][1]['changed_protected_blocks'])

    def test_protected_sparse_holes_fail_even_with_new_manifest_hash(self):
        for name, block in [('product', 3), ('system', 3), ('system_ext', 2), ('system_ext', 5)]:
            with self.subTest(partition=name, block=block):
                req = provenance_request()
                self.update_image(req, name, block)
                with self.assertRaisesRegex(CareMapUnsafe, 'outside authenticated sparse'):
                    run(req)

    def test_missing_signed_output_hash_fails(self):
        req = provenance_request()
        self.update_image(req, 'product', 4, signed=False)
        with self.assertRaisesRegex(CareMapUnsafe, 'digest differs'):
            run(req)

    def test_source_manifest_hash_fails(self):
        req = provenance_request()
        req['partitions'][2]['source_manifest_sha256'] = '0' * 64
        with self.assertRaisesRegex(CareMapUnsafe, 'digest differs'):
            run(req)

    def test_source_map_digest_fails(self):
        req = provenance_request()
        req['source_care_map_sha256'] = '0' * 64
        with self.assertRaisesRegex(CareMapUnsafe, 'source care map SHA-256'):
            run(req)

    def test_changed_source_filesystem_fingerprint_fails(self):
        req = provenance_request()
        self.rec(req, 'product')['source_filesystem_fingerprint'] = LINEAGE
        with self.assertRaisesRegex(CareMapUnsafe, 'drift'):
            run(req)

    def test_avb_identity_substitution_fails(self):
        req = provenance_request()
        self.rec(req, 'odm')['output_filesystem_fingerprint'] = LINEAGE
        with self.assertRaisesRegex(CareMapUnsafe, 'drift'):
            run(req)

    def test_changed_candidate_ranges_fails(self):
        req = provenance_request()
        change = original_map().replace(b'4,0,2,4,7', b'4,0,3,4,7')
        req['candidate_output_care_map_b64'] = b64(change)
        with self.assertRaisesRegex(CareMapUnsafe, 'Output care-map'):
            run(req)

    def test_missing_manifest_partition_fails(self):
        req = provenance_request()
        req['output_manifest_dynamic_partitions'].pop()
        with self.assertRaisesRegex(CareMapUnsafe, 'partitions disagree'):
            run(req)

    def test_duplicate_manifest_partition_fails(self):
        req = provenance_request()
        req['output_manifest_dynamic_partitions'][1] = req['output_manifest_dynamic_partitions'][0]
        with self.assertRaisesRegex(CareMapUnsafe, 'duplicate partition'):
            run(req)

    def test_invalid_footer_hashtree_extent_fails(self):
        req = provenance_request()
        self.rec(req, 'vendor')['output_footer_original_size'] += BS
        with self.assertRaisesRegex(CareMapUnsafe, 'Inconsistent signed manifest'):
            run(req)

    def test_wrong_signed_image_size_fails(self):
        req = provenance_request()
        self.rec(req, 'vendor')['output_manifest_size'] += BS
        with self.assertRaisesRegex(CareMapUnsafe, 'Inconsistent signed manifest'):
            run(req)

    def test_source_and_final_full_image_sizes_differ(self):
        req = provenance_request()
        r = self.rec(req, 'product')
        r['output_image_b64'] = b64(base64.b64decode(r['output_image_b64'])[:-BS])
        r['output_manifest_size'] -= BS
        r['output_manifest_sha256'] = sha(base64.b64decode(r['output_image_b64']))
        with self.assertRaisesRegex(CareMapUnsafe, 'changed partition image size'):
            run(req)

    def test_nonext4_fails_closed(self):
        req = provenance_request()
        self.rec(req, 'vendor')['source_filesystem_type'] = 'erofs'
        with self.assertRaisesRegex(CareMapUnsafe, 'unsupported filesystem'):
            run(req)

    def test_wrong_property_id_fails_closed(self):
        req = provenance_request()
        self.rec(req, 'vendor')['output_property_id'] = 'ro.odm.build.fingerprint'
        with self.assertRaisesRegex(CareMapUnsafe, 'property ID'):
            run(req)

    def test_bad_base64_fails(self):
        req = provenance_request()
        req['partitions'][3]['source_image_b64'] = '!!not-base64!!'
        with self.assertRaisesRegex(CareMapUnsafe, 'malformed base64'):
            run(req)

    def test_changed_source_hole_fails(self):
        req = provenance_request()
        self.update_image(req, 'product', 3, side='source')
        with self.assertRaisesRegex(CareMapUnsafe, 'outside authenticated sparse'):
            run(req)

    def test_signed_image_trailer_change_without_hash_update_fails(self):
        req = provenance_request()
        self.update_image(req, 'vendor', 9, signed=False)
        with self.assertRaisesRegex(CareMapUnsafe, 'digest differs'):
            run(req)

    def test_candidate_can_reorder_partition_records(self):
        req = provenance_request()
        from care_map_prototype import _fields, _wire_field
        chunks = [record for field, record in _fields(original_map()) if field == 1]
        swapped = b''.join(_wire_field(1, record) for record in reversed(chunks))
        req['candidate_output_care_map_b64'] = b64(swapped)
        self.assertTrue(run(req)['candidate_care_map_matches_source_semantics'])

    def test_each_protected_block_fails_or_passes_according_to_exact_sparse_membership(self):
        # Exhaustively try every protected block of every synthetic partition.
        for name in NAMES:
            values = tuple(map(int, RANGES[name].split(',')))
            cared = {b for start, end in zip(values[1::2], values[2::2])
                     for b in range(start, end)}
            for block in range(8):
                with self.subTest(name=name, block=block):
                    req = provenance_request()
                    self.update_image(req, name, block)
                    if block in cared:
                        result = run(req)
                        record = next(row for row in result['partitions'] if row['name'] == name)
                        self.assertEqual(1, record['changed_protected_blocks'])
                    else:
                        with self.assertRaisesRegex(CareMapUnsafe, 'outside authenticated sparse'):
                            run(req)

    def test_byte_exact_authenticated_care_map_can_be_regenerated(self):
        # Historical signed-source values from the independent Worklane 3 fixture.
        original_ranges = {
            'odm': '2,0,472',
            'product': '18,0,46,511,32771,33279,65537,66045,98307,98815,130453,163840,163843,229376,229379,294912,294915,589824,589825',
            'system': '20,0,212,489,32771,33257,65537,66023,98307,98793,131073,131559,163843,164329,196609,197095,229379,229865,255080,262144,262145',
            'system_ext': '12,0,240,430,32771,33198,65537,65964,98307,98734,112735,131072,131073',
            'vendor': '2,0,189386',
            'vendor_dlkm': '2,0,6575',
        }
        encoded = serialize_map({
            name: PartitionEntry(name, ranges, f'ro.{name}.build.fingerprint', STOCK)
            for name, ranges in original_ranges.items()
        })
        self.assertEqual(len(encoded), 1086)
        self.assertEqual(sha(encoded), 'e903a2c0e4a71aaadf757d7d479a6be2ca80939a084c1832796db61c75e6e147')

    def test_output_protocol_cli_and_duplicate_json_field_rejected(self):
        argv = [sys.executable, str(Path(__file__).resolve().parents[1] / 'research' / 'care_map_candidate.py'), '--json']
        req = conformance_request()
        proc = subprocess.run(argv, input=json.dumps(req), text=True, capture_output=True, timeout=15)
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual('4,0,2,4,7', json.loads(proc.stdout)['ranges'])
        proc = subprocess.run(argv, input='{"schema":"x","schema":"y"}',
                              text=True, capture_output=True, timeout=15)
        self.assertNotEqual(0, proc.returncode)
        self.assertIn('duplicate JSON', proc.stderr)


if __name__ == '__main__':
    unittest.main()