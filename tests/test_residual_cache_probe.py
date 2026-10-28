"""Read-only recovery diagnostics for TOC tombstones and surviving video F pieces."""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'data'))

import inspect_missing_source as probe
import warframe_install_to_patch as w

class ResidualCacheProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cache = Path(self.temp.name) / 'Cache.Windows'
        self.cache.mkdir()
        self.path = '/SampleVideo.bk2'
        self.digest = hashlib.md5(b'example-h-data').digest()
        self.row = {'namespace': '0', 'logical_path': self.path,
            'expected_hash_base64': w.b64m_encode(self.digest),
            'manifest_hbf_flags_hex': '0xA0000000'}

    def make_toc(self, kind: str, body: bytes, *, deleted: bool,
        name: str = 'SampleVideo.bk2', package: str = 'Misc'):
        cache = self.cache / f'{kind}.{package}.cache'
        cache.write_bytes(body)
        toc = self.cache / f'{kind}.{package}.toc'
        header = struct.pack('<II', w.TOC_MAGIC, 16)
        record = w.TOC_ENTRY.pack(0, 0 if deleted else 1, len(body), len(body),
            0, 0, name.encode('ascii').ljust(64, b'\x00'))
        toc.write_bytes(header + record)
        return toc

    def test_tombstones_hidden_from_live_cache_reader(self):
        toc = self.make_toc('H', self.digest + b'resource', deleted=True)
        self.assertEqual(list(w.iter_toc_entries(toc, 'H', 'Misc')), [])
        deleted = list(w.iter_toc_entries(toc, 'H', 'Misc', deleted_only=True))
        self.assertEqual(len(deleted), 1)
        self.assertEqual(deleted[0].logical_path, self.path)

    def test_stale_h_and_f_are_candidates_not_proven_recoveries(self):
        self.make_toc('H', self.digest + b'header', deleted=True)
        self.make_toc('F', b'video frames', deleted=True)
        index = probe._scan_residual_entries(self.cache, {('0', self.path)})
        result = probe._probe_residual_source(index, self.row, object())
        self.assertEqual(result['status'], 'candidate-matching-h-and-required-pieces')
        self.assertEqual(result['toc_entries']['H']['deleted'], 1)
        self.assertEqual(result['toc_entries']['F']['deleted'], 1)
        self.assertEqual(len(result['same_package_h_f_pairs']), 1)

    def test_surviving_f_cannot_prove_missing_h(self):
        self.make_toc('H', b'wrongdigest12345' + b'header', deleted=True)
        self.make_toc('F', b'video frames', deleted=False)
        index = probe._scan_residual_entries(self.cache, {('0', self.path)})
        result = probe._probe_residual_source(index, self.row, object())
        self.assertEqual(result['status'], 'readable-f-without-matching-h')
        self.assertEqual(result['matching_h_entries'], [])
        self.assertEqual(len(result['readable_f_entries']), 1)

    def test_missing_f_does_not_count_as_video_recovery(self):
        self.make_toc('H', self.digest + b'header', deleted=True)
        index = probe._scan_residual_entries(self.cache, {('0', self.path)})
        result = probe._probe_residual_source(index, self.row, object())
        self.assertEqual(result['status'], 'matching-h-but-required-f-missing')

    def test_deleted_record_cannot_recover_out_of_bounds_payload(self):
        self.make_toc('H', self.digest + b'header', deleted=True)
        toc = self.cache / 'H.Misc.toc'
        data = bytearray(toc.read_bytes())
        # Record cache-offset starts at byte 8 of the TOC.
        struct.pack_into('<q', data, 8, 0x400000)
        toc.write_bytes(data)
        index = probe._scan_residual_entries(self.cache, {('0', self.path)})
        result = probe._probe_residual_source(index, self.row, object())
        self.assertEqual(result['status'], 'no-matching-readable-pieces')
        self.assertTrue(result['read_errors'])

if __name__ == '__main__':
    unittest.main()
