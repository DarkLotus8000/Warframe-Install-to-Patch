"""Regression coverage for pristine H.Cache.bin empty B/F chunk sentinels."""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'data'))

import warframe_install_to_patch as w

class TestHCacheMetadataSentinels(unittest.TestCase):
    HEADER = b'H.Cache header regression fixture'

    @staticmethod
    def make_object(header: bytes, b_size: int, f_size: int,
            *, b_payload: bytes = b'', f_payload: bytes = b'') -> bytes:
        h = struct.pack('<BII', 0, len(header), len(header)) + header
        b = struct.pack('<BII', 0, b_size, len(b_payload)) + b_payload
        f = struct.pack('<BII', 0, f_size, len(f_payload)) + f_payload
        body = w.SHCC_PREAMBLE + h + b + f + b'\x52'
        return body + struct.pack('<I', w.crc32c(body))

    def test_both_accepted_empty_chunk_forms(self):
        for b_size in (0, 0xFFFFFFFF):
            for f_size in (0, 0xFFFFFFFF):
                with self.subTest(b_size=b_size, f_size=f_size):
                    raw = self.make_object(self.HEADER, b_size, f_size)
                    expected = hashlib.sha256(raw).hexdigest()
                    self.assertEqual(w.verify_h_cache_metadata_object(raw, self.HEADER, None), expected)

    def test_internal_framed_h_chunk_with_empty_sentinels(self):
        # Exercise codec 2 decoding without depending on Windows Oodle DLL.
        # A Warframe frame may store a block verbatim (packed == unpacked).
        header = self.HEADER
        frame_header = ((0x80000000 | (len(header) << 2)).to_bytes(4, 'big')
            + ((len(header) << 5) | 1).to_bytes(4, 'big'))
        framed = frame_header + header
        h = struct.pack('<BII', 2, len(header), len(framed)) + framed
        empty = struct.pack('<BII', 0, 0xFFFFFFFF, 0)
        body = w.SHCC_PREAMBLE + h + empty + empty + b'\x52'
        raw = body + struct.pack('<I', w.crc32c(body))
        self.assertEqual(w.verify_h_cache_metadata_object(raw, header, None),
            hashlib.sha256(raw).hexdigest())

    def test_reject_nonempty_b_or_f_chunks(self):
        for kwargs in ({'b_payload': b'X'}, {'f_payload': b'X'}):
            with self.subTest(kwargs=kwargs):
                raw = self.make_object(self.HEADER, 0xFFFFFFFF, 0xFFFFFFFF, **kwargs)
                with self.assertRaisesRegex(w.ExportError, 'B/F slots must be empty'):
                    w.verify_h_cache_metadata_object(raw, self.HEADER, None)

    def test_reject_other_large_sentinels(self):
        for b_size, f_size in ((0xFFFFFFFE, 0xFFFFFFFF),
                (0xFFFFFFFF, 0xFFFFFFFE)):
            raw = self.make_object(self.HEADER, b_size, f_size)
            with self.assertRaisesRegex(w.ExportError, 'B/F slots must be empty'):
                w.verify_h_cache_metadata_object(raw, self.HEADER, None)

    def test_reject_modified_h_cache_header(self):
        raw = self.make_object(self.HEADER, 0xFFFFFFFF, 0xFFFFFFFF)
        with self.assertRaisesRegex(w.ExportError, 'differ from pristine target'):
            w.verify_h_cache_metadata_object(raw, b'other header', None)

    def test_reject_bad_crc(self):
        raw = bytearray(self.make_object(self.HEADER, 0xFFFFFFFF, 0xFFFFFFFF))
        raw[-1] ^= 0x01
        with self.assertRaisesRegex(w.ExportError, 'CRC32C mismatch'):
            w.verify_h_cache_metadata_object(bytes(raw), self.HEADER, None)

if __name__ == '__main__':
    unittest.main()
