"""Regression tests for outer Oodle streams with raw-first blocks."""
from __future__ import annotations

from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'data'))

import warframe_install_to_patch as w

class FakeOodle:
    def __init__(self, prefix: bytes, plain: bytes, codec=13, independent=True):
        self.prefix = prefix
        self.plain = plain
        self.codec = codec
        self.independent = independent
        self.compress_call = None

    def compress(self, data: bytes, compressor: int, level: int) -> bytes:
        self.compress_call = (data, compressor, level)
        return self.prefix

    def identify_compressed_stream(self, data: bytes) -> tuple[int, bool]:
        assert data == self.prefix
        return self.codec, self.independent

    def decompress(self, data: bytes, expected_size: int) -> bytes:
        assert data == self.prefix and expected_size == len(self.plain)
        return self.plain

class TestOuterOodleRawFirstChunk(unittest.TestCase):
    def setUp(self):
        # A valid synthetic direct object. Outer encoding excludes its 5-byte trailer.
        h = b'header' * 8
        body = w.SHCC_PREAMBLE + struct.pack('<BII', 0, len(h), len(h)) + h
        body += struct.pack('<BII', 0, 0, 0) * 2
        self.plain = body
        self.direct = body + b'\x52' + struct.pack('<I', w.crc32c(body + b'\x52'))

    def test_accept_raw_first_oodle_block(self):
        # A 0xCC header indicates the first Oodle block is stored verbatim.
        # The encoder can legitimately produce this for incompressible data.
        prefix = b'\xcc\x0c' + b'fixture'
        oodle = FakeOodle(prefix, self.plain)
        result = w.try_encode_outer_oodle(self.direct, len(prefix) + 9, oodle)
        self.assertIsNotNone(result)
        encoded, (codec, level) = result
        self.assertEqual((codec, level), (13, 4))
        self.assertEqual(oodle.compress_call, (self.plain, 13, 4))
        self.assertEqual(encoded[:2], b'\xcc\x0c')
        self.assertEqual(encoded[-5], 0x43)
        self.assertEqual(int.from_bytes(encoded[-9:-5], 'little'), len(self.plain))
        self.assertEqual(int.from_bytes(encoded[-4:], 'little'), w.crc32c(encoded[:-4]))

    def test_accept_compressed_first_oodle_block(self):
        prefix = b'\x8c\x0c' + b'fixture'
        self.assertIsNotNone(w.try_encode_outer_oodle(
            self.direct, len(prefix) + 9, FakeOodle(prefix, self.plain)))

    def test_reject_wrong_codec_or_independence(self):
        prefix = b'\xcc\x0c' + b'fixture'
        for codec, independent in ((8, True), (13, False)):
            with self.subTest(codec=codec, independent=independent):
                oodle = FakeOodle(prefix, self.plain, codec=codec, independent=independent)
                self.assertIsNone(w.try_encode_outer_oodle(self.direct, len(prefix) + 9, oodle))

    def test_reject_wrong_manifest_size(self):
        prefix = b'\xcc\x0c' + b'fixture'
        self.assertIsNone(w.try_encode_outer_oodle(
            self.direct, len(prefix) + 10, FakeOodle(prefix, self.plain)))

    def test_reject_invalid_round_trip(self):
        prefix = b'\xcc\x0c' + b'fixture'
        oodle = FakeOodle(prefix, b'Z' + self.plain[1:])
        # Fake decompressor returns different data, demonstrating the byte check.
        self.assertIsNone(w.try_encode_outer_oodle(self.direct, len(prefix) + 9, oodle))

if __name__ == '__main__':
    unittest.main()
