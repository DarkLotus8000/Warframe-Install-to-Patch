"""Gap enumeration must not skip overlapping ranges or scan beyond EOF."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'data'))
from probe_unindexed_cache import gaps, select_rows
import warframe_install_to_patch as w

class GapTests(unittest.TestCase):
    def test_requested_count_is_not_build_specific(self):
        for count in (0, 1, 7):
            rows = [{'namespace': '0', 'logical_path': f'/Video{i}.bk2',
                'expected_hash_base64': w.b64m_encode(b'0123456789abcdef'), 'required_pieces': ['F']}
                for i in range(count)]
            residual = {'objects': [dict(namespace=r['namespace'], logical_path=r['logical_path'],
                manifest_hash=r['expected_hash_base64'], required_pieces=r['required_pieces']) for r in rows]}
            self.assertEqual(select_rows(residual, {'missing_objects': rows}), rows)
            if count:
                residual['objects'][0]['required_pieces'] = []
                with self.assertRaises(w.ExportError):
                    select_rows(residual, {'missing_objects': rows})

    def test_overlapping_and_unsorted_ranges(self):
        self.assertEqual(list(gaps(100, [(40, 50), (15, 30), (10, 20)])),
            [(0, 10), (30, 40), (50, 100)])

    def test_empty_and_complete_coverage(self):
        self.assertEqual(list(gaps(10, [])), [(0, 10)])
        self.assertEqual(list(gaps(10, [(0, 10)])), [])

    def test_clip_outside_file(self):
        self.assertEqual(list(gaps(10, [(20, 30)])), [(0, 10)])
        self.assertEqual(list(gaps(10, [(5, 30)])), [(0, 5)])

if __name__ == '__main__':
    unittest.main()
