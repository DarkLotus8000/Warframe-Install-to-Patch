"""Manifest-based recovery: independent of U44.0.0's specific missing objects."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'data'))

import compare_sources as comparison
import inspect_missing_source as source_scan
import source_inventory as inventory
import recover_manifest_sources as recovery
import recover_remaining_h_only as h_only
from recovery_imports import RecoveredCdnCollection, RecoveredHOnlyCollection, ExactSourceCollection
import warframe_install_to_patch as w

DIGEST = b'0123456789abcdef'

def make_object(type_id: int, f: bytes = b'') -> bytes:
    header = DIGEST + struct.pack('<III', 20, type_id, 1)
    payload = w.SHCC_PREAMBLE + b''.join(
        struct.pack('<BII', 0, len(x), len(x)) + x for x in (header, b'', f))
    return payload + b'\x52' + struct.pack('<I', w.crc32c(payload + b'\x52'))

def row(path: str, raw: bytes) -> dict:
    is_video = path.lower().endswith('.bk2')
    return {'namespace': '0', 'logical_path': path,
        'expected_hash_base64': w.b64m_encode(DIGEST),
        'expected_cdn_size_bytes': len(raw), 'manifest_section': 'stripped',
        'manifest_flags': '0xA0000000' if is_video else '0x20000000',
        'required_pieces': ['F'] if is_video else [],
        'category': 'video-preview' if is_video else 'non-video-resource'}

def asset(r: dict) -> w.ManifestAsset:
    return w.ManifestAsset(r['namespace'], 'stripped', r['logical_path'], DIGEST,
        int(r['manifest_flags'], 16) | r['expected_cdn_size_bytes'])

class TestManifestDrivenRecovery(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / 'work'
        self.project.mkdir()
        self.source = self.root / 'source'
        self.content = self.source / 'OpenWF' / 'Content'
        self.content.mkdir(parents=True)
        self.oodle = object()

    def put(self, r: dict, type_id: int, raw: bytes) -> Path:
        path = w._safe_output_path(self.content, r['namespace'],
            r['logical_path'], type_id, r['expected_hash_base64'])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def test_v01_inventory_is_accepted_by_base_inheritance(self):
        report = {'report_version': w.VERSION, 'base_cache': str(self.root),
            'summary': {'source_missing': 0}, 'missing_objects': []}
        with patch.object(w, 'find_cache_windows_dir', return_value=self.root), \
             patch.object(w, 'scan_cache', return_value={}), \
             patch.object(w, 'Oodle', return_value=self.oodle):
            result = source_scan.verify_base_inheritance(report, self.root)
            self.assertEqual(result['version'], '0.1')
            self.assertEqual(result['summary']['base_read_error'], 0)
            with self.assertRaises(w.ExportError):
                source_scan.verify_base_inheritance(dict(report, report_version='0.2.17'), self.root)

    def test_absent_source_patch_is_supported(self):
        raw = make_object(0xAA, b'frames')
        for count in (0, 2):
            rows = [row(f'/Lotus/Interface/AbilityVideos/Future{i}.bk2', raw)
                for i in range(count)]
            with self.subTest(count=count):
                doc = comparison.compare(rows, None, self.oodle)
                self.assertEqual(doc['summary']['exact_objects_absent'], count)
                self.assertEqual(doc['summary']['exact_objects_verified'], 0)
                self.assertEqual(doc['summary']['exact_objects_rejected'], 0)

    def test_recovery_inventory_rejects_conflicting_flags(self):
        raw = make_object(0xD2)
        good = row('/Lotus/Objects/Generated/Material', raw)
        inventory.validate_recovery_inventory([good])
        with self.assertRaises(w.ExportError):
            inventory.validate_recovery_inventory([good, good])
        with self.assertRaises(w.ExportError):
            inventory.validate_recovery_inventory([dict(good, manifest_flags='0xA0000000', required_pieces=['F'])])

    def test_public_exporter_allows_no_source_patch(self):
        import install_to_patch
        args = install_to_patch.parser().parse_args(
            ['-t', str(self.root), '-b', str(self.source), '-P', str(self.project / 'output')])
        self.assertIsNone(args.u4401)

    def test_comparison_discovers_exact_nonvideo_type_without_pins(self):
        for typ in (0xD2, 0xC3):
            with self.subTest(cdn_type=typ):
                raw = make_object(typ)
                r = row(f'/Lotus/Generated/Material{typ}', raw)
                self.put(r, typ, raw)
                result = comparison.compare([r], self.source, self.oodle)
                doc = result['objects'][0]
                self.assertEqual(doc['status'], 'exact-object-verified')
                self.assertEqual(doc['cdn_type_hex'], f'{typ:X}')
                self.assertEqual(doc['manifest_hash'], r['expected_hash_base64'])
                self.assertEqual(result['summary']['required_missing_objects'], 1)

    def test_bad_source_is_rejected_not_silently_downloaded(self):
        raw = make_object(0xD2)
        r = row('/Lotus/Generated/Bad', raw)
        self.put(r, 0xD2, raw[:-1] + b'!')
        result = comparison.compare([r], self.source, self.oodle)
        self.assertEqual(result['summary']['exact_objects_rejected'], 1)
        self.assertEqual(result['objects'][0]['status'], 'exact-object-rejected')

    def test_missing_count_is_not_fixed_to_three(self):
        for n in (0, 1, 5):
            with self.subTest(count=n):
                rows = [row(f'/Lotus/AbilityVideos/Future{i}.bk2', make_object(0xAA, b'frames'))
                    for i in range(n)]
                report = comparison.compare(rows, self.source, self.oodle)
                self.assertEqual(report['summary']['required_missing_objects'], n)
                self.assertEqual(report['summary']['exact_objects_absent'], n)

    def test_exact_source_and_cdn_recovery_end_to_end(self):
        raw_video = make_object(0xAA, b'frames')
        raw_h = make_object(0xD2)
        source_video = row('/Lotus/Interface/AbilityVideos/AlphaPower1_s.bk2', raw_video)
        missing_video = row('/Lotus/Interface/AbilityVideos/BetaPower1_s.bk2', raw_video)
        missing_h = row('/Lotus/Objects/Generated/Resource', raw_h)
        self.put(source_video, 0xAA, raw_video)
        rows = [source_video, missing_video, missing_h]
        expected = {
            recovery.triage.make_cdn_url(missing_video, 0xAA): raw_video,
            recovery.triage.make_cdn_url(missing_h, 0xD2): raw_h,
        }
        def head(url, *, timeout):
            body = expected.get(url)
            return {'http_status': 200 if body is not None else 404,
                'content_length': len(body) if body is not None else None}
        def get(url, size, timeout):
            return expected[url]
        fake_peers = [{'namespace': '0', 'logical_path': missing_h['logical_path'],
            'peer_candidates': [{'type_hex': 'D2'}]}]
        with patch.object(recovery.inventory, 'load_manifest_inventory', return_value=({}, rows)), \
             patch.object(recovery, '_report_inputs', return_value=[missing_video, missing_h]), \
             patch.object(h_only, 'infer_peer_types', return_value=fake_peers):
            result = recovery.run(self.project, download=True, timeout=1, retries=1,
                fresh_sources=(self.root, self.root, self.source), oodle=self.oodle,
                head_func=head, get_func=get)
        self.assertEqual(result['summary']['fully_verified'], 2)
        self.assertEqual(result['summary']['required'], 2)
        self.assertEqual(result['summary']['unavailable_or_failed'], 0)
        folder = self.project / recovery.RECOVERY_DIR
        videos = RecoveredCdnCollection(folder / 'recovered-videos')
        headers = RecoveredHOnlyCollection(folder / 'recovered-h-only')
        self.assertEqual(videos.validate_asset(asset(missing_video), self.oodle), raw_video)
        self.assertEqual(headers.validate_asset(asset(missing_h), self.oodle), (raw_h, 0xD2))
        source_comp = ExactSourceCollection(self.source, self.project / recovery.COMPARISON_REPORT)
        self.assertEqual(source_comp.validate_asset(asset(source_video), self.oodle), (raw_video, 0xAA))

    def test_single_candidate_get_verifies_inconclusive_head(self):
        raw = make_object(0xAA, b'frames')
        for http_status, length in ((405, None), (501, None), (200, None)):
            with self.subTest(status=http_status, content_length=length):
                item = row(f'/Lotus/Interface/AbilityVideos/OnlyCandidate{http_status}_s.bk2', raw)
                requests = []

                def head(_url, *, timeout):
                    return {'http_status': http_status, 'content_length': length}

                def get(_url, expected_size, timeout):
                    requests.append(expected_size)
                    return raw

                with patch.object(recovery.inventory, 'load_manifest_inventory', return_value=({}, [item])), \
                     patch.object(recovery, '_report_inputs', return_value=[item]):
                    result = recovery.run(self.project, download=True, timeout=1, retries=1,
                        fresh_sources=(self.root, self.root, None), oodle=self.oodle,
                        head_func=head, get_func=get)
                self.assertEqual(result['summary']['fully_verified'], 1)
                self.assertEqual(result['objects'][0]['head_inconclusive']['http_status'], http_status)
                self.assertEqual(requests, [len(raw)])

    def test_inconclusive_head_never_downloaded_in_probe_mode(self):
        raw = make_object(0xAA, b'frames')
        item = row('/Lotus/Interface/AbilityVideos/ProbeOnly_s.bk2', raw)

        def no_get(*args):
            self.fail('HEAD-only mode must never issue GET')

        with patch.object(recovery.inventory, 'load_manifest_inventory', return_value=({}, [item])), \
             patch.object(recovery, '_report_inputs', return_value=[item]):
            result = recovery.run(self.project, download=False, timeout=1,
                fresh_sources=(self.root, self.root, None), oodle=self.oodle,
                head_func=lambda url, timeout: {'http_status': 405, 'content_length': None},
                get_func=no_get)
        self.assertEqual(result['summary']['fully_verified'], 0)
        self.assertEqual(result['summary']['unavailable_or_failed'], 1)

    def test_known_wrong_size_or_missing_url_never_downloads(self):
        raw = make_object(0xAA, b'frames')
        item = row('/Lotus/Interface/AbilityVideos/WrongLength_s.bk2', raw)

        def no_get(*args):
            self.fail('Known wrong or unavailable CDN object must not be downloaded')

        for status, length in ((200, len(raw) + 1), (404, None)):
            with self.subTest(status=status):
                with patch.object(recovery.inventory, 'load_manifest_inventory', return_value=({}, [item])), \
                     patch.object(recovery, '_report_inputs', return_value=[item]):
                    result = recovery.run(self.project, download=True, timeout=1,
                        fresh_sources=(self.root, self.root, None), oodle=self.oodle,
                        head_func=lambda url, timeout: {'http_status': status, 'content_length': length},
                        get_func=no_get)
                self.assertEqual(result['summary']['fully_verified'], 0)
                self.assertEqual(result['summary']['unavailable_or_failed'], 1)

    def test_two_matching_types_are_ambiguous_and_never_downloaded(self):
        raw = make_object(0xD2)
        r = row('/Lotus/Objects/FutureAsset', raw)
        peers = [{ 'namespace': '0', 'logical_path': r['logical_path'],
            'peer_candidates': [{'type_hex': 'D2'}, {'type_hex': 'D1'}]}]
        calls = []
        def head(url, *, timeout):
            return {'http_status': 200, 'content_length': len(raw)}
        def get(*_args):
            calls.append(True)
            return raw
        with patch.object(recovery.inventory, 'load_manifest_inventory', return_value=({}, [r])), \
             patch.object(recovery, '_report_inputs', return_value=[r]), \
             patch.object(h_only, 'infer_peer_types', return_value=peers):
            result = recovery.run(self.project, download=True, timeout=1, retries=1,
                fresh_sources=(self.root, self.root, self.source), oodle=self.oodle,
                head_func=head, get_func=get)
        self.assertEqual(result['summary']['fully_verified'], 0)
        self.assertEqual(result['summary']['unavailable_or_failed'], 1)
        self.assertEqual(calls, [])

    def test_failed_get_is_reported_and_other_objects_are_checked(self):
        raw = make_object(0xAA, b'frames')
        first = row('/Lotus/Interface/AbilityVideos/Failed_s.bk2', raw)
        second = row('/Lotus/Interface/AbilityVideos/Good_s.bk2', raw)
        urls = {recovery.triage.make_cdn_url(x, 0xAA): x for x in (first, second)}
        requests = []

        def head(url, *, timeout):
            return {'http_status': 200, 'content_length': len(raw)}

        def get(url, expected_size, timeout):
            requests.append(url)
            if urls[url] is first:
                raise OSError('simulated disconnected CDN')
            return raw

        with patch.object(recovery.inventory, 'load_manifest_inventory', return_value=({}, [first, second])), \
             patch.object(recovery, '_report_inputs', return_value=[first, second]):
            result = recovery.run(self.project, download=True, timeout=1, retries=1,
                fresh_sources=(self.root, self.root, None), oodle=self.oodle,
                head_func=head, get_func=get)
        self.assertEqual(len(requests), 2)
        self.assertEqual(result['summary']['required'], 2)
        self.assertEqual(result['summary']['fully_verified'], 1)
        self.assertEqual(result['summary']['unavailable_or_failed'], 1)
        self.assertEqual(result['objects'][0]['status'], 'download-failed')
        self.assertEqual(result['objects'][0]['download_attempts'][0]['status'], 'network-failed')
        self.assertEqual(result['objects'][1]['status'], 'recovered-validated')
        self.assertTrue((self.project / recovery.RECOVERY_REPORT).is_file())
        self.assertEqual(json.loads((self.project / recovery.RECOVERY_REPORT).read_text())['summary'],
            result['summary'])

    def test_h_only_recovery_report_rejects_case_collisions(self):
        folder = self.project / 'h-only'
        folder.mkdir()
        shared = dict(namespace='0', expected_hash_base64=w.b64m_encode(DIGEST),
            expected_cdn_size_bytes=100, manifest_flags='0x20000000',
            cdn_type_hex='D2', sha256='0' * 64, status='recovered-validated')
        rows = [dict(shared, logical_path='/Lotus/Fx/Same'),
            dict(shared, logical_path='/lotus/fx/same')]
        report = {'version': w.VERSION, 'kind': 'h-only-cdn-recovery',
            'summary': {'selected': 2, 'recovered_validated': 2, 'failed': 0},
            'objects': rows}
        (folder / h_only.REPORT_NAME).write_text(json.dumps(report), encoding='utf-8')
        with self.assertRaisesRegex(w.ExportError, 'case-conflicting'):
            RecoveredHOnlyCollection(folder)

    def test_zero_missing_objects_needs_no_source_or_cdn(self):
        def no_network(*args, **kwargs):
            self.fail('No network request is needed when nothing is missing')
        with patch.object(recovery.inventory, 'load_manifest_inventory', return_value=({}, [])), \
             patch.object(recovery, '_report_inputs', return_value=[]):
            report = recovery.run(self.project, download=True, timeout=1, retries=1,
                fresh_sources=(self.root, self.root, None), oodle=self.oodle,
                head_func=no_network, get_func=no_network)
        self.assertEqual(report['summary']['required'], 0)
        self.assertEqual(report['summary']['fully_verified'], 0)
        self.assertEqual(report['summary']['unavailable_or_failed'], 0)
        self.assertFalse((self.project / recovery.RECOVERY_DIR).exists())
        self.assertTrue((self.project / recovery.RECOVERY_REPORT).is_file())

    def test_source_patch_is_not_labeled_as_u4401_in_messages(self):
        text = (ROOT / 'data' / 'warframe_install_to_patch.py').read_text(encoding='utf-8')
        self.assertNotIn('U44.0.1', text)
        self.assertIn('Exact source patch:', text)
        self.assertIn('Source-patch exact imports:', text)

    def test_manifest_namespace_validation(self):
        for name in ('0', '0_en', '0_de', '0_XX', '9', 'A'):
            with self.subTest(namespace=name):
                self.assertEqual(w._validate_manifest_namespace(name), name)
        for name in ('', '../0', '0/../9', '0_foo/bar', 'b', 'B', '9_en', None):
            with self.subTest(invalid=name), self.assertRaises(w.ExportError):
                w._validate_manifest_namespace(name)
        raw = make_object(0xD2)
        unsafe = dict(row('/Lotus/Objects/Material', raw), namespace='../outside')
        with self.assertRaises(w.ExportError):
            inventory.validate_recovery_inventory([unsafe])

    def test_exact_source_import_accepts_manifest_namespace(self):
        raw = make_object(0xC3)
        item = dict(row('/Lotus/Graphics/ShaderMaterial', raw), namespace='9')
        self.put(item, 0xC3, raw)
        comparison_doc = comparison.compare([item], self.source, self.oodle)
        self.assertEqual(comparison_doc['objects'][0]['status'], 'exact-object-verified')
        path = self.project / recovery.COMPARISON_REPORT
        inventory.save_report(path, comparison_doc)
        source = ExactSourceCollection(self.source, path)
        self.assertEqual(source.validate_asset(asset(item), self.oodle), (raw, 0xC3))

    def test_recovered_video_import_accepts_manifest_namespace(self):
        raw = make_object(0xAA, b'frames')
        item = dict(row('/Lotus/Interface/AbilityVideos/Localized.bk2', raw), namespace='0_en')
        with patch.object(recovery.inventory, 'load_manifest_inventory', return_value=({}, [item])), \
             patch.object(recovery, '_report_inputs', return_value=[item]):
            result = recovery.run(self.project, download=True, timeout=1, retries=1,
                fresh_sources=(self.root, self.root, None), oodle=self.oodle,
                head_func=lambda url, timeout: {'http_status': 200, 'content_length': len(raw)},
                get_func=lambda url, size, timeout: raw)
        self.assertEqual(result['summary']['fully_verified'], 1)
        folder = self.project / recovery.RECOVERY_DIR / 'recovered-videos'
        self.assertEqual(RecoveredCdnCollection(folder).validate_asset(asset(item), self.oodle), raw)

    def test_h_only_peer_types_do_not_cross_namespaces(self):
        raw_zero = make_object(0xD2)
        raw_dx11 = make_object(0xC3)
        from types import SimpleNamespace
        def peer(path, data):
            return SimpleNamespace(logical_path=path, package='Graphics', raw=data)
        path = '/Lotus/Graphics/Material'
        cache = {
            ('0', path): {'H': [peer(path, DIGEST + struct.pack('<III', 20, 0xD2, 1))]},
            ('9', path): {'H': [peer(path, DIGEST + struct.pack('<III', 20, 0xC3, 1))]},
        }
        zero = dict(row(path + 'Future', raw_zero), namespace='0')
        dx11 = dict(row(path + 'Future', raw_dx11), namespace='9')
        with patch.object(w, 'decompress_cache_entry', side_effect=lambda entry, oodle: entry.raw):
            inferred = h_only.infer_peer_types(self.root, [zero, dx11],
                max_samples=2, cache_index=cache, oodle=self.oodle)
        self.assertEqual(inferred[0]['peer_candidates'][0]['type_hex'], 'D2')
        self.assertEqual(inferred[1]['peer_candidates'][0]['type_hex'], 'C3')

    def test_no_historical_object_names_are_pinned_in_production(self):
        names = (
            'SonarWeakSpotCapsuleMat', 'NarinPower4_s.bk2',
            'HubParallax/Building01a', 'VoidArmageddonRewards',
            'VoidCascadeRewards', 'VoidFloodRewards',
            'ZarimanExterminateRewards', 'ZarimanMobileDefenseRewards',
        )
        for path in (ROOT / 'data').glob('*.py'):
            text = path.read_text(encoding='utf-8')
            for name in names:
                self.assertNotIn(name, text, f'{path.name} pins {name}')

if __name__ == '__main__':
    unittest.main()
