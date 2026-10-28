"""Local recovery must validate bytes, preserve provenance and fail closed offline."""
from pathlib import Path
import sys
import tempfile
import unittest
import contextlib
import io
import struct
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'data'))
from test_manifest_recovery import make_object, row, asset
import recover_manifest_sources as recovery
from recovery_imports import RecoveredCdnCollection, RecoveredHOnlyCollection
from local_asset_source import LocalAssetSource
import warframe_install_to_patch as w

class LocalAssetTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.local = self.root / 'samples'
        self.work = self.root / 'work'
        self.local.mkdir()
        self.work.mkdir()
        self.raw = make_object(0xAA, b'video frames')
        self.row = row('/Lotus/Interface/AbilityVideos/Example.bk2', self.raw)

    def put(self, raw=None, name=None, folder=None):
        path = (folder or self.local) / (name or f'Example.bk2!AA_{self.row["expected_hash_base64"]}')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.raw if raw is None else raw)
        return path

    def run_recovery(self, rows=None, offline=True, download=True):
        def no_network(*args, **kwargs):
            self.fail('Unexpected network request')
        with patch.object(recovery, '_report_inputs', return_value=rows or [self.row]):
            return recovery.run(self.work, download=download, local_assets=self.local,
                offline=offline, oodle=object(), head_func=no_network, get_func=no_network)

    def test_offline_partial_recovery_round_trip_and_provenance(self):
        source = self.put()
        before = source.read_bytes()
        missing = row('/Lotus/Objects/Missing', make_object(0xD2))
        result = self.run_recovery([self.row, missing])
        self.assertEqual(result['summary']['fully_verified'], 1)
        self.assertEqual(result['summary']['validated_local_assets'], 1)
        self.assertEqual(result['summary']['unavailable_or_failed'], 1)
        self.assertEqual(result['objects'][1]['status'], 'unresolved')
        self.assertFalse(result['network_enabled'])
        self.assertEqual(result['objects'][0]['provenance']['source_path'], str(source))
        collection = RecoveredCdnCollection(self.work / recovery.RECOVERY_DIR / 'recovered-videos')
        self.assertEqual(collection.validate_asset(asset(self.row), object()), self.raw)
        self.assertEqual(source.read_bytes(), before)
        self.assertIn('provenance', collection.rows[('0', self.row['logical_path'])])
        # The staged copy is independently revalidated before export.
        copied = collection._expected_file(collection.rows[('0', self.row['logical_path'])], asset(self.row))
        copied.write_bytes(self.raw[:-1] + bytes([self.raw[-1] ^ 1]))
        with self.assertRaises(w.ExportError):
            collection.validate_asset(asset(self.row), object())

    def test_corrupt_local_candidate_never_falls_back_to_network(self):
        self.put(self.raw[:-1] + bytes([self.raw[-1] ^ 1]))
        result = self.run_recovery(offline=False)
        self.assertEqual(result['objects'][0]['status'], 'local-source-rejected')
        self.assertIn('CRC32C', result['objects'][0]['error'])
        self.assertEqual(result['summary']['unavailable_or_failed'], 1)
        self.assertFalse((self.work / recovery.RECOVERY_DIR).exists())

    def test_ambiguous_files_are_rejected(self):
        self.put()
        self.put(folder=self.local / 'duplicate')
        result = self.run_recovery()
        self.assertEqual(result['objects'][0]['status'], 'local-source-rejected')
        self.assertIn('Ambiguous', result['objects'][0]['error'])

    def test_wrong_size_and_type_are_rejected(self):
        self.put(self.raw + b'extra')
        result = self.run_recovery()
        self.assertIn('size', result['objects'][0]['error'])
        next(self.local.iterdir()).unlink()
        self.put(name=f'Example.bk2!D2_{self.row["expected_hash_base64"]}')
        result = self.run_recovery()
        self.assertEqual(result['objects'][0]['status'], 'local-source-rejected')

    def test_valid_crc_with_wrong_h_digest_is_rejected(self):
        raw = bytearray(self.raw)
        raw[17] ^= 1  # First H byte, keeping both filename and declared sizes.
        raw[-4:] = struct.pack('<I', w.crc32c(bytes(raw[:-4])))
        self.put(bytes(raw))
        result = self.run_recovery()
        self.assertEqual(result['objects'][0]['status'], 'local-source-rejected')
        self.assertIn('hash does not match', result['objects'][0]['error'])

    def test_existing_validated_copy_can_be_rechecked(self):
        self.put()
        self.run_recovery()
        result = self.run_recovery()
        self.assertEqual(result['summary']['fully_verified'], 1)

    def test_offline_reuse_without_original_folder(self):
        self.put()
        first = self.run_recovery()
        with patch.object(recovery, '_report_inputs', return_value=[self.row]):
            result = recovery.run(self.work, download=True, offline=True, oodle=object(),
                head_func=lambda *a, **k: self.fail('offline HEAD'),
                get_func=lambda *a, **k: self.fail('offline GET'))
        self.assertEqual(result['summary']['fully_verified'], 1)
        self.assertTrue(result['objects'][0]['reused_staged_copy'])
        self.assertEqual(result['objects'][0]['provenance'], first['objects'][0]['provenance'])

    def test_offline_reuse_rejects_tampered_copy(self):
        self.put()
        self.run_recovery()
        source = RecoveredCdnCollection(self.work / recovery.RECOVERY_DIR / 'recovered-videos')
        copied = source._expected_file(source.rows[('0', self.row['logical_path'])], asset(self.row))
        copied.write_bytes(self.raw[:-1] + bytes([self.raw[-1] ^ 1]))
        with patch.object(recovery, '_report_inputs', return_value=[self.row]), self.assertRaises(w.ExportError):
            recovery.run(self.work, download=True, offline=True, oodle=object())

    def test_offline_h_only_reuse_does_not_need_peer_types(self):
        raw = make_object(0xD2)
        item = row('/Lotus/Objects/Material', raw)
        self.put(raw, f'Material!D2_{item["expected_hash_base64"]}')
        self.run_recovery([item])
        with patch.object(recovery, '_report_inputs', return_value=[item]):
            result = recovery.run(self.work, download=True, offline=True, oodle=object())
        self.assertEqual(result['summary']['fully_verified'], 1)
        self.assertEqual(result['objects'][0]['cdn_type_hex'], 'D2')

    def test_unreadable_is_distinct_from_missing(self):
        self.put()
        with patch.object(LocalAssetSource, 'read', side_effect=PermissionError('cannot read')):
            result = self.run_recovery()
        self.assertEqual(result['objects'][0]['status'], 'local-source-unreadable')

    def test_probe_validates_without_staging_assets(self):
        self.put()
        result = self.run_recovery(download=False)
        self.assertEqual(result['objects'][0]['status'], 'local-asset-validated')
        self.assertEqual(result['summary']['fully_verified'], 1)
        self.assertFalse((self.work / recovery.RECOVERY_DIR).exists())

    def test_h_only_type_is_validated_from_supplied_object(self):
        raw = make_object(0xD2)
        item = row('/Lotus/Objects/Material', raw)
        self.put(raw, f'Material!D2_{item["expected_hash_base64"]}')
        result = self.run_recovery([item])
        self.assertEqual(result['summary']['fully_verified'], 1)
        source = RecoveredHOnlyCollection(self.work / recovery.RECOVERY_DIR / 'recovered-h-only')
        self.assertEqual(source.validate_asset(asset(item), object()), (raw, 0xD2))

    def test_overlapping_workspace_refused(self):
        work = self.local / 'work'
        work.mkdir()
        with self.assertRaisesRegex(w.ExportError, 'overlap'):
            recovery.run(work, download=True, local_assets=self.local, offline=True)

    def test_public_offline_options_and_network_conflicts(self):
        import install_to_patch
        args = ['-t', 'target', '-b', 'base', '-P', 'output', '--offline',
            '--local-assets', str(self.local)]
        parsed = install_to_patch.parser().parse_args(args)
        self.assertTrue(parsed.offline)
        self.assertEqual(parsed.local_assets, self.local)
        for more in (['-a', '-c'], ['-H', 'archive']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                install_to_patch.main(args + more)
            self.assertEqual(raised.exception.code, 2)

if __name__ == '__main__':
    unittest.main()
