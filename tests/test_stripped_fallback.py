import sys
import tempfile
import unittest
import struct
from pathlib import Path
import contextlib
import hashlib
import io
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'data'))
import stripped_archive as s
import warframe_install_to_patch as w
import add_stripped

DIGEST=b'0123456789abcdef'
H = DIGEST + struct.pack('<III',0x14,0xAA,1)
F = b'original-preview-frames'

def obj(f=F):
    chunks = [H,b'',f]
    payload=w.SHCC_PREAMBLE + b''.join(struct.pack('<BII',0,len(p),len(p))+p for p in chunks)
    return payload+b'\x52'+struct.pack('<I',w.crc32c(payload+b'\x52'))

class TestSource(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name)
        self.asset=w.ManifestAsset('0','stripped','/Lotus/Fx/Narin/Ability.bk2', DIGEST,
            len(obj()) | w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F)
        self.sources=[]

    def make_source(self, name, raw=obj()):
        root=self.home/name
        content=root/'OpenWF'/'Content'
        content.mkdir(parents=True)
        candidate=w._safe_output_path(content,'0',self.asset.logical_path,0xAA,self.asset.hash_b64)
        candidate.parent.mkdir(parents=True,exist_ok=True)
        if raw is not None:
            candidate.write_bytes(raw)
        self.sources.append((root,content))
        return candidate

    def get(self):
        return s._exact_source_object(self.asset,0xAA,self.sources,None,'target','base')

    def test_first_source_wins_no_network(self):
        self.make_source('u4401')
        self.make_source('u44121')
        with patch.object(w,'_select_h_by_hash',side_effect=w.SourceCoverageError('absent')):
            data,src,evidence=self.get()
        self.assertEqual(src,self.home/'u4401')
        self.assertEqual(data,obj())
        self.assertIn('not-independently-known',evidence)

    def test_type_check_only_decodes_h_and_not_video_f(self):
        # Nonempty F encoded as codec 2 is deliberately malformed here;
        # reading the video type should not decompress irrelevant frames.
        raw = (w.SHCC_PREAMBLE + struct.pack('<BII', 0, len(H), len(H)) + H
               + struct.pack('<BII', 0, 0, 0)
               + struct.pack('<BII', 2, 50, 3) + b'bad'
               + b'\x52' + b'\0' * 4)
        with patch('recover_missing_cdn._unpack_framed_payload',
                side_effect=AssertionError('should not decode F')):
            self.assertEqual(s._decoded_sections(raw, None, kinds='H'), {'H': H})

    def test_conflicting_full_payloads_in_two_sources_rejected(self):
        # Both objects have a valid CRC and the same original H hash/size,
        # but their video F content differs. Do not silently trust either.
        self.make_source('u4401', obj())
        self.make_source('u44121', obj(b'altered!-preview-frames'))
        with patch.object(w, '_select_h_by_hash', side_effect=w.SourceCoverageError('absent')):
            with self.assertRaisesRegex(s.StrippedError, 'Conflicting full CDN payloads'):
                self.get()

    def test_matching_full_payloads_in_two_sources_choose_oldest(self):
        self.make_source('u4401', obj())
        self.make_source('u44121', obj())
        with patch.object(w, '_select_h_by_hash', side_effect=w.SourceCoverageError('absent')):
            data, source, evidence = self.get()
        self.assertEqual(source, self.home / 'u4401')
        self.assertEqual(data, obj())
        self.assertIn('not-independently-known', evidence)

    def test_invalid_second_source_does_not_hide_corruption(self):
        self.make_source('u4401', obj())
        self.make_source('u44121', obj()[:-1] + b'X')
        with patch.object(w, '_select_h_by_hash', side_effect=w.SourceCoverageError('absent')):
            with self.assertRaises(w.ExportError):
                self.get()

    def test_original_f_rejects_same_h_same_size_different_video(self):
        self.make_source('u4401',obj(b'altered!-preview-frames'))
        with patch.object(w,'_select_h_by_hash',return_value=(SimpleNamespace(package='fixture'),H,0xAA)), \
             patch.object(w,'_entries_for', return_value=[]), \
             patch.object(w,'_piece_in_package',side_effect=lambda *_args: 'F' if _args[-1] == 'fixture' and _args[-2] == 'F' else None), \
             patch.object(w,'decompress_cache_entry',side_effect=lambda entry,_: {'F':F}[entry]):
            with self.assertRaisesRegex(s.StrippedError,'F bytes differ'):
                self.get()

    def test_original_f_matches(self):
        self.make_source('u4401')
        with patch.object(w,'_select_h_by_hash',return_value=(SimpleNamespace(package='fixture'),H,0xAA)), \
             patch.object(w,'_entries_for', return_value=[]), \
             patch.object(w,'_piece_in_package',side_effect=lambda *_args: 'F' if _args[-1] == 'fixture' and _args[-2] == 'F' else None), \
             patch.object(w,'decompress_cache_entry',side_effect=lambda entry,_: {'F':F}[entry]):
            data, _, evidence=self.get()
        self.assertEqual(data,obj())
        self.assertEqual(evidence,'pristine-HF-match+base-HF-match')

    def test_partial_original_h_and_f_rejects_changed_frames(self):
        # There is no complete cache object, but retained F bytes are enough
        # to reject a newer preview sharing the same H hash and total length.
        self.make_source('u4401', obj(b'altered!-preview-frames'))
        with patch.object(w, '_select_h_by_hash', return_value=(SimpleNamespace(package='p'), H, 0xAA)), \
             patch.object(w, '_entries_for', return_value=[]), \
             patch.object(w, '_piece_in_package', side_effect=lambda *_args: 'F' if _args[-2:] == ('F', 'p') else None), \
             patch.object(w, 'decompress_cache_entry', return_value=F):
            with self.assertRaisesRegex(s.StrippedError, 'F bytes differ'):
                self.get()

    def test_malformed_commonheader_type_rejected(self):
        altered_header = DIGEST + struct.pack('<III', 0x14, 0xAB, 1)
        bad = w.SHCC_PREAMBLE + b''.join(struct.pack('<BII', 0, len(c), len(c)) + c
            for c in (altered_header, b'', F))
        bad += b'\x52' + struct.pack('<I', w.crc32c(bad + b'\x52'))
        self.make_source('u4401', bad)
        with self.assertRaisesRegex(s.StrippedError, 'Video CommonHeader'):
            self.get()

    def test_source_symlinked_ancestor_inside_root_rejected(self):
        candidate = self.make_source('u4401', None)
        ancestor = candidate.parent
        # Move a regular source subtree and install an in-root junction-like link.
        mirror = ancestor.parent / 'mirror'
        ancestor.rename(mirror)
        try:
            ancestor.symlink_to(mirror, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('no symlink privileges')
        with self.assertRaisesRegex(s.StrippedError, 'Symlinked object or ancestor'):
            self.get()

    def test_partial_h_only_evidence_reports_unknown_video_bytes(self):
        self.make_source('u4401')
        with patch.object(w, '_select_h_by_hash', return_value=(SimpleNamespace(package='p'), H, 0xAA)), \
             patch.object(w, '_entries_for', return_value=[]), \
             patch.object(w, '_piece_in_package', return_value=None):
            _, _, evidence = self.get()
        self.assertIn('original-F-not-independently-known', evidence)

    def test_other_matching_package_f_is_checked(self):
        first = SimpleNamespace(package='first')
        second = SimpleNamespace(package='second')
        def h_selection(index, *_args, **_kwargs):
            if index == 'base':
                raise w.SourceCoverageError('absent')
            return first, H, 0xAA
        def piece(_index, _ns, _path, kind, package):
            return 'bad-F' if kind == 'F' and package == 'second' else None
        with patch.object(w, '_select_h_by_hash', side_effect=h_selection), \
             patch.object(w, '_entries_for', return_value=[first, second]), \
             patch.object(w, '_piece_in_package', side_effect=piece), \
             patch.object(w, 'decompress_cache_entry', side_effect=lambda entry, _: H if entry is second else b'corrupted-frames'):
            with self.assertRaisesRegex(s.StrippedError, 'F bytes differ'):
                s._crosscheck_installed_pieces(self.asset, obj(), 'target', 'base', None)

    def test_different_identity_not_substituted(self):
        exact=self.make_source('u4401',None)
        (exact.parent / exact.name.replace(self.asset.hash_b64, 'different')).write_bytes(obj())
        with patch.object(w,'_select_h_by_hash',side_effect=w.SourceCoverageError('absent')):
            self.assertIsNone(self.get())

    def test_corrupt_exact_candidate_rejected(self):
        self.make_source('u4401',obj()[:-1]+b'X')
        with patch.object(w,'_select_h_by_hash',side_effect=w.SourceCoverageError('absent')):
            with self.assertRaises(w.ExportError): self.get()

    def test_source_overlap_rejected(self):
        self.make_source('u4401')
        with self.assertRaisesRegex(s.StrippedError,'overlaps'):
            s._source_contents((self.home/'u4401',), (self.home,))

    def test_symlink_exact_candidate_rejected(self):
        src=self.make_source('u4401')
        target=self.home/'payload'
        target.write_bytes(obj())
        src.unlink()
        try: src.symlink_to(target)
        except (OSError,NotImplementedError): self.skipTest('no symlink support')
        with self.assertRaisesRegex(s.StrippedError,'Symlinked object or ancestor'):
            self.get()

class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent=Path(self.temp.name)
        self.patch=self.parent/'patch'
        self.content=self.patch/'OpenWF'/'Content'
        self.content.mkdir(parents=True)
        self.target=self.parent/'target'
        self.base=self.parent/'base'
        self.target.mkdir()
        self.base.mkdir()
        self.exe=self.target/'Warframe.x64.exe'
        self.exe.write_bytes(b'fakeexe')
        self.asset=w.ManifestAsset('0','stripped','/Lotus/Fx/Narin/Ability.bk2',DIGEST,
            len(obj()) | w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F)
        self.source=self.parent/'u4401'
        source_content=self.source/'OpenWF'/'Content'
        source_content.mkdir(parents=True)
        self.source_path=w._safe_output_path(source_content,'0',self.asset.logical_path,0xAA,self.asset.hash_b64)
        self.source_path.parent.mkdir(parents=True)
        self.source_path.write_bytes(obj())
        self.output_path=w._safe_output_path(self.content,'0',self.asset.logical_path,0xAA,self.asset.hash_b64)

    def run_add(self, assets=None, fail_final_for=None, dry_run=False, allow_cdn=False):
        import installed_type_resolver as resolver
        import common as fp
        from unittest.mock import patch
        real_verify = s._verify_asset
        def verify(path, asset, oodle, expected_type):
            if path == fail_final_for:
                raise s.StrippedError('Injected final-copy verification failure')
            return real_verify(path, asset, oodle, expected_type)
        with patch.object(s, '_verify_asset', side_effect=verify), \
             patch.object(s,'validate_patch_identity'), \
             patch.object(s,'installed_stripped',return_value=assets if assets is not None else [self.asset]), \
             patch.object(s,'_expected_type',return_value=0xAA), \
             patch.object(s,'_existing_asset',return_value=None), \
             patch.object(w,'_find_target_exe',return_value=self.exe), \
             patch.object(w,'Oodle',return_value=None), \
             patch.object(w,'find_cache_windows_dir',side_effect=lambda x:x), \
             patch.object(w,'scan_cache',side_effect=lambda x:x), \
             patch.object(w,'_select_h_by_hash',side_effect=w.SourceCoverageError('absent')), \
             patch.object(w,'_select_h_by_hash',side_effect=w.SourceCoverageError('absent')), \
             patch.object(w,'_validate_windows_export_path'), \
             patch.object(resolver,'prepare',return_value=None), \
             patch.object(fp,'snapshot',return_value={'digest':'stable'}), \
             patch.object(fp,'compare',return_value={'counts':{}}):
            return s.add_missing(patch=self.patch, target=self.target, base=self.base,
                source_patches=(self.source,), allow_cdn=allow_cdn,
                dry_run=dry_run)

    def test_dry_run_checks_object_but_does_not_publish_it(self):
        result = self.run_add(dry_run=True)
        self.assertEqual(result['would_add'], 1)
        self.assertEqual(result['added'], 0)
        self.assertEqual(result['source'], 1)
        self.assertEqual(result['cdn'], 0)
        self.assertTrue(result['dry_run'])
        self.assertFalse(self.output_path.exists())
        self.assertEqual(self.source_path.read_bytes(), obj())
        self.assertEqual(list(self.parent.glob('.wf-stripped-*')), [])

    def test_dry_run_reports_missing_but_does_not_change_patch(self):
        second = w.ManifestAsset('0', 'stripped', '/Lotus/Fx/Narin/Another.bk2',
            DIGEST, len(obj()) | w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F)
        result = self.run_add(assets=[self.asset, second], dry_run=True)
        self.assertEqual(result['would_add'], 1)
        self.assertEqual(result['unresolved'], 1)
        self.assertEqual(result['unresolved_assets'][0]['logical_path'], second.logical_path)
        self.assertEqual(result['added'], 0)
        self.assertFalse(self.output_path.exists())
        self.assertFalse((self.content / '0').exists())

    def test_cdn_format_failure_in_dry_run_is_reported_and_no_write(self):
        import offline_patch_audit as audit
        second = w.ManifestAsset('0', 'stripped', '/Lotus/Fx/Narin/Another.bk2',
            DIGEST, len(obj()) | w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F)
        with patch.object(s, '_download_exact', side_effect=audit.UnsupportedCdnFormatError('unknown marker')) as fetch:
            result = self.run_add(assets=[self.asset, second], dry_run=True, allow_cdn=True)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(result['would_add'], 1)
        self.assertEqual(result['unresolved'], 1)
        self.assertIn('unknown marker', result['unresolved_assets'][0]['reason'])
        self.assertFalse(self.output_path.exists())

    def test_cdn_format_failure_in_publish_rolls_back(self):
        import offline_patch_audit as audit
        second = w.ManifestAsset('0', 'stripped', '/Lotus/Fx/Narin/Another.bk2',
            DIGEST, len(obj()) | w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F)
        with patch.object(s, '_download_exact', side_effect=audit.UnsupportedCdnFormatError('unknown marker')):
            with self.assertRaises(audit.UnsupportedCdnFormatError):
                self.run_add(assets=[self.asset, second], allow_cdn=True)
        self.assertFalse(self.output_path.exists())

    def test_exact_source_enrichment_no_cdn(self):
        result=self.run_add()
        self.assertEqual(result['source'],1)
        self.assertEqual(result['cdn'],0)
        self.assertEqual(self.output_path.read_bytes(),obj())
        self.assertEqual(self.source_path.read_bytes(),obj())
        self.assertEqual(result['provenance'][0]['sha256'],__import__('hashlib').sha256(obj()).hexdigest())

    def test_final_copy_verification_failure_rolls_back_both_files(self):
        second = w.ManifestAsset('0', 'stripped', '/Lotus/Fx/Narin/Another.bk2',
            DIGEST, len(obj()) | w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F)
        source_content = self.source / 'OpenWF' / 'Content'
        source_second = w._safe_output_path(source_content, '0', second.logical_path,
            0xAA, second.hash_b64)
        source_second.write_bytes(obj())
        final_second = w._safe_output_path(self.content, '0', second.logical_path,
            0xAA, second.hash_b64)
        with self.assertRaisesRegex(s.StrippedError, 'Injected final-copy'):
            self.run_add(assets=[self.asset, second], fail_final_for=final_second)
        self.assertFalse(self.output_path.exists())
        self.assertFalse(final_second.exists())
        self.assertEqual(source_second.read_bytes(), obj())
        self.assertEqual(self.source_path.read_bytes(), obj())

    def test_destination_symlinked_ancestor_rejected(self):
        namespace = self.content / '0'
        namespace.mkdir()
        mirror = namespace / 'mirror'
        mirror.mkdir()
        link = namespace / 'Lotus'
        try:
            link.symlink_to(mirror, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('no symlink privileges')
        with self.assertRaisesRegex(s.StrippedError, 'Symlinked object or ancestor'):
            self.run_add()
        self.assertFalse(list(mirror.rglob('*.bk2*')))

    def test_missing_second_asset_causes_no_patch_mutation(self):
        second=w.ManifestAsset('0','stripped','/Lotus/Fx/Narin/Another.bk2',DIGEST,
            len(obj()) | w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F)
        with self.assertRaisesRegex(s.StrippedError,'No locally reconstructed'):
            self.run_add(assets=[self.asset,second])
        self.assertFalse(self.output_path.exists())
        self.assertEqual(self.source_path.read_bytes(),obj())

class TestCDNEnvelope(unittest.TestCase):
    def setUp(self):
        import offline_patch_audit as audit
        self.audit = audit
        self.plain = obj()[:-5]

    def test_alternative_oodle_header_must_decode_and_validate(self):
        class FakeOodle:
            def identify_compressed_stream(self, packed):
                self_test.assertEqual(packed, b'\x81dummy-oodle')
                return 9, True
            def decompress(self, packed, expected_size):
                self_test.assertEqual(expected_size, len(self_plain))
                return self_plain
        self_test = self
        self_plain = self.plain
        raw = b'\x81dummy-oodle' + struct.pack('<I', len(self.plain)) + b'\x43'
        raw += struct.pack('<I', w.crc32c(raw))
        asset = w.ManifestAsset('0', 'stripped', '/Lotus/Fx/Narin/Ability.bk2',
            DIGEST, len(raw) | w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F)
        self.assertEqual(self.audit.verify_cdn_bytes(raw, asset, FakeOodle()),
            'outer-oodle-crc-h-sections')

    def test_unknown_footer_reports_signature_and_refuses_payload(self):
        raw = b'\x8cmystery' + struct.pack('<I', len(self.plain)) + b'\x99'
        raw += struct.pack('<I', w.crc32c(raw))
        asset = w.ManifestAsset('0', 'stripped', '/Lotus/Fx/Narin/Ability.bk2',
            DIGEST, len(raw) | w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F)
        with self.assertRaisesRegex(self.audit.UnsupportedCdnFormatError,
                r'first8=.*footer-marker=0x99.*CRC32C valid') as caught:
            self.audit.verify_cdn_bytes(raw, asset, None)
        self.assertEqual(caught.exception.retryable, False)

    def test_unknown_format_never_retries_same_url(self):
        from common import fetch_verified
        from unittest.mock import Mock
        get = Mock(return_value=b'raw')
        def reject(_data):
            raise self.audit.UnsupportedCdnFormatError('unrecognized valid CRC wrapper')
        attempts = []
        with self.assertRaises(self.audit.UnsupportedCdnFormatError):
            fetch_verified(url='https://example.invalid/object', logical_path='0/test',
                expected_size=3, timeout=5, get_func=get,
                verify_func=reject, retries=5, attempts_log=attempts,
                sleeper=lambda _: self.fail('Unexpected retry'))
        self.assertEqual(get.call_count, 1)
        self.assertEqual(attempts[0]['status'], 'integrity-failed')
        self.assertFalse(attempts[0]['retryable'])

    def test_console_severity_colors_match_nct(self):
        import common
        self.assertEqual((common.RED, common.YELLOW, common.GREEN, common.CYAN),
            ('\x1b[31m', '\x1b[33m', '\x1b[32m', '\x1b[36m'))

class TestCRC32C(unittest.TestCase):
    def test_known_castagnoli_vectors(self):
        for content, expected in ((b'', 0), (b'123456789', 0xE3069283)):
            self.assertEqual(w._crc32c_python(content), expected)
            self.assertEqual(w.crc32c(content), expected)

    def test_native_dispatch_and_portable_fallback(self):
        data = b'123456789'
        with patch.object(w, '_google_crc32c', SimpleNamespace(implementation='c', value=lambda _data: 0xE3069283)):
            self.assertEqual(w.crc32c(data), 0xE3069283)
        with patch.object(w, '_google_crc32c', SimpleNamespace(implementation='python', value=lambda _data: -1)):
            self.assertEqual(w.crc32c(data), 0xE3069283)

class VideoAuditTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.patch_path = self.root / 'patch'
        self.target = self.root / 'target'
        self.base = self.root / 'base'
        for path in (self.patch_path, self.target, self.base):
            path.mkdir()
        self.content = self.patch_path / 'OpenWF' / 'Content'
        self.content.mkdir(parents=True)
        self.asset = w.ManifestAsset('0', 'stripped', '/Lotus/Fx/Narin/Ability.bk2',
            DIGEST, len(obj()) | w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F)
        self.path = w._safe_output_path(self.content, self.asset.namespace, self.asset.logical_path,
            0xAA, self.asset.hash_b64)
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(obj())

    def audit(self, evidence='pristine-HF-match+base-HF-match', assets=None):
        with patch.object(w, 'Oodle', return_value=None), \
             patch.object(w, 'find_cache_windows_dir', side_effect=lambda path: path), \
             patch.object(w, 'scan_cache', side_effect=lambda path: path), \
             patch.object(s, 'validate_patch_identity'), \
             patch.object(s, 'installed_stripped', return_value=assets if assets is not None else [self.asset]), \
             patch.object(s, '_crosscheck_installed_pieces', return_value=evidence):
            return s.audit_existing_videos(patch=self.patch_path, target=self.target, base=self.base)

    def test_pristine_f_match_is_verified_and_patch_unchanged(self):
        before = self.path.read_bytes()
        result = self.audit()
        self.assertEqual(result['target_f_verified'], 1)
        self.assertEqual(result['failed'], 0)
        self.assertEqual(result['videos'][0]['f_bytes'], len(F))
        self.assertEqual(result['videos'][0]['f_sha256'], __import__('hashlib').sha256(F).hexdigest())
        self.assertFalse(result['full_cdn_bytes_proven'])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['base', 'patch', 'target'])

    def test_base_f_match_does_not_claim_pristine_proof(self):
        result = self.audit('pristine-H-match+base-HF-match')
        self.assertEqual(result['target_f_verified'], 0)
        self.assertEqual(result['base_only'], 1)
        self.assertEqual(result['videos'][0]['status'], 'base_only')

    def test_h_only_reference_is_inconclusive(self):
        result = self.audit('pristine-H-match+base-H-match; original-F-not-independently-known')
        self.assertEqual(result['inconclusive'], 1)
        self.assertEqual(result['target_f_verified'], 0)

    def test_missing_patch_video_is_failed_and_not_reconstructed(self):
        self.path.unlink()
        result = self.audit()
        self.assertEqual(result['failed'], 1)
        self.assertIn('missing', result['videos'][0]['error'])
        self.assertFalse(self.path.exists())

    def test_bad_crc_is_failed_and_original_bytes_preserved(self):
        changed = obj()[:-1] + b'X'
        self.path.write_bytes(changed)
        result = self.audit()
        self.assertEqual(result['failed'], 1)
        self.assertEqual(self.path.read_bytes(), changed)

    def test_changed_video_frames_are_rejected_even_with_identical_h_and_size(self):
        # The altered video passes CDN CRC, manifest size and the H identity.
        changed = obj(b'altered!-preview-frames')
        self.assertEqual(len(changed), len(obj()))
        self.path.write_bytes(changed)
        with patch.object(w, 'Oodle', return_value=None), \
             patch.object(w, 'find_cache_windows_dir', side_effect=lambda path: path), \
             patch.object(w, 'scan_cache', side_effect=lambda path: path), \
             patch.object(s, 'validate_patch_identity'), \
             patch.object(s, 'installed_stripped', return_value=[self.asset]), \
             patch.object(w, '_select_h_by_hash', return_value=(type('E', (), {'package': 'p'})(), H, 0xAA)), \
             patch.object(w, '_entries_for', return_value=[]), \
             patch.object(w, '_piece_in_package', side_effect=lambda *_: 'F' if _[-2:] == ('F', 'p') else None), \
             patch.object(w, 'decompress_cache_entry', return_value=F):
            result = s.audit_existing_videos(patch=self.patch_path, target=self.target, base=self.base)
        self.assertEqual(result['failed'], 1)
        self.assertIn('F bytes differ', result['videos'][0]['error'])
        self.assertEqual(self.path.read_bytes(), changed)

    def test_out_of_scope_or_empty_manifest_cannot_pass(self):
        with self.assertRaisesRegex(s.StrippedError, 'no stripped'):
            self.audit(assets=[])

    def test_incorrect_piece_flags_fail_closed(self):
        bad = w.ManifestAsset(self.asset.namespace, self.asset.section, self.asset.logical_path,
            self.asset.manifest_hash, len(obj()) | w.MANIFEST_FLAG_H)
        result = self.audit(assets=[bad])
        self.assertEqual(result['failed'], 1)
        self.assertIn('flags', result['videos'][0]['error'])

    def test_audit_cli_rejects_recovery_options_and_ambiguous_groups(self):
        for args in (['-c'], ['-n'], ['-f'], ['-r', '2'], ['-r', '5'], ['--retries=5'], ['-An']):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    add_stripped.main(['-p', str(self.patch_path), '-A', *args])
                self.assertEqual(raised.exception.code, 2)

    def make_video_source(self, *, name='u4401', payload=None, digest=DIGEST):
        root = self.root / name
        content = root / 'OpenWF' / 'Content'
        content.mkdir(parents=True)
        if payload is not None:
            import hashlib
            # Keep the source CommonHeader identity aligned with its filename.
            header = digest + struct.pack('<III', 0x14, 0xAA, 1)
            section = [header, b'', payload]
            body = w.SHCC_PREAMBLE + b''.join(
                struct.pack('<BII', 0, len(part), len(part)) + part for part in section)
            raw = body + b'\x52' + struct.pack('<I', w.crc32c(body + b'\x52'))
            filename = w._safe_output_path(content, '0', self.asset.logical_path,
                0xAA, w.b64m_encode(digest))
            filename.parent.mkdir(parents=True, exist_ok=True)
            filename.write_bytes(raw)
            return root, filename
        return root, None

    def test_comparison_exact_f_byte_match_without_historical_promotion(self):
        source, _file = self.make_video_source(payload=F)
        with patch.object(w, 'Oodle', return_value=None), \
             patch.object(w, 'find_cache_windows_dir', side_effect=lambda path: path), \
             patch.object(w, 'scan_cache', side_effect=lambda path: path), \
             patch.object(s, 'validate_patch_identity'), \
             patch.object(s, 'installed_stripped', return_value=[self.asset]), \
             patch.object(s, '_crosscheck_installed_pieces', return_value='pristine-H-match; original-F-not-independently-known'):
            result = s.audit_existing_videos(patch=self.patch_path, target=self.target,
                base=self.base, source_patches=(source,))
        self.assertEqual(result['inconclusive'], 1)
        compare = result['videos'][0]['source_comparisons'][0]
        self.assertEqual(compare['status'], 'f_match')
        self.assertTrue(compare['same_h_identity'])
        self.assertTrue(compare['same_full_cdn_bytes'])
        self.assertEqual(result['source_comparison_counts']['f_match'], 1)
        self.assertEqual(self.path.read_bytes(), obj())

    def test_comparison_different_f_and_same_h_is_flagged(self):
        source, _file = self.make_video_source(payload=b'different-preview-frames')
        comparisons = s._compare_video_source(self.asset, obj(), F, source,
            source / 'OpenWF' / 'Content', None)
        self.assertEqual(comparisons['status'], 'f_different')
        self.assertTrue(comparisons['same_h_identity'])
        self.assertFalse(comparisons['same_full_cdn_bytes'])

    def test_comparison_different_h_but_same_video_f(self):
        source, _file = self.make_video_source(payload=F, digest=b'fedcba9876543210')
        result = s._compare_video_source(self.asset, obj(), F, source,
            source / 'OpenWF' / 'Content', None)
        self.assertEqual(result['status'], 'f_match')
        self.assertFalse(result['same_h_identity'])
        self.assertFalse(result['same_full_cdn_bytes'])

    def test_comparison_incremental_patch_absence_is_not_mismatch(self):
        source, _file = self.make_video_source()
        result = s._compare_video_source(self.asset, obj(), F, source,
            source / 'OpenWF' / 'Content', None)
        self.assertEqual(result['status'], 'not_present')

    def test_comparison_corrupt_source_rejected_not_reported_as_match(self):
        source, file = self.make_video_source(payload=F)
        file.write_bytes(file.read_bytes()[:-1] + b'Z')
        result = s._compare_video_source(self.asset, obj(), F, source,
            source / 'OpenWF' / 'Content', None)
        self.assertEqual(result['status'], 'invalid')

    def test_comparison_multiple_same_path_objects_are_ambiguous(self):
        source, file = self.make_video_source(payload=F)
        alternative = file.with_name(file.name.replace('_', '_', 1).replace('AA_', 'A9_', 1))
        alternative.write_bytes(file.read_bytes())
        result = s._compare_video_source(self.asset, obj(), F, source,
            source / 'OpenWF' / 'Content', None)
        self.assertEqual(result['status'], 'ambiguous')

    def test_source_comparison_symlink_is_rejected(self):
        source, file = self.make_video_source(payload=F)
        file.unlink()
        try:
            file.symlink_to(self.path)
        except (OSError, NotImplementedError):
            self.skipTest('Symlinks unavailable')
        result = s._compare_video_source(self.asset, obj(), F, source,
            source / 'OpenWF' / 'Content', None)
        self.assertEqual(result['status'], 'invalid')

    def test_audit_accepts_source_patch_but_rejects_mutating_flags(self):
        opts = add_stripped.parser().parse_args(['-p', 'patch', '-t', 'target', '-b', 'base', '-A', '-s', 'one',
            '--source-patch', 'two'])
        self.assertEqual(opts.source_patch, [Path('one'), Path('two')])
        for flags in (['-c'], ['-n'], ['-f'], ['-r', '5']):
            with self.subTest(flags=flags), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    add_stripped.main(['-p', str(self.patch_path), '-t', 'target', '-b', 'base', '-A', '-s', 'one', *flags])
                self.assertEqual(raised.exception.code, 2)

    def test_audit_cli_aliases(self):
        short = vars(add_stripped.parser().parse_args(['-p', 'patch', '-t', 'target', '-b', 'base', '-A']))
        long = vars(add_stripped.parser().parse_args(['--patch', 'patch', '--target', 'target', '--base', 'base', '--audit-videos']))
        self.assertEqual(short, long)

if __name__ == '__main__':
    unittest.main(verbosity=2)

class TestOriginalHCache(unittest.TestCase):
    def setUp(self):
        import rebuild_patch as rebuild
        self.rebuild = rebuild
        self.header = b'pristine-h-cache-header-contents'
        self.plain = (w.SHCC_PREAMBLE
            + struct.pack('<BII', 0, len(self.header), len(self.header)) + self.header
            + struct.pack('<BII', 0, 0, 0) * 2)
        self.direct = self.plain + b'\x52' + struct.pack('<I', w.crc32c(self.plain + b'\x52'))

    def test_direct_and_different_outer_envelope_accepted_when_h_matches(self):
        self.assertEqual(w.verify_h_cache_metadata_object(self.direct, self.header, None),
            hashlib.sha256(self.direct).hexdigest())
        outer = b'compressed-stream-' * 3 + struct.pack('<I', len(self.plain)) + w.CDN_OUTER_FOOTER_MARKER
        outer += struct.pack('<I', w.crc32c(outer))
        oodle = SimpleNamespace(decompress=lambda raw, length: self.plain)
        self.assertEqual(w.verify_h_cache_metadata_object(outer, self.header, oodle),
            hashlib.sha256(outer).hexdigest())
        self.assertNotEqual(self.direct, outer)

    def test_h_cache_wrong_header_or_crc_rejected(self):
        with self.assertRaisesRegex(w.ExportError, 'differ'):
            w.verify_h_cache_metadata_object(self.direct, b'other', None)
        with self.assertRaisesRegex(w.ExportError, 'CRC32C'):
            w.verify_h_cache_metadata_object(self.direct[:-1] + b'\xff', self.header, None)

    def test_h_cache_rejects_nonempty_b_or_f_and_trailing_bytes(self):
        bad = w.SHCC_PREAMBLE + struct.pack('<BII', 0, len(self.header), len(self.header)) + self.header
        bad += struct.pack('<BII', 0, 1, 1) + b'X' + struct.pack('<BII', 0, 0, 0)
        bad += b'\x52' + struct.pack('<I', w.crc32c(bad + b'\x52'))
        with self.assertRaisesRegex(w.ExportError, 'B/F'):
            w.verify_h_cache_metadata_object(bad, self.header, None)
        bad = self.plain + b'X'
        bad += b'\x52' + struct.pack('<I', w.crc32c(bad + b'\x52'))
        with self.assertRaisesRegex(w.ExportError, 'trailing'):
            w.verify_h_cache_metadata_object(bad, self.header, None)

    def test_existing_patch_can_keep_verified_original_h_cache_envelope(self):
        with tempfile.TemporaryDirectory() as dirname:
            home = Path(dirname)
            target = home / 'target'
            patch_root = home / 'patch'
            target.mkdir()
            content = patch_root / 'OpenWF' / 'Content' / '0'
            content.mkdir(parents=True)
            (target / 'Warframe.x64.exe').write_bytes(b'pristine-executable')
            (patch_root / 'Warframe.x64.exe').write_bytes(b'pristine-executable')
            (content / 'UNMANAGED').write_bytes(b'')
            # A valid alternative envelope encodes the same untouched H bytes.
            outer = b'compressed-stream-' * 3 + struct.pack('<I', len(self.plain)) + w.CDN_OUTER_FOOTER_MARKER
            outer += struct.pack('<I', w.crc32c(outer))
            (content / f'H.Cache.bin!E_{w.H_CACHE_SENTINEL_HASH}').write_bytes(outer)
            fake_oodle = SimpleNamespace(decompress=lambda raw, size: self.plain)
            with patch.object(w, '_find_target_exe', return_value=target/'Warframe.x64.exe'), \
                 patch.object(w, '_select_h_cache', return_value=(SimpleNamespace(), self.header)), \
                 patch.object(w, 'build_shcc', return_value=self.direct), \
                 patch.object(w, 'parse_h_cache_header', return_value=w.HCacheIndex(14, ())):
                s.validate_patch_identity(patch_root, target, fake_oodle, {})
                (content / f'H.Cache.bin!E_{w.H_CACHE_SENTINEL_HASH}').write_bytes(outer[:-1] + b'X')
                with self.assertRaises(w.ExportError):
                    s.validate_patch_identity(patch_root, target, fake_oodle, {})

    def test_build_label_and_url_quoted_correctly(self):
        value = '2026.09.22.16.46/rsytTB10v64vR64neflfqw'
        self.assertEqual(self.rebuild.normalize_build_label(value), value)
        self.assertEqual(self.rebuild.h_cache_url(value),
            'https://openwf.io/supplementals/static%20data/H.Cache_2026.09.22.16.46_rsytTB10v64vR64neflfqw.bin')
        value2 = '2026.06.30.09.08/MOWJj4ozQ+med4chgjXxUg'
        self.assertIn('%2B', self.rebuild.h_cache_url(value2))
        for bad in ('2026.99.22.16.46/rsytTB10v64vR64neflfqw',
                '2026.09.22.16.46/../evil',
                '2026.09.22.16.46/abc',
                'https://evil.site/H.Cache.bin'):
            with self.subTest(bad=bad), self.assertRaises(self.rebuild.CleanRunError):
                self.rebuild.normalize_build_label(bad)

    def test_unique_executable_build_label_or_none(self):
        with tempfile.TemporaryDirectory() as temp:
            exe = Path(temp)/'Warframe.x64.exe'
            exe.write_bytes(b'prefix|2026.09.22.16.46/rsytTB10v64vR64neflfqw|suffix')
            self.assertEqual(self.rebuild.find_embedded_build_label(exe),
                '2026.09.22.16.46/rsytTB10v64vR64neflfqw')
            exe.write_bytes(exe.read_bytes() + b' 2026.06.30.09.08/MOWJj4ozQ+med4chgjXxUg')
            self.assertIsNone(self.rebuild.find_embedded_build_label(exe))

    def test_exact_http_download_and_missing_and_oversize(self):
        from urllib.error import HTTPError
        label = '2026.09.22.16.46/rsytTB10v64vR64neflfqw'
        class Response:
            def __init__(self, data): self.data = data
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def getcode(self): return 200
            def read(self, count): return self.data[:count]
        class FakeOpener:
            def __init__(self, response): self.response = response
            def open(self, req, timeout):
                assert timeout == 5
                assert req.full_url == self_rebuild.h_cache_url(label)
                if isinstance(self.response, Exception): raise self.response
                return Response(self.response)
        self_rebuild = self.rebuild
        downloaded, report = self.rebuild.fetch_original_h_cache(label, timeout=5, opener=FakeOpener(self.direct))
        self.assertEqual(downloaded, self.direct)
        self.assertEqual(report['sha256'], hashlib.sha256(self.direct).hexdigest())
        missing = HTTPError('http://x', 404, 'not found', None, None)
        downloaded, report = self.rebuild.fetch_original_h_cache(label, timeout=5, opener=FakeOpener(missing))
        self.assertIsNone(downloaded)
        self.assertEqual(report['http_status'], 404)
        with self.assertRaisesRegex(self.rebuild.CleanRunError, '1 MiB'):
            self.rebuild.fetch_original_h_cache(label, timeout=5,
                opener=FakeOpener(b'X' * (1024 * 1024 + 1)))

class TestReleaseWorkspaceAndRuntime(unittest.TestCase):
    def test_bundled_oodle_runtime_matches_pinned_binary(self):
        runtime = Path(w.__file__).resolve().parent / w.OODLE_DLL_NAME
        self.assertTrue(runtime.is_file(), 'Release archive must include the requested Oodle runtime')
        self.assertEqual(runtime.stat().st_size, w.OODLE_X64_SIZE)
        self.assertEqual(hashlib.sha256(runtime.read_bytes()).hexdigest(), w.OODLE_X64_SHA256)

    def test_relative_target_uses_resolved_drive_for_default_workspace(self):
        from types import SimpleNamespace
        from unittest.mock import patch as mock_patch
        import rebuild_patch as rebuild
        target = Path('nested-target-relative')
        opts = SimpleNamespace(target=target, base=Path('base'), u4401=Path('source'),
            output=Path('output'), output_parent=None)
        with tempfile.TemporaryDirectory() as temp, \
             mock_patch.object(rebuild, 'validate_roots', side_effect=rebuild.CleanRunError('stop')) as validate, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            # The early guard runs before creating any recovery workspace.
            result = rebuild.build(opts, report_root=Path(temp), run_id='test')
            self.assertEqual(result, 2)
            calculated_work = validate.call_args.args[4]
            self.assertEqual(calculated_work, Path(target.resolve(strict=False).anchor) / 'WF-Rebuild' / 'test')
