"""Contract tests for safe, unambiguous short and long CLI switches."""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import add_stripped
import install_to_patch
import warframe_install_to_patch as exporter

class TestCliAliases(unittest.TestCase):
    @staticmethod
    def parse(factory, args):
        return vars(factory().parse_args(args))

    def assert_rejected(self, factory, args):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                factory().parse_args(args)
        self.assertEqual(raised.exception.code, 2)

    def test_add_stripped_short_aliases_match_long_options(self):
        short = ['-p', 'existing', '-t', 'target', '-b', 'base', '-s', 'older',
                 '-c', '-n', '-r', '3', '-f', '-l', 'logs']
        long = ['--patch', 'existing', '--target', 'target', '--base', 'base',
                '--source-patch', 'older', '--cdn-fallback', '--dry-run',
                '--retries', '3', '--full-source-hash', '--logs-dir', 'logs']
        self.assertEqual(self.parse(add_stripped.parser, short),
                         self.parse(add_stripped.parser, long))

    def test_install_short_aliases_match_long_options(self):
        short = ['-t', 'target', '-b', 'base', '-u', 'older', '-P', 'parent',
                 '-w', 'workspace', '-l', 'logs', '-r', '3', '-T', '12', '-f',
                 '-a', '-c', '-e', '-k']
        long = ['--target', 'target', '--base', 'base', '--u4401', 'older',
                '--output-parent', 'parent', '--work-parent', 'workspace',
                '--logs-dir', 'logs', '--cdn-retries', '3', '--cdn-timeout', '12',
                '--full-source-hash', '--all-stripped', '--stripped-cdn-fallback',
                '--keep-failed-output', '--keep-workspace']
        self.assertEqual(self.parse(install_to_patch.parser, short),
                         self.parse(install_to_patch.parser, long))
        self.assertEqual(self.parse(install_to_patch.parser, ['-t', 'target', '-b', 'base', '-u', 'older', '-o', 'out'])['output'], Path('out'))

    def test_repeated_source_patch_is_intentional(self):
        opts = self.parse(add_stripped.parser,
                          ['-p', 'existing', '-t', 'target', '-b', 'base', '-s', 'first', '--source-patch', 'second', '-n'])
        self.assertEqual(opts['source_patch'], [Path('first'), Path('second')])
        self.assertTrue(opts['dry_run'])

    def test_require_explicit_portable_paths(self):
        self.assert_rejected(add_stripped.parser, ['-p', 'existing'])
        self.assert_rejected(add_stripped.parser, ['-p', 'existing', '-t', 'target'])
        self.assert_rejected(install_to_patch.parser, ['-t', 'target', '-b', 'base', '-u', 'older'])
        self.assert_rejected(install_to_patch.parser, ['-b', 'base', '-u', 'older', '-P', 'parent'])

    def test_dry_run_and_cdn_can_be_combined(self):
        opts = self.parse(add_stripped.parser, ['-p', 'existing', '-t', 'target', '-b', 'base', '-n', '-c'])
        self.assertTrue(opts['dry_run'])
        self.assertTrue(opts['cdn_fallback'])

    def test_reject_stacked_short_options_and_attached_values(self):
        for args in (['-p', 'existing', '-cn'], ['-p', 'existing', '-pother'],
                     ['-p=existing'], ['-p', 'existing', '-r3']):
            with self.subTest(args=args):
                self.assert_rejected(add_stripped.parser, args)
        self.assert_rejected(install_to_patch.parser, ['-ac'])
        self.assert_rejected(install_to_patch.parser, ['-r5'])

    def test_reject_abbreviated_long_options(self):
        self.assert_rejected(add_stripped.parser, ['--pat', 'existing'])
        self.assert_rejected(add_stripped.parser, ['-p', 'existing', '--dry'])
        self.assert_rejected(install_to_patch.parser, ['--cdn-ret', '3'])

    def test_reject_duplicate_nonrepeatable_options(self):
        self.assert_rejected(add_stripped.parser, ['-p', 'first', '--patch', 'second'])
        self.assert_rejected(add_stripped.parser, ['-p', 'existing', '-n', '--dry-run'])
        self.assert_rejected(install_to_patch.parser, ['-r', '3', '--cdn-retries', '5'])
        self.assert_rejected(install_to_patch.parser, ['-c', '--stripped-cdn-fallback'])

    def test_reject_conflicting_output_destinations(self):
        self.assert_rejected(install_to_patch.parser, ['-o', 'path', '-P', 'parent'])
        self.assert_rejected(install_to_patch.parser, ['--output-parent', 'parent', '-o', 'path'])

    def test_cdn_fallback_dependency_remains_enforced(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                install_to_patch.main(['-t', 'target', '-b', 'base', '-u', 'older', '-P', 'out', '-c'])
        self.assertEqual(raised.exception.code, 2)

    def test_missing_bundled_oodle_dll_fails_with_setup_guidance(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(exporter.ExportError) as raised:
                exporter.Oodle(Path(temporary))._load()
        self.assertIn('Extract the complete archive', str(raised.exception))
        self.assertIn('oo2core_9.dll', str(raised.exception))

    def test_help_and_version_exit_cleanly(self):
        for factory in (add_stripped.parser, install_to_patch.parser):
            for opt in ('-h', '-v'):
                with self.subTest(factory=factory, option=opt):
                    with contextlib.redirect_stdout(io.StringIO()):
                        with self.assertRaises(SystemExit) as raised:
                            factory().parse_args([opt])
                    self.assertEqual(raised.exception.code, 0)

class TestOriginalHCacheCli(unittest.TestCase):
    def test_build_label_option_is_not_stackable(self):
        args = ['-t','target','-b','base','-u','source','-P','out']
        explicit = install_to_patch.parser().parse_args(args + ['-H', '2026.09.22.16.46/rsytTB10v64vR64neflfqw'])
        self.assertEqual(explicit.h_cache_build_label, '2026.09.22.16.46/rsytTB10v64vR64neflfqw')
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                install_to_patch.parser().parse_args(args + ['-H', 'x', '-Hx'])
            with self.assertRaises(SystemExit):
                install_to_patch.parser().parse_args(args + ['-H', 'x', '--h-cache-build-label', 'y'])

class TestReleaseMetadata(unittest.TestCase):
    def test_internal_report_versions_match_public_release(self):
        import common
        import recover_missing_cdn
        import recover_remaining_h_only
        import recover_u4400_last_three

        self.assertEqual(common.PRODUCT_VERSION, 'v0.1')
        for version in (common.VERSION, exporter.VERSION,
                        recover_missing_cdn.RECOVERY_REPORT_FORMAT,
                        recover_remaining_h_only.VERSION,
                        recover_u4400_last_three.VERSION):
            self.assertEqual(version, '0.1')
        self.assertEqual(recover_remaining_h_only.REPORT_NAME,
                         'cdn-h-only-recovery-v0.1.json')

    def test_no_obsolete_development_release_labels(self):
        for path in (*ROOT.glob('*.py'), *(ROOT / 'data').glob('*.py'), ROOT / 'README.md',
                     ROOT / 'Warframe-Install-to-Patch-Internals.md'):
            with self.subTest(file=path.relative_to(ROOT)):
                text = path.read_text(encoding='utf-8')
                self.assertNotIn('v0.2.', text)
                self.assertNotIn('v0.2.x', text)
                self.assertNotIn('0.2.48', text)

    def test_license_matches_nct_gplv3(self):
        import hashlib
        payload = (ROOT / 'LICENSE').read_bytes()
        self.assertIn(b'GNU GENERAL PUBLIC LICENSE', payload)
        self.assertIn(b'Version 3, 29 June 2007', payload)
        blob = b'blob ' + str(len(payload)).encode('ascii') + b'\0' + payload
        # Blob hash of DarkLotus8000/Ninja-Capture-Tool main/LICENSE.
        self.assertEqual(hashlib.sha1(blob).hexdigest(),
                         'f288702d2fa16d3cdf0035b15a9fcbc552cd88e7')

class TestNctCliErrors(unittest.TestCase):
    def test_missing_arguments_use_error_label(self):
        with contextlib.redirect_stderr(io.StringIO()) as stream:
            with self.assertRaises(SystemExit) as raised:
                install_to_patch.parser().parse_args(['nonsense'])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn('ERROR:', stream.getvalue())
        self.assertIn('the following arguments are required', stream.getvalue())
        self.assertNotIn('error: the following', stream.getvalue())

    def test_ansi_red_when_terminal_supports_it(self):
        import common
        with mock.patch.object(common, '_enabled', return_value=True):
            with contextlib.redirect_stderr(io.StringIO()) as stream:
                with self.assertRaises(SystemExit):
                    install_to_patch.parser().parse_args(['invalid'])
        self.assertIn('\x1b[31mERROR:\x1b[0m', stream.getvalue())

    def test_source_patch_public_alias(self):
        old = vars(install_to_patch.parser().parse_args(['-t', 'target', '-b', 'base', '-u', 'patch', '-P', 'out']))
        new = vars(install_to_patch.parser().parse_args(['-t', 'target', '-b', 'base', '--source-patch', 'patch', '-P', 'out']))
        self.assertEqual(old, new)

class TestInterruptCli(unittest.TestCase):
    def test_standalone_interrupt_returns_130_with_clean_diagnostics(self):
        import json
        import add_stripped
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            opts = ['-p', str(base/'patch'), '-t', str(base/'target'),
                    '-b', str(base/'base'), '-l', str(base/'logs')]
            with mock.patch.object(add_stripped.stripped_archive, 'add_missing', side_effect=KeyboardInterrupt), \
                 contextlib.redirect_stdout(io.StringIO()) as stdout, \
                 contextlib.redirect_stderr(io.StringIO()) as stderr:
                code = add_stripped.main(opts)
            self.assertEqual(code, 130)
            self.assertIn('ERROR: Interrupted by user', stderr.getvalue())
            self.assertNotIn('Traceback', stderr.getvalue())
            reports = list((base/'logs').glob('*.json'))
            self.assertEqual(len(reports), 1)
            self.assertEqual(json.loads(reports[0].read_text(encoding='utf-8'))['status'], 'interrupted')

class TestHCacheRetryPolicy(unittest.TestCase):
    LABEL = '2026.09.22.16.46/rsytTB10v64vR64neflfqw'

    def test_transient_http_and_connection_errors_retry(self):
        from urllib.error import HTTPError, URLError
        import rebuild_pristine_u4400 as rebuild
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def getcode(self): return 200
            def read(self, n): return b'valid'
        class Opener:
            calls = 0
            def open(self, req, timeout):
                self.calls += 1
                if self.calls == 1: raise HTTPError(req.full_url, 503, 'busy', None, None)
                if self.calls == 2: raise URLError('offline')
                return Response()
        o = Opener()
        sleeps = []
        data, report = rebuild.fetch_original_h_cache(self.LABEL, timeout=5, retries=5, opener=o, sleeper=sleeps.append)
        self.assertEqual(data, b'valid')
        self.assertEqual(report['attempts'], 3)
        self.assertEqual(sleeps, [1, 2])

    def test_not_found_does_not_retry(self):
        from urllib.error import HTTPError
        import rebuild_pristine_u4400 as rebuild
        class Opener:
            calls = 0
            def open(self, req, timeout):
                self.calls += 1
                raise HTTPError(req.full_url, 404, 'missing', None, None)
        o = Opener()
        data, report = rebuild.fetch_original_h_cache(self.LABEL, timeout=5, retries=5, opener=o)
        self.assertIsNone(data)
        self.assertEqual(report['attempts'], 1)
        self.assertEqual(o.calls, 1)

    def test_permanent_http_does_not_retry_and_network_is_bounded(self):
        from urllib.error import HTTPError, URLError
        import rebuild_pristine_u4400 as rebuild
        class Opener:
            def __init__(self, code): self.code = code; self.calls = 0
            def open(self, req, timeout):
                self.calls += 1
                if self.code: raise HTTPError(req.full_url, self.code, 'denied', None, None)
                raise URLError('timeout')
        o = Opener(403)
        with self.assertRaisesRegex(rebuild.CleanRunError, 'HTTP 403'):
            rebuild.fetch_original_h_cache(self.LABEL, timeout=5, retries=5, opener=o)
        self.assertEqual(o.calls, 1)
        o = Opener(None)
        with self.assertRaisesRegex(rebuild.CleanRunError, 'attempt 3/3'):
            rebuild.fetch_original_h_cache(self.LABEL, timeout=5, retries=3, opener=o, sleeper=lambda x: None)
        self.assertEqual(o.calls, 3)

    def test_corrupted_200_response_retries_before_acceptance(self):
        import rebuild_pristine_u4400 as rebuild
        import warframe_install_to_patch as w
        class Response:
            def __init__(self, payload): self.payload = payload
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def getcode(self): return 200
            def read(self, count): return self.payload
        class Opener:
            calls = 0
            def open(self, req, timeout):
                self.calls += 1
                return Response(b'bad' if self.calls == 1 else b'good')
        def verify(payload):
            if payload != b'good':
                raise w.ExportError('CRC32C mismatch')
        o = Opener()
        pauses = []
        data, info = rebuild.fetch_original_h_cache(
            self.LABEL, timeout=5, retries=5, opener=o, sleeper=pauses.append, verify_func=verify)
        self.assertEqual(data, b'good')
        self.assertEqual(info['attempts'], 2)
        self.assertEqual(pauses, [1])

    def test_persistent_invalid_http_200_fails_closed(self):
        import rebuild_pristine_u4400 as rebuild
        import warframe_install_to_patch as w
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def getcode(self): return 200
            def read(self, count): return b'invalid'
        class Opener:
            calls = 0
            def open(self, req, timeout):
                self.calls += 1
                return Response()
        o = Opener()
        def verify(payload):
            raise w.ExportError('H.Cache CDN CRC32C mismatch')
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(rebuild.HCacheVerificationError):
                rebuild.fetch_original_h_cache(self.LABEL, timeout=5, retries=3,
                                               opener=o, sleeper=lambda delay: None, verify_func=verify)
        self.assertEqual(o.calls, 3)

    def test_invalid_retry_count_rejected(self):
        import rebuild_pristine_u4400 as rebuild
        for n in (0, 21):
            with self.assertRaises(ValueError):
                rebuild.fetch_original_h_cache(self.LABEL, timeout=5, retries=n)

if __name__ == '__main__':
    unittest.main()

class TestSourceFormatting(unittest.TestCase):
    def test_no_redundant_source_whitespace(self):
        import re
        source_files = [p for p in ROOT.rglob('*') if p.is_file() and
                        p.suffix in ('.py', '.md', '.txt') and
                        '__pycache__' not in p.parts]
        for path in source_files:
            with self.subTest(file=path.relative_to(ROOT)):
                lines = path.read_text(encoding='utf-8').splitlines()
                for number, line in enumerate(lines, 1):
                    self.assertEqual(line, line.rstrip(' \t'), f'{path}:{number}: trailing whitespace')
                    self.assertNotIn('\t', line, f'{path}:{number}: tab')
                    self.assertFalse(line.lstrip().startswith('#  '),
                                     f'{path}:{number}: redundant comment spacing')
                    self.assertIsNone(re.search(r'(?<=[.!?]) {2,}(?=\S)', line),
                                      f'{path}:{number}: repeated spaces after punctuation')
                    if number > 1:
                        self.assertFalse(not line.strip() and not lines[number - 2].strip(),
                                         f'{path}:{number}: consecutive blank lines')
