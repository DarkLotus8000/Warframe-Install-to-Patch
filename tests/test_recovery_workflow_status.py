"""Public failure reporting, internal CLI defaults and source hash progress."""
from pathlib import Path
import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'data'))
import common
import rebuild_patch as rebuild
import install_to_patch as public

class WorkflowTests(unittest.TestCase):
    def test_internal_cli_supplies_retries_and_local_options(self):
        args = ['--target', 'target', '--base', 'base', '--output-parent', 'output',
            '--offline', '--local-assets', 'samples']
        with patch.object(rebuild, 'build', return_value=3) as build:
            self.assertEqual(rebuild.main(args), 3)
            opts = build.call_args.args[0]
            self.assertEqual(opts.cdn_retries, 5)
            self.assertTrue(opts.offline)
            self.assertEqual(opts.local_assets, Path('samples'))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            rebuild.main(args + ['--cdn-retries', '0'])

    def test_missing_sources_have_distinct_status_and_no_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = public.parser().parse_args(['-t', str(root/'target'), '-b', str(root/'base'),
                '-P', str(root/'output'), '--offline', '-k'])
            recovery = {'summary': {'required': 2, 'fully_verified': 1}, 'objects': [
                {'namespace': '0', 'logical_path': '/Found.bk2', 'status': 'already-verified-locally'},
                {'namespace': '0', 'logical_path': '/Missing.bk2', 'status': 'unresolved',
                    'cache_source_reason': 'no-target-h-entry', 'error': 'network disabled'}]}
            with patch.object(rebuild, 'validate_roots'), patch.object(rebuild, 'validate_export_contract'), \
                    patch.object(rebuild, 'read_only_snapshot', return_value={}), \
                    patch.object(rebuild, 'snapshot_target_executable', return_value={}), \
                    patch.object(rebuild.importlib.util, 'find_spec', return_value=object()), \
                    patch.object(rebuild.w, 'Oodle', return_value=Mock()), \
                    patch.object(rebuild.historical, 'run', return_value=recovery), \
                    contextlib.redirect_stdout(io.StringIO()) as console:
                code = rebuild.build(args, work_parent=root/'work', report_root=root/'logs', run_id='test')
            self.assertEqual(code, 3)
            self.assertIn('[Missing] 0/Missing.bk2', console.getvalue())
            self.assertFalse((root/'output').exists())
            _, result = public.consolidate_logs(root/'logs', 'test', code)
            doc = json.loads(result.read_text())
            self.assertEqual(doc['status'], 'incomplete-sources')
            self.assertEqual(doc['exit_code'], 3)
            self.assertEqual(doc['unresolved_objects'][0]['logical_path'], '/Missing.bk2')
            self.assertEqual(doc['recovery_summary']['fully_verified'], 1)
            self.assertIsNone(doc['failure'])

    def test_progress_preserves_sha256_and_reports_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'sample.cache'
            raw = b'x' * (5*1024*1024)
            path.write_bytes(raw)
            with patch.object(common.time, 'monotonic', side_effect=[0, 6, 6, 7]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                digest = common.sha256(path, progress=True)
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
            self.assertIn('4,194,304/5,242,880 bytes', output.getvalue())
            self.assertIn('5,242,880/5,242,880 bytes complete', output.getvalue())

if __name__ == '__main__':
    unittest.main()
