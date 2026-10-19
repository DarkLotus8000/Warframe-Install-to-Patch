#!/usr/bin/env python3
"""Build and verify a Warframe update patch from its installed manifests.

Unverifiable assets cause a failed export instead of incomplete publication.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import tempfile
import traceback
import uuid

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / 'data'
if not DATA_DIR.is_dir():
    raise SystemExit('Missing bundled data directory. Extract the COMPLETE release archive.')
sys.path.insert(0, str(DATA_DIR))

import rebuild_patch as core
from common import VERSION, StrictArgumentParser, error as print_error, warning as print_warning

def parser() -> StrictArgumentParser:
    p = StrictArgumentParser(
        description='Reconstruct and deep-verify an update patch from an untouched installation.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('-v', '--version', action='version', version=f'Warframe Install-to-Patch {VERSION}')
    p.add_argument('-t', '--target', type=Path, required=True,
        help='Untouched final Warframe installation')
    p.add_argument('-b', '--base', type=Path, required=True,
        help='Untouched original Steam base')
    p.add_argument('-u', '--source-patch', '--u4401', dest='u4401', type=Path,
        help='Optional exact-identity source patch; unavailable objects are attempted through original CDN URLs')
    output = p.add_mutually_exclusive_group(required=True)
    output.add_argument('-P', '--output-parent', type=Path,
        help='Parent directory for a uniquely named new patch')
    output.add_argument('-o', '--output', type=Path,
        help='Optional exact new patch directory (MUST NOT already exist)')
    p.add_argument('-w', '--work-parent', type=Path,
        help=r'Short-lived work parent, default <target drive>\WF-Rebuild')
    p.add_argument('-l', '--logs-dir', type=Path, default=ROOT / 'logs',
        help='Permanent flat log folder; each run produces <timestamp>.log and <timestamp>.json')
    p.add_argument('-r', '--cdn-retries', type=int, default=5,
        help='Maximum attempts per exact CDN object, including integrity failures (1..20)')
    p.add_argument('-T', '--cdn-timeout', type=float, default=30.0,
        help='Per-request timeout for historical CDN and optional H.Cache download (seconds)')
    p.add_argument('-H', '--h-cache-archive-key', '--h-cache-build-label', type=str, dest='h_cache_build_label',
        help='Optional original H.Cache archive key (build date/cache hash); default: EXE VERSIONINFO + installed H.Cache')
    p.add_argument('-f', '--full-source-hash', action='store_true',
        help='SHA-256 every cache payload in addition to TOCs/selected payloads (slow)')
    p.add_argument('-a', '--all-stripped', action='store_true',
        help='Include every original stripped object from the installed manifests; fail closed if any cannot be verified')
    p.add_argument('-c', '--stripped-cdn-fallback', action='store_true',
        help='With --all-stripped, allow exact manifest hash/type/size CDN fallback after local reconstruction fails')
    p.add_argument('-e', '--keep-failed-output', action='store_true',
        help='Keep failed temporary patch for investigation; never publish it')
    p.add_argument('-k', '--keep-workspace', action='store_true',
        help='Keep isolated recovery bytes for debugging; later runs never reuse them')
    return p

def _save_json_atomic(path: Path, data: dict) -> None:
    """Write logs without a partially overwritten/truncated result."""
    temp = None
    try:
        with tempfile.NamedTemporaryFile('w', prefix='.wf-log-', suffix='.tmp',
                dir=path.parent, delete=False, encoding='utf-8') as f:
            temp = Path(f.name)
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write('\n')
        if path.exists() or path.is_symlink():
            raise FileExistsError(f'Refusing to overwrite an existing log: {path}')
        temp.rename(path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)

def consolidate_logs(logs: Path, run_id: str, exit_code: int, fatal: str | None = None) -> tuple[Path, Path]:
    """Flatten one run's many private audit JSONs into TWO timestamped public log files.

    If consolidation fails, the original directory is deliberately preserved.
    """
    work = logs / run_id
    result = logs / f'{run_id}.json'
    console = logs / f'{run_id}.log'
    if result.exists() or console.exists():
        raise FileExistsError('Timestamped log destination unexpectedly exists; original diagnostics retained')
    if work.is_symlink():
        raise ValueError('Refusing to read or clean a symlinked diagnostic directory')
    evidence: dict[str, object] = {}
    if work.is_dir():
        for source in sorted(work.rglob('*.json')):
            if source.is_symlink() or not source.is_file():
                raise ValueError(f'Unsafe diagnostic file: {source}')
            key = source.relative_to(work).as_posix()
            evidence[key] = json.loads(source.read_text(encoding='utf-8'))
    workflow = evidence.get('workflow-result.json', {})
    summary = {
        'kind': 'warframe-install-to-patch-run',
        'release': VERSION,
        'reconstruction_engine': core.w.VERSION,
        'run_id': run_id,
        'exit_code': exit_code,
        'status': workflow.get('status', 'failed') if isinstance(workflow, dict) else 'failed',
        'output': workflow.get('patch_output') if isinstance(workflow, dict) else None,
        'failure': fatal,
        'console_log': str(console),
        'details': evidence,
    }
    logs.mkdir(parents=True, exist_ok=True)
    # Write the consolidated JSON BEFORE removing any of the original evidence.
    _save_json_atomic(result, summary)
    original_log = work / 'clean-run-console.log'
    try:
        if original_log.is_file() and not original_log.is_symlink():
            # Same-volume logs directory: preserving the exact full console transcript.
            original_log.rename(console)
        else:
            console.write_text((fatal or 'Run stopped before console capture was initialized.') + '\n', encoding='utf-8')
    except BaseException:
        # Never throw away the unmerged reports if the console log cannot be created.
        raise
    # Only after both public log files exist is it safe to discard intermediate reports.
    if work.exists():
        shutil.rmtree(work)
    return console, result

def main(argv: list[str] | None = None) -> int:
    p = parser()
    opts = p.parse_args(argv)
    if not 1 <= opts.cdn_retries <= 20:
        p.error('--cdn-retries must be between 1 and 20')
    if not 1 <= opts.cdn_timeout <= 120:
        p.error('--cdn-timeout must be between 1 and 120 seconds')
    if opts.stripped_cdn_fallback and not opts.all_stripped:
        p.error('--stripped-cdn-fallback requires --all-stripped')
    if opts.h_cache_build_label is not None:
        try:
            core.normalize_archive_key(opts.h_cache_build_label)
        except core.CleanRunError as exc:
            p.error(str(exc))
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    logs = opts.logs_dir.resolve(strict=False)
    print(f'[Install-to-Patch {VERSION}] Manifest-derived recovery')
    print('[Inputs] Only installed target manifests and independently authenticated recovery objects')
    print('[Run] One command; no earlier run data, no runtime-request list, no old patch reuse')
    print(f'[Logs] {logs / (run_id + ".log")} and {logs / (run_id + ".json")}')
    code = 2
    failure = None
    try:
        if logs.is_symlink():
            raise ValueError('Log folder must not be a symlink')
        code = core.build(opts, work_parent=opts.work_parent, report_root=logs, run_id=run_id)
    except KeyboardInterrupt:
        code = 130
        failure = 'Interrupted by user'
        print_warning(failure, file=sys.stderr)
    except Exception as exc:
        code = 2
        failure = f'{type(exc).__name__}: {exc}'
        print_error(failure)
        traceback.print_exc()
    # Never fail silently: even failed initial checks get an exit report.
    try:
        console, result = consolidate_logs(logs, run_id, code, failure)
        print(f'[Log] {console}')
        print(f'[Result] {result}')
    except Exception as exc:
        print_error(f'Log consolidation failed: {exc}; intermediate reports, if any, retained under {logs / run_id}')
        if code == 0:
            code = 2
    return code

if __name__ == '__main__':
    raise SystemExit(main())
