#!/usr/bin/env python3
"""Extend a reconstructed patch with verified stripped objects or audit its videos."""
from __future__ import annotations

import contextlib
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import traceback
import uuid

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'data'))
import stripped_archive

from common import PRODUCT_VERSION, PlainLogTee as Tee, StrictArgumentParser, error as print_error, label as color_label

def parser() -> StrictArgumentParser:
    p = StrictArgumentParser(repeatable_destinations={'source_patch'}, description='Recover manifest-declared stripped CDN objects or audit existing videos.')
    p.add_argument('-v', '--version', action='version', version=f'Warframe Install-to-Patch {PRODUCT_VERSION}')
    p.add_argument('-p', '--patch', type=Path, required=True, help='Existing completed update patch (modified only after verification)')
    p.add_argument('-t', '--target', type=Path, required=True, help='Untouched final installation corresponding to the patch')
    p.add_argument('-b', '--base', type=Path, required=True, help='Untouched Steam base')
    p.add_argument('-s', '--source-patch', type=Path, action='append', default=[], metavar='DIR',
                   help='Read-only patch source; repeatable for recovery or -A video comparisons')
    p.add_argument('-c', '--cdn-fallback', action='store_true', help='Allow exact hash-pinned CDN downloads after offline recovery')
    p.add_argument('-A', '--audit-videos', action='store_true',
                   help='Read-only audit of existing stripped .bk2 video F bytes against original caches')
    p.add_argument('-n', '--dry-run', action='store_true',
                   help='Stage and verify recoverable objects, but do not change the patch')
    p.add_argument('-r', '--retries', type=int, default=5, help='Maximum CDN attempts per object (1..20; default 5)')
    p.add_argument('-f', '--full-source-hash', action='store_true', help='Hash all source cache payloads before/after')
    p.add_argument('-l', '--logs-dir', type=Path, default=ROOT/'logs')
    return p

def main(argv=None):
    p = parser()
    cli_args = list(sys.argv[1:] if argv is None else argv)
    opts = p.parse_args(cli_args)
    explicit_retries = any(x in ('-r', '--retries') or x.startswith('--retries=')
                           for x in cli_args)
    if opts.audit_videos and (opts.cdn_fallback or opts.dry_run
                              or opts.full_source_hash or explicit_retries):
        p.error('--audit-videos is read-only and cannot be combined with CDN recovery, '
                'dry-run, retry or full-source-hash options')
    if not 1 <= opts.retries <= 20:
        p.error('--retries must be 1..20')
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    if opts.logs_dir.is_symlink():
        p.error("Logs directory must not be a symlink")
    logs = opts.logs_dir.resolve(strict=False)
    if any(logs == src.resolve(strict=False) or logs.is_relative_to(src.resolve(strict=False))
           for src in (opts.patch, opts.target, opts.base, *opts.source_patch)):
        p.error('Logs must be outside all input/output directories')
    logs.mkdir(parents=True, exist_ok=True)
    log = logs / f'{run_id}.log'
    result_file = logs / f'{run_id}.json'
    result = {'kind':('video-byte-audit' if opts.audit_videos else 'stripped-assets-extension'), 'release':PRODUCT_VERSION, 'run_id':run_id, 'patch':str(opts.patch),
              'target':str(opts.target), 'base':str(opts.base), 'cdn_fallback':opts.cdn_fallback,
              'retries':opts.retries, 'dry_run':opts.dry_run,
              'source_patches':[str(path) for path in opts.source_patch],
              'status':'failed'}
    attempts = []
    with log.open('w', encoding='utf-8') as out:
        with contextlib.redirect_stdout(Tee(sys.stdout,out)), contextlib.redirect_stderr(Tee(sys.stderr,out)):
            try:
                if opts.audit_videos:
                    counts = stripped_archive.audit_existing_videos(
                        patch=opts.patch, target=opts.target, base=opts.base,
                        source_patches=tuple(opts.source_patch))
                    result['counts'] = counts
                    result['status'] = ('failed' if counts['failed'] or
                                        counts['source_comparison_counts']['invalid'] or
                                        counts['source_comparison_counts']['ambiguous'] else
                                        'incomplete' if counts['base_only'] or counts['inconclusive']
                                        else 'complete')
                    print(f'{color_label("Complete" if result["status"] == "complete" else
                                         "Failed" if result["status"] == "failed" else "Incomplete")} '
                          f'Video audit: {counts["target_f_verified"]}/{counts["total"]} '
                          'match pristine installation F bytes; patch unchanged')
                else:
                    counts = stripped_archive.add_missing(patch=opts.patch, target=opts.target,
                                  base=opts.base, allow_cdn=opts.cdn_fallback,
                                  full_source_hash=opts.full_source_hash,
                                  retries=opts.retries, source_patches=tuple(opts.source_patch),
                                  attempt_history=attempts, dry_run=opts.dry_run)
                    result['counts'] = counts
                    result['status'] = ('incomplete' if counts['unresolved'] else 'complete')
                    if opts.dry_run:
                        print(f'{color_label("Incomplete" if counts["unresolved"] else "Complete")} '
                              f'Check-only: {counts["would_add"]} '
                              f'objects would be added; {counts["unresolved"]} unresolved; '
                              f'patch unchanged (local {counts["local"]}, '
                              f'source patches {counts["source"]}, CDN {counts["cdn"]})')
                    else:
                        print(f'{color_label("Complete")} {counts["total"]} stripped entries covered; '
                              f'{counts["added"]} added (local {counts["local"]}, '
                              f'source patches {counts["source"]}, CDN {counts["cdn"]})')
            except KeyboardInterrupt:
                result['error'] = 'Interrupted by user'
                result['status'] = 'interrupted'
                print_error('Interrupted by user; staged changes were rolled back')
            except Exception as exc:
                result['error'] = f'{type(exc).__name__}: {exc}'
                print_error(result['error'])
                traceback.print_exc()
            finally:
                result['cdn_attempts'] = attempts
                result_file.write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
                print(f'[Logs] {log} | {result_file}')
    return {'complete': 0, 'incomplete': 3, 'interrupted': 130}.get(result['status'], 2)

if __name__ == '__main__':
    raise SystemExit(main())
