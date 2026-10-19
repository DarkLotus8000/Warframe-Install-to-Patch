"""Crash-conscious, fail-closed publication of locally generated Warframe patches.

Only a staging directory created by this invocation is eligible for cleanup.
The final output is never overwritten or deleted. Diagnostics live outside it.
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import sys
import tempfile
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Any

def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()

class TransactionFailure(RuntimeError):
    """A controlled unsuccessful export, preflight, or post-export audit."""

from common import PlainLogTee as _Tee, error as print_error

def _write_json(path: Path, doc: dict) -> None:
    # Do not leave a truncated result file after an interrupted write.
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', dir=path.parent, prefix='.export-result-',
                                     suffix='.tmp', encoding='utf-8', delete=False) as handle:
        temporary = Path(handle.name)
        try:
            json.dump(doc, handle, indent=2, ensure_ascii=False)
            handle.write('\n')
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)

def execute(*, final_output: Path, diagnostics_dir: Path, version: str,
            export: Callable[[Path, list[dict]], int],
            verify: Callable[[Path], dict],
            preflight: Callable[[], bool] | None = None,
            keep_failed_output: bool = False,
            protected_sources: tuple[Path | None, ...] = (),
            post_audit_report: Path | None = None,
            preflight_report: Path | None = None) -> int:
    """Run preflight/export/deep audit and publish only after verification.

    Callbacks may raise exceptions. The return status, log, failed objects, and
    post-audit findings are recorded even when work fails partway through.
    """
    final = final_output.resolve(strict=False)
    diagnostics = diagnostics_dir.resolve(strict=False)
    sources = [path.resolve(strict=False) for path in protected_sources if path is not None]
    # The caller may put its recovery directories inside the project folder,
    # so an ancestor of one source is allowed for diagnostics. Writing reports
    # *inside* any source or final patch is forbidden.
    if diagnostics == final or diagnostics.is_relative_to(final):
        raise TransactionFailure('Diagnostics directory must be outside the final patch')
    for source in sources:
        if diagnostics == source or diagnostics.is_relative_to(source):
            raise TransactionFailure(f'Diagnostics directory must not be inside a source: {source}')
    if post_audit_report is not None:
        report = post_audit_report.resolve(strict=False)
        if report == final or report.is_relative_to(final):
            raise TransactionFailure('Post-audit report must be outside the patch')
        for source in sources:
            if report == source or report.is_relative_to(source):
                raise TransactionFailure('Post-audit report must be outside source inputs')
    # Project-local unique filenames avoid destroying useful older failure logs.
    diagnostics.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    log_path = diagnostics / f'export-console-{run_id}.log'
    result_path = diagnostics / f'export-result-{run_id}.json'
    details: dict[str, Any] = {
        'version': version, 'kind': 'install-to-patch-export-result',
        'run_id': run_id, 'started_utc': _utc(), 'finished_utc': None,
        'status': 'started', 'phase': 'initialization', 'exit_code': None,
        'final_output': str(final), 'staging_output': None,
        'keep_failed_output': keep_failed_output, 'cleanup': 'not-needed',
        'failed_objects': [], 'errors': [],
        'console_log': str(log_path), 'result_report': str(result_path),
        'preflight_report': str(preflight_report.resolve(strict=False)) if preflight_report else None,
        'post_audit_report': str(post_audit_report.resolve(strict=False)) if post_audit_report else None,
    }
    staged: Path | None = None
    published = False
    failure_code = 2
    with log_path.open('w', encoding='utf-8', buffering=1) as logfile:
        with contextlib.redirect_stdout(_Tee(sys.stdout, logfile)), contextlib.redirect_stderr(_Tee(sys.stderr, logfile)):
            try:
                print(f'[Transaction] Final patch: {final}')
                print(f'[Transaction] Diagnostics: {diagnostics}')
                for source in sources:
                    if final == source or final.is_relative_to(source) or source.is_relative_to(final):
                        raise TransactionFailure(f'Patch output must not overlap a source: {source}')
                # Checking the final path before creating staging prevents treating
                # an existing empty directory as disposable data.
                if final.exists() or final.is_symlink():
                    raise TransactionFailure(f'Final patch path already exists; refusing to overwrite: {final}')
                details['phase'] = 'preflight'
                if preflight is not None and not preflight():
                    raise TransactionFailure('Preflight did not pass; no patch was generated')
                if final.exists() or final.is_symlink():
                    raise TransactionFailure(f'Final patch path appeared during preflight: {final}')
                # Short sibling filename avoids Windows MAX_PATH regressions.
                # mkdtemp creates this exact directory exclusively; it is the
                # only directory later eligible for recursive deletion.
                final.parent.mkdir(parents=True, exist_ok=True)
                staged = Path(tempfile.mkdtemp(prefix='.wf-stage-', dir=final.parent))
                details['staging_output'] = str(staged)
                print(f'[Transaction] New temporary patch: {staged}')
                details['phase'] = 'export'
                if export(staged, details['failed_objects']) != 0:
                    raise TransactionFailure('One or more CDN objects failed to export')
                details['phase'] = 'deep-post-audit'
                post_report = verify(staged)
                details['post_audit'] = {
                    'hard_issue_total': post_report.get('hard_issue_total'),
                    'hard_issue_counts': post_report.get('hard_issue_counts'),
                    'counts': {k: post_report.get('counts', {}).get(k, 0) for k in (
                        'expected_export_files', 'patch_files_valid_name_size',
                        'patch_deep_verified', 'patch_metadata_verified')},
                }
                if post_audit_report is not None:
                    # Record the staging path that was actually audited. On
                    # successful publication, also identify the final path.
                    post_report['publication_target'] = str(final)
                    _write_json(post_audit_report, post_report)
                    print(f'[Post-export report] {post_audit_report}')
                counts = post_report.get('counts', {})
                expected = counts.get('expected_export_files')
                if (post_report.get('hard_issue_total') != 0
                        or not isinstance(expected, int) or expected <= 0
                        or counts.get('patch_files_valid_name_size') != expected
                        or counts.get('patch_deep_verified') != expected
                        or counts.get('patch_metadata_verified', 0) <= 0):
                    raise TransactionFailure('Deep post-export audit failed or had incomplete object coverage')
                details['phase'] = 'publishing'
                if final.exists() or final.is_symlink():
                    raise TransactionFailure(f'Final output appeared before publication; refusing overwrite: {final}')
                staged.rename(final)  # same-volume directory rename
                published = True
                staged = None
                details['staging_output'] = None
                details['status'] = 'verified-and-published'
                details['phase'] = 'done'
                details['cleanup'] = 'not-needed'
                details['exit_code'] = 0
                print(f'[Published] {final}: {expected:,}/{expected:,} CDN objects passed deep verification')
                failure_code = 0
            except (Exception, KeyboardInterrupt) as exc:
                details['status'] = 'interrupted' if isinstance(exc, KeyboardInterrupt) else 'failed'
                failure_code = 130 if isinstance(exc, KeyboardInterrupt) else 2
                details['exit_code'] = failure_code
                details['errors'].append({'phase': details['phase'], 'type': type(exc).__name__, 'message': str(exc)})
                print_error(f'Transaction failed during {details["phase"]}: {exc}')
                # Preserve full traceback for debugging unexpected exceptions.
                if not isinstance(exc, (TransactionFailure, KeyboardInterrupt)):
                    traceback.print_exc()
                # Persist failure evidence *before* cleanup. If the result
                # JSON cannot be written, retain the temporary patch rather
                # than discard data while troubleshooting is degraded.
                diagnostics_saved = False
                if staged is not None:
                    details['cleanup'] = 'pending'
                    try:
                        logfile.flush()
                        _write_json(result_path, details)
                        diagnostics_saved = True
                    except OSError as save_exc:
                        details['errors'].append({'phase': 'save-before-cleanup',
                                                  'type': type(save_exc).__name__,
                                                  'message': str(save_exc)})
                        print_error(f'Failed saving diagnostics; temporary patch retained: {save_exc}')
                if staged is not None:
                    if keep_failed_output or not diagnostics_saved:
                        try:
                            marker = staged / '.install-to-patch.failed'
                            old = staged / '.install-to-patch.in-progress'
                            if old.exists():
                                old.replace(marker)
                            else:
                                marker.write_text('Failed transactional export; do not use.\n', encoding='utf-8')
                            details['cleanup'] = ('retained-by-request' if keep_failed_output
                                                  else 'retained-diagnostics-write-failed')
                            print(f'[Kept failed patch] {staged}')
                        except OSError as marker_exc:
                            details['cleanup'] = 'retained-marker-write-failed'
                            details['errors'].append({'phase': 'failed-marker', 'type': type(marker_exc).__name__, 'message': str(marker_exc)})
                    else:
                        try:
                            # Only the exclusively created staging folder may
                            # be deleted, never the final patch or a source.
                            shutil.rmtree(staged)
                            details['staging_output'] = None
                            details['cleanup'] = 'temporary-patch-deleted'
                            print('[Cleanup] Temporary patch deleted; reports and log retained')
                        except OSError as cleanup_exc:
                            details['cleanup'] = 'cleanup-failed-temporary-patch-retained'
                            details['errors'].append({'phase': 'cleanup', 'type': type(cleanup_exc).__name__, 'message': str(cleanup_exc)})
                            print_error(f'Failed to delete temporary patch {staged}: {cleanup_exc}')
                if not published and final.exists():
                    print(f'[Safety] Final output was not deleted: {final}', file=sys.stderr)
            finally:
                details['finished_utc'] = _utc()
                try:
                    _write_json(result_path, details)
                    print(f'[Result report] {result_path}')
                    print(f'[Console log] {log_path}')
                except OSError as report_exc:
                    # Do not delete an already published patch because writing
                    # a diagnostic report failed. The console log is still kept.
                    print(f'[Result report error] {report_exc}', file=sys.stderr)
                    if failure_code == 0:
                        failure_code = 2
    return failure_code
