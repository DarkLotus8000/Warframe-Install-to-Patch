#!/usr/bin/env python3
"""One-run, clean-source Warframe patch reconstruction and verification.

Always creates a fresh, isolated work directory. Never reads previous recovery
reports or old patch exports. Only original installed manifests decide the
output membership. No runtime-log/525 forced-unchanged entries are imported.

Absent objects are identified from the installed manifests, checked against
an optional exact source patch, then recovered from the manifest-addressed CDN
when needed. No hardcoded object hashes or expected recovery counts are used.
"""
from __future__ import annotations

from common import StrictArgumentParser

import argparse
import contextlib
from datetime import datetime, timezone
import json
import importlib.util
import inspect
import re
import hashlib
from urllib.error import HTTPError, URLError
import time
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPRedirectHandler
from pathlib import Path
import shutil
import sys
import traceback
import uuid

import common as fingerprint
import compare_sources as compare_u4401
import export_transaction as tx
import offline_patch_audit as offline
import recover_manifest_sources as historical
import source_inventory as restore
import warframe_install_to_patch as w
import stripped_archive

# The EXE VERSIONINFO ProductVersion is the build date. The archive suffix
# comes from the B.Cache.Windows.bin manifest hash inside H.Cache.bin.
_BUILD_DATE = re.compile(r'20\d{2}\.\d{2}\.\d{2}\.\d{2}\.\d{2}\Z')
_H_CACHE_ARCHIVE_KEY = re.compile(r'(20\d{2}\.\d{2}\.\d{2}\.\d{2}\.\d{2})/([A-Za-z0-9+\-]{22})\Z')
_H_CACHE_ROOT = 'https://openwf.io/supplementals/static%20data/'
_H_CACHE_MAX_BYTES = 1024 * 1024

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def normalize_build_date(value: str) -> str:
    if not _BUILD_DATE.fullmatch(value):
        raise CleanRunError('Expected EXE ProductVersion date YYYY.MM.DD.HH.MM')
    try:
        datetime.strptime(value, '%Y.%m.%d.%H.%M')
    except ValueError as exc:
        raise CleanRunError('Invalid EXE ProductVersion date') from exc
    return value

def normalize_archive_key(value: str) -> str:
    match = _H_CACHE_ARCHIVE_KEY.fullmatch(value)
    if match is None:
        raise CleanRunError('Expected H.Cache archive key YYYY.MM.DD.HH.MM/22-character-hash')
    normalize_build_date(match[1])
    return value

def _pe_text(value: str | bytes) -> str:
    if isinstance(value, str):
        return value.rstrip('\x00')
    if b'\x00' in value:
        return value.decode('utf-16le', errors='replace').rstrip('\x00')
    return value.decode('utf-8', errors='replace').rstrip('\x00')

def find_executable_build_date(exe: Path) -> str | None:
    """Read the date-only ProductVersion from the executable's PE VERSIONINFO."""
    import pefile
    try:
        pe = pefile.PE(str(exe), fast_load=True)
    except (OSError, pefile.PEFormatError):
        return None
    try:
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
            ])
        except pefile.PEFormatError:
            return None
        dates = set()
        for group in getattr(pe, 'FileInfo', ()) or ():
            entries = group if isinstance(group, (list, tuple)) else (group,)
            for entry in entries:
                for table in getattr(entry, 'StringTable', ()) or ():
                    for key, value in table.entries.items():
                        if _pe_text(key).casefold() != 'productversion':
                            continue
                        try:
                            dates.add(normalize_build_date(_pe_text(value)))
                        except CleanRunError:
                            continue
        return next(iter(dates)) if len(dates) == 1 else None
    finally:
        pe.close()

def original_h_cache_archive_key(exe: Path, installed_h: bytes) -> str | None:
    """Combine the EXE's build date with the original Windows B.Cache hash."""
    date = find_executable_build_date(exe)
    if date is None:
        return None
    records = [r for r in w.parse_h_cache_header(installed_h).records
        if r.logical_path == '/B.Cache.Windows.bin']
    if len(records) != 1 or len(records[0].target_hash) != 16:
        raise CleanRunError('Expected a unique B.Cache.Windows.bin hash in installed H.Cache.bin')
    return normalize_archive_key(date + '/' + w.b64m_encode(records[0].target_hash))

def h_cache_url(archive_key: str) -> str:
    date, digest = normalize_archive_key(archive_key).split('/', 1)
    return _H_CACHE_ROOT + quote('H.Cache_' + date + '_' + digest + '.bin', safe='.')

def fetch_original_h_cache(archive_key: str, *, timeout: float, retries: int = 5,
        opener=None, sleeper=None, verify_func=None) -> tuple[bytes | None, dict]:
    """Fetch one exact archived H.Cache.bin, retrying only transient failures."""
    if not 1 <= retries <= 20:
        raise ValueError('H.Cache retries must be between 1 and 20')
    url = h_cache_url(archive_key)
    summary = {'archive_key': archive_key, 'url': url, 'status': 'not-found', 'attempts': 0}
    opener = opener or build_opener(_NoRedirect())
    pause = time.sleep if sleeper is None else sleeper
    request = Request(url, headers={'User-Agent': 'Warframe-Install-to-Patch/0.1', 'Accept': 'application/octet-stream'})
    for attempt in range(1, retries + 1):
        summary['attempts'] = attempt
        try:
            with opener.open(request, timeout=timeout) as response:
                code = response.getcode()
                if code != 200:
                    raise CleanRunError(f'Unexpected H.Cache HTTP {code}')
                payload = response.read(_H_CACHE_MAX_BYTES + 1)
        except HTTPError as exc:
            if exc.code in (404, 410):
                summary['http_status'] = exc.code
                return None, summary
            retryable = exc.code in fingerprint.RETRYABLE_HTTP or 500 <= exc.code <= 599
            failure = f'H.Cache host returned HTTP {exc.code}'
        except (OSError, URLError, TimeoutError) as exc:
            retryable = True
            failure = f'H.Cache network request failed: {exc}'
        else:
            if len(payload) > _H_CACHE_MAX_BYTES:
                raise CleanRunError('H.Cache web object exceeds 1 MiB limit')
            if verify_func is not None:
                try:
                    verify_func(payload)
                except (w.ExportError, ValueError) as exc:
                    if attempt == retries:
                        raise HCacheVerificationError(f'H.Cache verification failed after {attempt} attempts: {exc}') from exc
                    delay = min(2 ** (attempt - 1), 8)
                    print_warning(f'H.Cache verification failed on attempt {attempt}/{retries}: '
                        f'{exc}; retrying in {delay}s')
                    pause(delay)
                    continue
            summary.update({'status': 'downloaded', 'http_status': 200, 'bytes': len(payload),
                'sha256': hashlib.sha256(payload).hexdigest()})
            return payload, summary
        if not retryable or attempt == retries:
            raise CleanRunError(f'{failure} (attempt {attempt}/{retries})')
        delay = min(2 ** (attempt - 1), 8)
        print_warning(f'H.Cache download attempt {attempt}/{retries} failed: {failure}; retrying in {delay}s')
        pause(delay)
    raise AssertionError('Unreachable H.Cache retry state')

PROJECT = Path(__file__).resolve().parent
MANIFEST_TYPE = 0xE  # H.Cache.bin/B.Cache CDN metadata type.

def export_arguments(videos: Path | None, honly: Path | None, comparison_file: Path | None,
        u4401: Path | None, output: Path, failures: list[dict],
        required_families: tuple[str, ...] = (), require_static_types: bool = False) -> dict:
    """One source of truth for the direct export_patch() API contract."""
    return dict(manifest_type=MANIFEST_TYPE, dry_run=False, require_complete=False,
        recovered_cdn_dir=videos, recovered_h_only_dir=honly,
        u4401_patch=u4401, u4401_report=comparison_file if u4401 is not None else None,
        required_manifest_families=required_families,
        static_type_recovery=True, require_static_types=require_static_types,
        published_output_root=output,
        failure_collector=failures)

def validate_export_contract(target: Path, base: Path, u4401: Path | None,
        workspace: Path, output: Path) -> None:
    """Fail before source scans/downloads if the one-click exporter API drifted."""
    args = export_arguments(workspace / 'recovered-videos',
        workspace / 'recovered-h-only',
        workspace / 'u4401-report.json', u4401, output, [])
    try:
        inspect.signature(w.export_patch).bind(target, base, workspace / 'staging', **args)
    except TypeError as exc:
        raise CleanRunError(f'Internal exporter interface mismatch (no download attempted): {exc}') from exc

class CleanRunError(RuntimeError):
    pass

class HCacheVerificationError(CleanRunError):
    """Downloaded object failed semantic verification; never use a silent fallback."""

from common import PlainLogTee as Tee, error as print_error, warning as print_warning

def write_json(path: Path, data: dict) -> None:
    restore.save_report(path, data)

def validate_roots(target: Path, base: Path, u4401: Path | None, output: Path,
        workspace: Path, report_dir: Path) -> None:
    sources = [x.resolve(strict=True) for x in (target, base, u4401) if x is not None]
    if len(set(sources)) != len(sources) or not all(x.is_dir() for x in sources):
        raise CleanRunError('Target, Steam base and optional source patch must be distinct directories')
    writable = [x.resolve(strict=False) for x in (output, workspace, report_dir)]
    if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
           for i, a in enumerate(sources) for b in sources[i+1:]):
        raise CleanRunError('Source directories overlap; cannot independently verify them')
    for source in sources:
        for dest in writable:
            if dest == source or dest.is_relative_to(source) or source.is_relative_to(dest):
                raise CleanRunError(f'An output/work/report directory overlaps a protected source: {source}')
    for i, dest in enumerate(writable):
        if any(dest == other or dest.is_relative_to(other) or other.is_relative_to(dest)
               for other in writable[i+1:]):
            raise CleanRunError('Output, recovery workspace and reports directories must not overlap')
    if any(path.is_symlink() for path in (target, base, u4401, output.parent,
            workspace.parent, report_dir.parent) if path is not None):
        raise CleanRunError('Root directory symlink detected; refusing unsafe reconstruction')
    if output.exists() or output.is_symlink():
        raise CleanRunError(f'Fresh output already exists; refusing to overwrite: {output}')
    for source in (target, base):
        if not w.find_cache_windows_dir(source).is_dir():
            raise CleanRunError(f'Missing Cache.Windows in required source: {source}')
    w._find_target_exe(target)
    if u4401 is not None:
        compare_u4401.safe_patch_content(u4401)
    if workspace.exists() or workspace.is_symlink():
        raise CleanRunError(f'Fresh workspace already exists; refusing to reuse: {workspace}')
    # Recovery object paths are checked from the actual manifest inventory.

def snapshot_target_executable(target: Path) -> dict:
    """Fingerprint the actual executable used to resolve installed type IDs."""
    exe = w._find_target_exe(target)
    if exe.is_symlink():
        raise CleanRunError(f'Reference executable must not be a symlink: {exe}')
    stat_before = exe.stat()
    digest = fingerprint.sha256(exe)
    stat_after = exe.stat()
    if (stat_before.st_size, stat_before.st_mtime_ns) != (stat_after.st_size, stat_after.st_mtime_ns):
        raise CleanRunError('Reference executable changed while being fingerprinted')
    return {'path': str(exe.resolve(strict=True)), 'size': stat_after.st_size,
            'mtime_ns': stat_after.st_mtime_ns, 'sha256': digest}

def check_target_executable(target: Path, baseline: dict, report_dir: Path, phase: str) -> None:
    current = snapshot_target_executable(target)
    changed = current['sha256'] != baseline['sha256'] or current['size'] != baseline['size']
    write_json(report_dir / f'executable-fingerprint-{phase}.json',
        {'phase': phase, 'baseline': baseline, 'observed': current,
        'content_changed': changed})
    if changed:
        raise CleanRunError(f'Reference executable changed during this run ({phase}); refusing publication')

def read_only_snapshot(root: Path, *, full_hash: bool) -> dict:
    return fingerprint.snapshot(root, all_cache=full_hash)

def check_source_unchanged(target: Path, base: Path, baselines: dict,
        report_dir: Path, phase: str, full_hash: bool) -> None:
    for key, source in (('target', target), ('base', base)):
        later = read_only_snapshot(source, full_hash=full_hash)
        before = baselines[key]
        differences = fingerprint.compare(before, later)
        write_json(report_dir / f'cache-diff-{phase}-{key}.json', differences)
        counts = differences['counts']
        # TOCs (and optionally every .cache) are cryptographically verified.
        # Treat any stat change to unhashed content as suspicious, too.
        suspect = sum(counts[x] for x in ('added', 'removed', 'content_changed', 'stat_changed_unhashed'))
        if suspect:
            raise CleanRunError(f'{source} changed during this run ({phase}); {suspect} cache files require review')
        if counts['timestamp_only']:
            print(f'[Fingerprint] {phase}: {key} has {counts["timestamp_only"]} timestamp-only changes; bytes unchanged')
    print(f'[Fingerprint] {phase}: installed reference and Steam base have no cache-content changes')

def stash_workspace_reports(workspace: Path, report_dir: Path) -> None:
    """Keep reports/logs, not recovered CDN bytes or patch output, after run."""
    for path in sorted(workspace.glob('*.json')) + sorted(workspace.glob('*.log')):
        if path.is_symlink() or not path.is_file():
            raise CleanRunError(f'Unexpected non-regular report: {path}')
        dest = report_dir / path.name
        if dest.exists() or dest.is_symlink():
            raise CleanRunError(f'Refusing to overwrite an existing diagnostic report: {dest}')
        shutil.copy2(path, dest)
        if dest.name.startswith('export-result-') and dest.suffix == '.json':
            # The transaction initially records temporary report paths. Update
            # only the relocated copy; never edit already-written evidence.
            result = json.loads(dest.read_text(encoding='utf-8'))
            for field in ('console_log', 'result_report', 'preflight_report', 'post_audit_report'):
                value = result.get(field)
                if value and Path(value).parent == workspace:
                    result[field] = str(report_dir / Path(value).name)
            write_json(dest, result)
    # Recovery-specific validation reports also matter when investigating a
    # corrupted or unavailable historical CDN object. Keep JSON evidence but
    # NEVER copy recovered asset bytes into permanent reports.
    recovered = workspace / historical.RECOVERY_DIR
    if recovered.is_symlink():
        raise CleanRunError(f'Unsafe recovery report directory: {recovered}')
    if recovered.is_dir():
        for name in ('recovered-videos', 'recovered-h-only'):
            folder = recovered / name
            if folder.is_symlink():
                raise CleanRunError(f'Unsafe recovery report directory: {folder}')
            if not folder.is_dir():
                continue
            for path in sorted(folder.glob('*.json')):
                if path.is_symlink() or not path.is_file():
                    raise CleanRunError(f'Unsafe nested recovery report: {path}')
                destination = report_dir / 'recovery' / name / path.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists() or destination.is_symlink():
                    raise CleanRunError(f'Refusing to overwrite a recovery report: {destination}')
                shutil.copy2(path, destination)

def build(args: argparse.Namespace, *, work_parent: Path | None = None,
        report_root: Path | None = None, run_id: str | None = None) -> int:
    target, base, u4401 = args.target, args.base, args.u4401
    if work_parent is None:
        work_parent = Path(target.resolve(strict=False).anchor) / 'WF-Rebuild'
    if report_root is None:
        report_root = PROJECT / 'reports'
    if run_id is None:
        run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    workspace = work_parent / run_id
    report_dir = report_root / run_id
    output = getattr(args, 'output', None) or (args.output_parent / f'Warframe-{run_id}')
    # The report root is independently protected even when an input is missing
    # or another preflight check fails, so failed initialization has a JSON log.
    report_real = report_dir.resolve(strict=False)
    for source in (target, base, u4401):
        if source is None:
            continue
        protected = source.resolve(strict=False)
        if report_real == protected or report_real.is_relative_to(protected) or protected.is_relative_to(report_real):
            raise CleanRunError(f'Report folder overlaps a protected input: {source}')
    if report_real == output.resolve(strict=False) or report_real.is_relative_to(output.resolve(strict=False)):
        raise CleanRunError('Report folder cannot be inside final output')
    if report_dir.parent.is_symlink():
        raise CleanRunError('Report folder parent cannot be a symlink')
    report_dir.mkdir(parents=True, exist_ok=False)
    report_log = report_dir / 'clean-run-console.log'
    workflow = {
        'version': w.VERSION, 'kind': 'manifest-driven-patch-rebuild',
        'run_id': run_id, 'status': 'started', 'phase': 'init',
        'reference': str(target), 'steam_base': str(base),
        'exact_source_patch': str(u4401) if u4401 is not None else None, 'patch_output': str(output),
        'report_folder': str(report_dir), 'network': 'manifest-addressed CDN URLs plus optional H.Cache lookup',
        'sources_from_failed_runs': False, 'force_unchanged_runtime_resources': False,
        'all_stripped': bool(getattr(args, 'all_stripped', False)),
        'scope': [], 'limitations': [
            'Patch application must be verified against its original Steam base.',
            'Missing objects require exact validated sources; installation-only recovery is not guaranteed.'
        ],
    }
    workspace_created = False
    copied_reports = False
    code = 2
    with report_log.open('w', encoding='utf-8', buffering=1) as logfile:
        with contextlib.redirect_stdout(Tee(sys.stdout, logfile)), contextlib.redirect_stderr(Tee(sys.stderr, logfile)):
            try:
                workflow['phase'] = 'validate-inputs'
                validate_roots(target, base, u4401, output, workspace, report_dir)
                print(f'[Clean] Untouched final installation: {target}')
                print(f'[Clean] Original Steam base: {base}')
                if u4401 is not None:
                    print(f'[Clean] Exact recovery source patch: {u4401}')
                else:
                    print('[Clean] No source patch supplied; trying manifest-identical CDN objects')
                print(f'[Clean] New isolated recovery workspace: {workspace}')
                print(f'[Clean] Fresh final patch destination: {output}')
                print(f'[Clean] Permanent reports: {report_dir}')
                print('[Clean] Fresh manifest inventory; no prior recovery reports used')
                print('[Network] Manifest-addressed recovery; optional original H.Cache lookup.')
                workflow['phase'] = 'verify-installed-dependencies'
                needed = ('pefile', 'capstone', 'numpy')
                missing = [module for module in needed if importlib.util.find_spec(module) is None]
                if missing:
                    raise CleanRunError('Installed executable type analysis requires '
                        + ', '.join(missing)
                        + '; install requirements.txt before rebuilding')
                # The SHA-256-pinned bundled Oodle DLL lives in data/, not the
                # short-path workspace. Validate it before any network access.
                oodle = w.Oodle(PROJECT)
                oodle._load()  # Verify the pinned x64 DLL BEFORE attempting any network access.
                workflow['phase'] = 'verify-exporter-interface'
                validate_export_contract(target, base, u4401, workspace, output)
                print('[Clean] Direct exporter API validated before scanning or downloading')
                workflow['phase'] = 'baseline-snapshots'
                before = {key: read_only_snapshot(source, full_hash=args.full_source_hash)
                    for key, source in (('target', target), ('base', base))}
                for key, value in before.items():
                    write_json(report_dir / f'cache-snapshot-before-{key}.json', value)
                baseline_exe = snapshot_target_executable(target)
                write_json(report_dir / 'executable-fingerprint-before.json', baseline_exe)
                workspace.parent.mkdir(parents=True, exist_ok=True)
                workspace.mkdir(exist_ok=False)
                workspace_created = True
                # This directory is freshly created, with no reports or previous recovery content.
                if list(workspace.iterdir()):
                    raise CleanRunError('Fresh workspace is unexpectedly nonempty')
                workflow['phase'] = 'manifest-source-recovery'
                recovery = historical.run(workspace, download=True, timeout=args.cdn_timeout,
                    oodle=oodle, retries=args.cdn_retries,
                    fresh_sources=(target, base, u4401))
                required = recovery['summary']['required']
                recovered = recovery['summary']['fully_verified']
                if recovered != required:
                    raise CleanRunError(f'Only {recovered}/{required} missing CDN objects recovered; refusing publication')
                comparison_file = workspace / historical.COMPARISON_REPORT
                source_comparison = json.loads(comparison_file.read_text(encoding='utf-8'))
                totals = source_comparison['summary']
                verified_source = totals.get('exact_objects_verified')
                if (totals.get('exact_objects_rejected') != 0
                        or totals.get('exact_objects_absent') != required
                        or not isinstance(verified_source, int)
                        or totals.get('required_missing_objects') != verified_source + required):
                    raise CleanRunError('Source comparison or manifest inventory is incomplete')
                video_dir = workspace / historical.RECOVERY_DIR / 'recovered-videos'
                h_only_dir = workspace / historical.RECOVERY_DIR / 'recovered-h-only'
                videos = video_dir if video_dir.is_dir() else None
                honly = h_only_dir if h_only_dir.is_dir() else None
                if (videos is None and any(x['status'] in ('recovered-validated', 'already-verified-locally')
                        and x.get('cdn_type_hex') == 'AA' for x in recovery['objects'])):
                    raise CleanRunError('Verified video recovery folder is missing')
                if (honly is None and any(x['status'] in ('recovered-validated', 'already-verified-locally')
                        and x.get('cdn_type_hex') != 'AA' for x in recovery['objects'])):
                    raise CleanRunError('Verified H-only recovery folder is missing')
                print(f'[Recovery] {verified_source} exact objects from source patch; '
                    f'{recovered} manifest-addressed CDN objects')
                inventory_report = json.loads((workspace / f'missing-source-v{w.VERSION}.json').read_text(encoding='utf-8'))
                declared = inventory_report.get('summary', {}).get('available_manifest_families')
                if not isinstance(declared, list) or not declared:
                    raise CleanRunError('No verifiable installed B.Cache families')
                families = tuple(entry['path'] for entry in declared)
                if len(set(families)) != len(families) or any(
                        not w.H_CACHE_B_CACHE_RE.fullmatch(name) for name in families):
                    raise CleanRunError('Duplicate or invalid installed B.Cache family')
                workflow['scope'] = list(families)
                from installed_type_resolver import KNOWN_EXE_HASHES
                require_native = baseline_exe['sha256'] in KNOWN_EXE_HASHES
                workflow['strict_native_type_evidence'] = require_native
                check_source_unchanged(target, base, before, report_dir, 'after-recovery', args.full_source_hash)
                check_target_executable(target, baseline_exe, report_dir, 'after-recovery')

                common = dict(target=target, base=base,
                    manifest_type=MANIFEST_TYPE, require_complete=False,
                    recovered_cdn=videos, recovered_h_only=honly,
                    u4401_patch=u4401, u4401_report=comparison_file if u4401 is not None else None,
                    required_manifest_families=families,
                    static_type_recovery=True, require_static_types=require_native)
                pre_path = workspace / 'offline-patch-audit-preexport.json'
                post_path = workspace / 'offline-patch-audit-postexport.json'
                def preflight() -> bool:
                    workflow['phase'] = 'preflight-audit'
                    report = offline.audit(**common)
                    write_json(pre_path, report)
                    print(f'[Preflight] {report["counts"]["expected_export_files"]:,} planned CDN assets; {report["hard_issue_total"]} hard issues')
                    check_source_unchanged(target, base, before, report_dir, 'after-preflight', args.full_source_hash)
                    check_target_executable(target, baseline_exe, report_dir, 'after-preflight')
                    return report['hard_issue_total'] == 0

                def export(stage: Path, failures: list[dict]) -> int:
                    workflow['phase'] = 'reconstruction'
                    result = w.export_patch(target, base, stage,
                        **export_arguments(videos, honly, comparison_file,
                        u4401, output, failures, families, require_native))
                    if result != 0:
                        return result
                    metadata = (stage / 'OpenWF' / 'Content' / '0' /
                        f'H.Cache.bin!E_{w.H_CACHE_SENTINEL_HASH}')
                    if metadata.is_symlink() or not metadata.is_file():
                        raise CleanRunError('Reconstructed H.Cache metadata is missing from staging')
                    reconstructed = metadata.read_bytes()
                    expected_h = stripped_archive._decoded_sections(reconstructed, oodle, kinds='H')['H']
                    explicit = getattr(args, 'h_cache_build_label', None)
                    archive_key = (normalize_archive_key(explicit) if explicit else
                        original_h_cache_archive_key(w._find_target_exe(target), expected_h))
                    if archive_key is None:
                        print('[H.Cache] No unique EXE VERSIONINFO ProductVersion; keeping local reconstruction')
                        workflow['original_h_cache'] = {'status': 'not-resolved', 'source': 'local'}
                        return result
                    if not explicit:
                        print(f'[H.Cache] Archive identity: {archive_key} (EXE date + H.Cache manifest hash)')
                    try:
                        original, record = fetch_original_h_cache(
                            archive_key, timeout=args.cdn_timeout, retries=args.cdn_retries,
                            verify_func=lambda data: w.verify_h_cache_metadata_object(data, expected_h, oodle))
                    except HCacheVerificationError:
                        raise
                    except CleanRunError as exc:
                        if explicit:
                            raise
                        print_warning(f'Optional original H.Cache lookup failed: {exc}; retaining local reconstruction')
                        workflow['original_h_cache'] = {'status': 'network-unavailable',
                            'archive_key': archive_key, 'source': 'local'}
                        return result
                    if original is None:
                        if explicit:
                            raise CleanRunError(f'Explicit H.Cache archive key has no archived object: {archive_key}')
                        print(f'[H.Cache] No archived H.Cache for {archive_key}; keeping local reconstruction')
                        workflow['original_h_cache'] = {**record, 'source': 'local'}
                        return result
                    if original != reconstructed:
                        w.atomic_write(metadata, original)
                    workflow['original_h_cache'] = {**record, 'status': 'verified-and-used',
                        'source': 'OpenWF-supplemental'}
                    write_json(workspace / 'original-h-cache-result.json', workflow['original_h_cache'])
                    print(f'[H.Cache] Original OpenWF object verified against pristine H bytes '
                          f'({len(original)} bytes); used in patch')
                    return result

                def verify(stage: Path) -> dict:
                    workflow['phase'] = 'deep-post-audit'
                    report = offline.audit(**common, patch=stage, deep_patch=True)
                    # Verify the proven ordinary export first. Optional stripped
                    # enrichment is then checked independently, all within the
                    # unpublished transaction staging directory.
                    if report['hard_issue_total'] == 0 and getattr(args, 'all_stripped', False):
                        # Keep CDN attempt evidence even when enrichment throws
                        # before it can return a successful summary.
                        attempts = []
                        workflow['stripped_cdn_attempts'] = attempts
                        extras = stripped_archive.add_missing(
                            patch=stage, target=target, base=base,
                            allow_cdn=getattr(args, 'stripped_cdn_fallback', False),
                            timeout=args.cdn_timeout, retries=args.cdn_retries,
                            full_source_hash=args.full_source_hash,
                            source_patches=(u4401,) if u4401 is not None else (), attempt_history=attempts)
                        # The normal deep audit ran before enrichment. New files
                        # receive per-object structural verification by the
                        # stripped archive stage, including verification after
                        # the final copy. Report both methods explicitly.
                        original_verified = report['counts']['patch_deep_verified']
                        report['verification_breakdown'] = {
                            'normal_export_deep_audit': original_verified,
                            'stripped_added_individual_deep_verification': extras['added'],
                            'stripped_existing_individual_deep_verification': extras['already'],
                            'stripped_total_manifest_entries': extras['total'],
                        }
                        report['stripped_archive'] = extras
                        report['counts']['expected_export_files'] += extras['added']
                        report['counts']['patch_files_valid_name_size'] += extras['added']
                        report['counts']['patch_deep_verified'] += extras['added']
                        workflow['stripped_archive'] = extras
                        print(f'[Stripped] Additional {extras["added"]:,} individually deep-verified objects; '
                              f'{extras["total"]:,} manifest stripped entries covered')
                    # Source validation takes place INSIDE verify, before rename.
                    check_source_unchanged(target, base, before, report_dir, 'before-publish', args.full_source_hash)
                    check_target_executable(target, baseline_exe, report_dir, 'before-publish')
                    return report

                workflow['phase'] = 'transactional-export'
                code = tx.execute(final_output=output, diagnostics_dir=workspace, version=w.VERSION,
                    preflight=preflight, export=export, verify=verify,
                    protected_sources=tuple(x for x in (target, base, u4401, videos, honly) if x is not None),
                    preflight_report=pre_path, post_audit_report=post_path,
                    keep_failed_output=args.keep_failed_output)
                if code != 0:
                    raise CleanRunError(f'Export or deep audit failed (code {code}); see export-result and console log')
                workflow['status'] = 'verified-and-published'
                workflow['phase'] = 'completed'
                workflow['actual_objects'] = json.loads(post_path.read_text(encoding='utf-8'))['counts']['patch_deep_verified']
                print(f'[Done] {workflow["actual_objects"]:,} deep-audited CDN objects published at {output}')
                print('[Not tested] Actual gameplay/patch application still needs an independent clean-base test.')
            except (Exception, KeyboardInterrupt) as exc:
                if isinstance(exc, KeyboardInterrupt):
                    code = 130
                elif code != 130:
                    code = 2
                workflow['status'] = 'interrupted' if isinstance(exc, KeyboardInterrupt) or code == 130 else 'failed'
                workflow['error'] = {'type': type(exc).__name__, 'message': str(exc)}
                print_error(f'Clean rebuild failed in {workflow["phase"]}: {exc}')
                if not isinstance(exc, (CleanRunError, w.ExportError, KeyboardInterrupt)):
                    traceback.print_exc()
            finally:
                workflow['exit_code'] = code
                workflow['finished_utc'] = datetime.now(timezone.utc).isoformat()
                try:
                    # Preserve reports even when recovery/preflight fails.
                    if workspace_created:
                        stash_workspace_reports(workspace, report_dir)
                    write_json(report_dir / 'workflow-result.json', workflow)
                    copied_reports = True
                except Exception as err:
                    print(f'[Diagnostics error] Keeping recovery workspace so evidence is not lost: {err}', file=sys.stderr)
                    workflow['diagnostics_error'] = str(err)
                if workspace_created and copied_reports and not args.keep_workspace:
                    try:
                        if workspace.is_symlink() or not workspace.is_dir():
                            raise CleanRunError('Workspace became unsafe to clean')
                        # Only clean this run's uniquely named directory.
                        shutil.rmtree(workspace)
                        print('[Cleanup] This run\'s temporary CDN recovery workspace removed; reports preserved')
                    except Exception as err:
                        print_warning(f'Temporary workspace retained at {workspace}: {err}', file=sys.stderr)
                if workflow['status'] == 'verified-and-published':
                    print(f'[Reports] {report_dir}')
                else:
                    print(f'[Troubleshooting] {report_dir}')
    return code

def main(argv: list[str] | None = None) -> int:
    parser = StrictArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--u4401', type=Path)
    parser.add_argument('--output-parent', type=Path, required=True)
    parser.add_argument('--work-parent', type=Path,
        help='optional SHORT temporary parent directory (default: <target drive>\\WF-Rebuild)')
    parser.add_argument('--report-root', type=Path, help='optional permanent report parent directory')
    parser.add_argument('--cdn-timeout', type=float, default=30.0)
    parser.add_argument('--full-source-hash', action='store_true',
        help='SHA-256 every .cache file as well as all TOCs before and after each phase (slower)')
    parser.add_argument('--keep-failed-output', action='store_true',
        help='retain failed temporary patch, not publish it')
    parser.add_argument('--keep-workspace', action='store_true',
        help='retain recovered objects for troubleshooting; a new run still never reuses them')
    args = parser.parse_args(argv)
    if not 1 <= args.cdn_timeout <= 120:
        parser.error('--cdn-timeout must be 1..120 seconds')
    try:
        return build(args, work_parent=args.work_parent, report_root=args.report_root)
    except (OSError, ValueError, CleanRunError, w.ExportError) as exc:
        fingerprint.error(f'Initialization failed: {exc}')
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
