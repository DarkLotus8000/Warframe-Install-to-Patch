#!/usr/bin/env python3
"""Regenerate U44.0.0 EN/DX11 hybrid patch without using any later update build.

Missing target/base cache objects are fetched only from canonical, manifest-
addressed original Warframe CDN URLs, with strict SHCC CRC32C/H hash/type/
section/length checks. Nothing is silently omitted. Successfully verified
objects are retained for safe retries. No remote requests without --download.
"""
from __future__ import annotations

from common import StrictArgumentParser, error as print_error, warning as print_warning

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError

import inspect_missing_source as missing_mod
import inspect_unresolved_content as triage
import recover_missing_cdn as video
import recover_remaining_h_only as honly
import warframe_install_to_patch as w

REQUIRED_FAMILIES = ('/B.Cache.Windows.bin', '/B.Cache.Windows_en.bin',
    '/B.Cache.Windows_xx.bin', '/B.Cache.Dx11.bin')
SOURCE_SNAPSHOT_NAME = 'workspace-source-snapshot-v0.1.json'

def save_report(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    w.atomic_write(path, (json.dumps(doc, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))

def ensure_safe_paths(target: Path, base: Path, workspace: Path, output: Path) -> None:
    target, base, workspace, output = (p.resolve() for p in (target, base, workspace, output))
    if not target.is_dir() or not base.is_dir() or target == base:
        raise w.ExportError('Target and original Steam base must be two existing distinct directories')
    if workspace == output or workspace.is_relative_to(output) or output.is_relative_to(workspace):
        raise w.ExportError('Recovery workspace and output patch must be separate directories')
    for protected in (target, base):
        if (workspace == protected or workspace.is_relative_to(protected) or protected.is_relative_to(workspace)
                or output == protected or output.is_relative_to(protected) or protected.is_relative_to(output)):
            raise w.ExportError('Recovery workspace/output must not overlap an original installation')
    if output.exists() or output.is_symlink():
        raise w.ExportError('Patch output already exists. Choose a new patch destination to avoid overwrites')
    if workspace.is_symlink():
        raise w.ExportError('Recovery workspace must not be a symlink')

def source_snapshot(target: Path, base: Path) -> dict:
    """Fast, conservative source-change guard for reusable cache inventory reports.

    This captures metadata of every package TOC/payload, not a cryptographic
    checksum; it detects ordinary installation/cache modifications between
    recovery attempts without rehashing hundreds of gigabytes of source data.
    """
    def snapshot_one(root: Path) -> dict:
        cache = w.find_cache_windows_dir(root).resolve()
        if not cache.is_dir():
            raise w.ExportError(f'Cache.Windows folder missing: {cache}')
        stats = []
        for entry in sorted(cache.iterdir(), key=lambda item: item.name.casefold()):
            if entry.suffix.lower() not in {'.toc', '.cache'}:
                continue
            if entry.is_symlink() or not entry.is_file():
                raise w.ExportError(f'Cache source is not an ordinary file: {entry}')
            info = entry.stat()
            stats.append([entry.name, info.st_size, info.st_mtime_ns])
        if not stats:
            raise w.ExportError(f'No TOC/cache files in source: {cache}')
        return {'path': str(cache), 'files': stats}

    result = {'version': w.VERSION, 'target_cache': snapshot_one(target),
        'base_cache': snapshot_one(base)}
    exe = w._find_target_exe(target)
    st = exe.stat()
    result['target_exe'] = [str(exe.resolve()), st.st_size, st.st_mtime_ns]
    return result

def load_manifest_inventory(target: Path, base: Path, workspace: Path) -> tuple[dict, list[dict]]:
    miss_path = workspace / 'missing-source-v0.1.json'
    base_path = workspace / 'base-inheritance-v0.1.json'
    snapshot_path = workspace / SOURCE_SNAPSHOT_NAME
    current_snapshot = source_snapshot(target, base)
    if miss_path.is_file() and base_path.is_file():
        if not snapshot_path.is_file():
            raise w.ExportError('Existing inventory has no input-source snapshot. Use a new workspace to safely rescan.')
        if json.loads(snapshot_path.read_text(encoding='utf-8')) != current_snapshot:
            raise w.ExportError('Installed target/Steam base changed since cached reports were created. Use a new workspace.')
        missing = json.loads(miss_path.read_text(encoding='utf-8'))
        inherited = json.loads(base_path.read_text(encoding='utf-8'))
        if (Path(missing.get('target_cache', '')).resolve() != w.find_cache_windows_dir(target).resolve()
                or Path(missing.get('base_cache', '')).resolve() != w.find_cache_windows_dir(base).resolve()
                or Path(inherited.get('base_cache', '')).resolve() != w.find_cache_windows_dir(base).resolve()):
            raise w.ExportError('Existing workspace reports belong to different installation paths')
    else:
        if miss_path.exists() or base_path.exists():
            raise w.ExportError('Incomplete manifest report pair in workspace. Use a new workspace for a fresh scan')
        print('[1/5] Inventory target manifest assets and independently validate base inheritance')
        missing = missing_mod.analyze(target, base, progress_every=25000)
        inherited = missing_mod.verify_base_inheritance(missing, base)
        if inherited['summary']['base_read_error']:
            raise w.ExportError('Steam base inheritance verification failed')
        if source_snapshot(target, base) != current_snapshot:
            raise w.ExportError('Source cache changed during inventory scan; refusing stale results.')
        save_report(miss_path, missing)
        save_report(base_path, inherited)
        save_report(snapshot_path, current_snapshot)
    if source_snapshot(target, base) != current_snapshot:
        raise w.ExportError('Source cache changed while validating reusable reports.')
    counts = inherited['summary']
    if counts['source_missing_in_target'] != len(missing['missing_objects']):
        raise w.ExportError('Input manifest and base inventory counts disagree')
    if counts['base_read_error']:
        raise w.ExportError('Base H/B/F verification had read errors')
    # The established triage schema is unchanged. Version labels are only
    # adjusted in-memory for the older reader, never persisted as fake history.
    legacy_missing = dict(missing, report_version=w.VERSION)
    legacy_base = dict(inherited, version=w.VERSION)
    remaining = triage._validate_report_inputs(legacy_missing, legacy_base)
    if counts['not_fully_in_base'] != len(remaining):
        raise w.ExportError('Unresolved resource count differs from base verification')
    print(f"[Sources] {counts['source_missing_in_target']} absent from target; "
          f"{counts['verified_in_base']} inherited; {len(remaining)} require source recovery")
    assert_all_u44_targets(remaining)
    return triage.summarize(remaining, legacy_missing, legacy_base), remaining

def assert_all_u44_targets(rows: list[dict]) -> None:
    expected_nonvideos = honly.KNOWN_TARGETS
    actual_nonvideos = {(r['namespace'], r['logical_path'], r['expected_hash_base64'],
        r['expected_cdn_size_bytes']) for r in rows if r['category'] == 'non-video-resource'}
    vids = [r for r in rows if r['category'] in ('video-preview', 'other-video')]
    if len(rows) != 103 or len(vids) != 101 or len(actual_nonvideos) != 2 or actual_nonvideos != expected_nonvideos:
        raise w.ExportError('U44 source inventory changed; refuse a silently incomplete fixed-103 recovery')
    seen = set()
    for r in rows:
        key = (r['namespace'], r['logical_path'])
        if key in seen:
            raise w.ExportError('Duplicate recovery object')
        seen.add(key)
        if r['namespace'] != '0' or r['manifest_section'] != 'stripped':
            raise w.ExportError('Unexpected recovery namespace/section')
        if r['category'] in ('video-preview', 'other-video'):
            if not (r['logical_path'].lower().endswith('.bk2') and r['manifest_flags'] == '0xA0000000'
                    and r['required_pieces'] == ['F'] and 40 <= r['expected_cdn_size_bytes'] <= video.MAX_ITEM_BYTES):
                raise w.ExportError('Unexpected missing video manifest fields')
    if sum(r['expected_cdn_size_bytes'] for r in vids) > video.MAX_TOTAL_BYTES:
        raise w.ExportError('Video recovery exceeds bounded byte budget')

def download_checked(url: str, size: int, timeout: float, tries: int) -> bytes:
    last: Exception | None = None
    for attempt in range(tries):
        try:
            return video._download(url, size, timeout)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            last = exc
            if isinstance(exc, HTTPError) and exc.code in (400, 401, 403, 404, 410):
                break
            if attempt + 1 < tries:
                print_warning(f'CDN retry {attempt+2}/{tries}: {exc}')
                time.sleep(min(2 + attempt * 2, 10))
    raise w.ExportError(f'Original CDN URL unavailable: {url}: {last}')

def read_or_download(root: Path, row: dict, type_id: int, oodle: w.Oodle,
        *, download: bool, timeout: float, retries: int, is_video: bool) -> tuple[bytes, dict]:
    target = w._safe_output_path(root / 'OpenWF' / 'Content', row['namespace'],
        row['logical_path'], type_id, row['expected_hash_base64'])
    if (root.resolve() == target.resolve() or not target.resolve().is_relative_to(root.resolve())
            or target.is_symlink()):
        raise w.ExportError(f'Recovery object path escapes workspace or is a symlink: {target}')
    if target.exists():
        if not target.is_file():
            raise w.ExportError(f'Existing recovery target is not a file: {target}')
        raw = target.read_bytes()
    else:
        if not download:
            raise w.ExportError('CDN objects unavailable locally; --download is required to recover them')
        url = triage.make_cdn_url(row, type_id)
        raw = download_checked(url, row['expected_cdn_size_bytes'], timeout, retries)
    check = (video.validate_cdn_payload(raw, row, oodle) if is_video
        else honly.validate_h_only_payload(raw, row, type_id, oodle))
    if not target.exists():
        w.atomic_write(target, raw)
    check['relative_path'] = target.relative_to(root).as_posix()
    return raw, check

def recover_videos(rows: list[dict], target: Path, root: Path, oodle: w.Oodle,
        *, download: bool, timeout: float, retries: int) -> dict:
    videos = sorted((x for x in rows if x['category'] != 'non-video-resource'),
        key=lambda x: x['logical_path'])
    # Evidence comes from installed video CommonHeaders, not from filename extension alone.
    inference = triage.infer_video_type(target)
    if inference.get('type_hex') != 'AA' or inference.get('type_confidence') != 'same-extension-cache-peers-not-per-file-proof':
        raise w.ExportError('Unable to corroborate CDN video type AA from this installed client')
    print(f"[2/5] Recover {len(videos)} original CDN videos (type AA; {inference['sampled_headers']} peer headers)")
    root.mkdir(parents=True, exist_ok=True)
    successes = []
    for n, row in enumerate(videos, 1):
        try:
            _, checks = read_or_download(root, row, 0xAA, oodle, download=download,
                timeout=timeout, retries=retries, is_video=True)
        except (w.ExportError, OSError, ValueError) as exc:
            print(f'[Missing video {n}/{len(videos)}] {row["logical_path"]}: {exc}')
            # Keep already downloaded validated files for retries, but never write
            # a partial success report that the exporter would accept.
            raise
        successes.append({
            'namespace': row['namespace'], 'logical_path': row['logical_path'],
            'url': triage.make_cdn_url(row, 0xAA),
            'expected_cdn_size_bytes': row['expected_cdn_size_bytes'],
            'status': 'recovered-validated', **checks,
        })
        if n % 10 == 0 or n == len(videos):
            print(f'[Videos] {n}/{len(videos)} fully verified')
    report = {'version': video.RECOVERY_REPORT_FORMAT, 'generated_by_version': w.VERSION,
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'source': 'verified live historical content-addressed U44 CDN URLs, not a later update patch',
        'summary': {'selected': len(successes), 'recovered_validated': len(successes), 'failed': 0},
        'objects': successes}
    save_report(root / 'cdn-recovery-v0.1.json', report)
    return report

def recover_h_only(rows: list[dict], target: Path, root: Path, oodle: w.Oodle,
        *, download: bool, timeout: float, retries: int) -> dict:
    selected = sorted((r for r in rows if r['category'] == 'non-video-resource'),
        key=lambda r: r['logical_path'])
    print('[3/5] Recover two H-only objects using installed header peers and verified CDN types')
    peers = honly.infer_peer_types(target, selected)
    root.mkdir(parents=True, exist_ok=True)
    successes = []
    for row, peer in zip(selected, peers):
        if row['logical_path'] != peer['logical_path']:
            raise w.ExportError('H-only type peer ordering mismatch')
        candidates = [int(x['type_hex'], 16) for x in peer['peer_candidates']]
        if not candidates:
            raise w.ExportError('No installed peer type evidence for ' + row['logical_path'])
        candidate_reasons = []
        chosen = None
        for type_id in candidates:
            existing = w._safe_output_path(root / 'OpenWF' / 'Content', row['namespace'],
                row['logical_path'], type_id, row['expected_hash_base64'])
            if existing.is_file():
                # On resume, always revalidate the object, not merely its filename.
                try:
                    _, checks = read_or_download(root, row, type_id, oodle, download=False,
                        timeout=timeout, retries=retries, is_video=False)
                    chosen = (type_id, checks)
                    break
                except (w.ExportError, OSError, ValueError) as exc:
                    raise w.ExportError(f'Invalid existing H-only source {existing}: {exc}') from exc
            if not download:
                continue
            url = triage.make_cdn_url(row, type_id)
            probe = triage._head(url, timeout=timeout)
            if (probe.get('http_status'), probe.get('content_length')) != (200, row['expected_cdn_size_bytes']):
                candidate_reasons.append(f'{type_id:X}: HEAD {probe.get("http_status")}')
                continue
            try:
                _, checks = read_or_download(root, row, type_id, oodle, download=True,
                    timeout=timeout, retries=retries, is_video=False)
                chosen = (type_id, checks)
                break
            except (w.ExportError, OSError, ValueError) as exc:
                candidate_reasons.append(f'{type_id:X}: {exc}')
        if chosen is None:
            raise w.ExportError(f'No independently validated CDN type for {row["logical_path"]}: ' + '; '.join(candidate_reasons))
        type_id, checks = chosen
        print(f'[H-only] {row["logical_path"]} | type {type_id:X} | SHCC/H verified')
        successes.append({key: row[key] for key in ('namespace', 'logical_path', 'expected_hash_base64',
            'expected_cdn_size_bytes', 'manifest_flags')} |
            {'url': triage.make_cdn_url(row, type_id), 'cdn_type_hex': f'{type_id:X}',
            'status': 'recovered-validated', **checks})
    doc = {'version': honly.VERSION, 'kind': 'h-only-cdn-recovery',
           'created_utc': datetime.now(timezone.utc).isoformat(),
           'summary': {'selected': len(successes), 'recovered_validated': len(successes), 'failed': 0},
           'objects': successes,
           'note': 'New SHA-256 is not an independent historical full-CDN hash.'}
    save_report(root / honly.REPORT_NAME, doc)
    return doc

def run(target: Path, base: Path, workspace: Path, output: Path, *, download: bool,
        timeout: float, retries: int) -> int:
    ensure_safe_paths(target, base, workspace, output)
    if not 1 <= timeout <= 120 or not 1 <= retries <= 8:
        raise w.ExportError('Timeout must be 1..120 seconds and retries 1..8')
    if not download:
        print('[Notice] Dry mode: this command cannot complete without existing verified recovery objects.')
    workspace.mkdir(parents=True, exist_ok=True)
    inventory, unresolved = load_manifest_inventory(target, base, workspace)
    save_report(workspace / 'restoration-inventory-v0.1.json', inventory)
    oodle = w.Oodle(Path(w.__file__).resolve().parent)
    vid_root = workspace / 'recovered-videos'
    h_root = workspace / 'recovered-h-only'
    for collection in (vid_root, h_root):
        if collection.is_symlink() or not collection.resolve().is_relative_to(workspace.resolve()):
            raise w.ExportError(f'Recovery collection escapes workspace or is a symlink: {collection}')
    recover_videos(unresolved, target, vid_root, oodle, download=download, timeout=timeout, retries=retries)
    recover_h_only(unresolved, target, h_root, oodle, download=download, timeout=timeout, retries=retries)
    print('[4/5] Strict preflight and cache export; all 103 recovered sources revalidated')
    base_args = [str(target), str(base), '--recovered-cdn', str(vid_root),
        '--recovered-h-only', str(h_root),
        '--require-static-types', '--no-bundled-type-hints']
    for family in REQUIRED_FAMILIES:
        base_args.extend(['--required-manifest-family', family])
    audit_pre = workspace / 'offline-patch-audit-preexport-v0.1.json'
    result = w.main(base_args + ['--audit-first', '--audit-report', str(audit_pre), '-o', str(output)])
    if result:
        print_error(f'Preflight or export did not finish; see {audit_pre}')
        return result
    print('[5/5] Deep post-export audit (all 2,231 required files)')
    import offline_patch_audit as audit_mod
    audit_post = workspace / 'offline-patch-audit-postexport-v0.1.json'
    check_args = base_args + ['--patch', str(output), '--deep-patch', '-o', str(audit_post)]
    outcome = audit_mod.main(check_args)
    if outcome:
        print_error(f'Post-export verification failed; see {audit_post}')
        return outcome
    doc = json.loads(audit_post.read_text(encoding='utf-8'))
    counts = doc.get('counts', {})
    if (doc.get('hard_issue_total') or counts.get('patch_deep_verified') != 2231
            or counts.get('recovered_videos') != 101
            or counts.get('recovered_h_only') != 2):
        raise w.ExportError('Post-export report does not confirm the expected EN/DX11 2,231 required objects')
    print('[Success] 2,231/2,231 required CDN files deep-verified, including 103 recovered objects.')
    print('[Notice] This covers installed EN/DX11 manifests, not uninstalled language/DX12 families.')
    print('[Output] ' + str(output))
    return 0

def main(argv: list[str] | None = None) -> int:
    p = StrictArgumentParser(description=__doc__)
    p.add_argument('target', type=Path)
    p.add_argument('base', type=Path)
    p.add_argument('--workspace', required=True, type=Path, help='Separate, reusable source-recovery workspace')
    p.add_argument('-o', '--output', required=True, type=Path, help='NEW, nonexistent final patch directory')
    p.add_argument('--download', action='store_true', help='Opt into HTTPS GET of missing content-addressed CDN assets')
    p.add_argument('--timeout', type=float, default=30)
    p.add_argument('--retries', type=int, default=4)
    p.add_argument('--version', action='version', version='%(prog)s ' + w.VERSION)
    a = p.parse_args(argv)
    try:
        return run(a.target, a.base, a.workspace, a.output,
            download=a.download, timeout=a.timeout, retries=a.retries)
    except KeyboardInterrupt:
        print('[Interrupted] Verified files already recovered remain in the workspace for a rerun.', file=sys.stderr)
        return 130
    except (w.ExportError, OSError, ValueError, KeyError, TypeError) as exc:
        print_error(str(exc))
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
