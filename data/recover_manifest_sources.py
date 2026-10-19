#!/usr/bin/env python3
"""Recover manifest-declared objects absent from the target and Steam base.

Exact source-patch objects are validated offline. Remaining objects may be
fetched from their original manifest CDN identities. Unknown types or bytes
are rejected rather than substituted from a newer build.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys

from common import StrictArgumentParser, fetch_verified, error as print_error
from common import label as color_label
import inspect_unresolved_content as triage
import recover_missing_cdn as video
import recover_remaining_h_only as honly
import source_inventory as inventory
import compare_sources as compare_source
import warframe_install_to_patch as w

VERSION = w.VERSION
PROJECT = Path(__file__).resolve().parent
RECOVERY_DIR = 'manifest-recovery'
PROBE_REPORT = f'manifest-cdn-probe-v{VERSION}.json'
RECOVERY_REPORT = f'manifest-cdn-recovery-v{VERSION}.json'
COMPARISON_REPORT = f'manifest-source-comparison-v{VERSION}.json'

def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()

def _category(row: dict) -> str:
    if row['manifest_flags'] == '0xA0000000' and row['logical_path'].lower().endswith('.bk2'):
        return 'recovered-videos'
    if row['manifest_flags'] == '0x20000000' and not row['logical_path'].lower().endswith('.bk2'):
        return 'recovered-h-only'
    raise w.ExportError(f'Unsupported recovery flags: {row["namespace"]}{row["logical_path"]}')

def _type_candidates(row: dict, peer_types: dict[tuple[str, str], list[int]]) -> list[int]:
    if _category(row) == 'recovered-videos':
        return [0xAA]
    return peer_types.get((row['namespace'], row['logical_path']), [])

def _relative_path(row: dict, type_id: int) -> Path:
    return w._safe_output_path(Path('OpenWF') / 'Content', row['namespace'],
        row['logical_path'], type_id, row['expected_hash_base64'])

def _object_path(project: Path, row: dict, type_id: int) -> Path:
    base = project / RECOVERY_DIR / _category(row)
    target = w._safe_output_path(base / 'OpenWF' / 'Content', row['namespace'],
        row['logical_path'], type_id, row['expected_hash_base64'])
    if not target.absolute().is_relative_to(base.absolute()):
        raise w.ExportError('Recovery output path escapes the workspace')
    for current in (target, *target.parents):
        if current == base.parent:
            break
        if current.is_symlink():
            raise w.ExportError(f'Symlinked recovery path: {current}')
    w._validate_windows_export_path(target, atomic=True)
    return target

def _validate_payload(raw: bytes, row: dict, type_id: int, oodle) -> dict:
    if _category(row) == 'recovered-videos':
        if type_id != 0xAA:
            raise w.ExportError('Unexpected video CDN type')
        return video.validate_cdn_payload(raw, row, oodle)
    return honly.validate_h_only_payload(raw, row, type_id, oodle)

def _report_inputs(project: Path, name: str = COMPARISON_REPORT) -> list[dict]:
    def load(filename: str) -> dict:
        path = project / filename
        if path.is_symlink() or not path.is_file():
            raise w.ExportError(f'Expected ordinary inventory report: {path}')
        import json
        doc = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(doc, dict):
            raise w.ExportError('Invalid inventory report')
        return doc

    missing = load(f'missing-source-v{VERSION}.json')
    inherited = load(f'base-inheritance-v{VERSION}.json')
    compared = load(name)
    if (missing.get('report_version') != VERSION or inherited.get('version') != VERSION
            or compared.get('version') != VERSION or compared.get('kind') != compare_source.PROBE_KIND):
        raise w.ExportError('Source reports have mismatched schema/versions')
    unresolved = triage._validate_report_inputs(missing, inherited)
    inventory.validate_recovery_inventory(unresolved)
    records = compared.get('objects')
    if not isinstance(records, list) or len(records) != len(unresolved):
        raise w.ExportError('Source comparison does not cover the manifest inventory')
    lookup = {(row['namespace'], row['logical_path']): row for row in unresolved}
    if len(lookup) != len(unresolved):
        raise w.ExportError('Duplicate manifest recovery identities')
    seen = set()
    absent = []
    verified = 0
    for record in records:
        key = (record.get('namespace'), record.get('logical_path'))
        if key not in lookup or key in seen:
            raise w.ExportError('Source report contains an extra or duplicate object')
        seen.add(key)
        row = lookup[key]
        if (record.get('manifest_hash') != row['expected_hash_base64']
                or record.get('expected_bytes') != row['expected_cdn_size_bytes']
                or record.get('expected_flags') != row['manifest_flags']):
            raise w.ExportError('Source comparison differs from target manifest')
        status = record.get('status')
        if status == 'exact-object-absent':
            absent.append(row)
        elif status == 'exact-object-verified':
            verified += 1
        else:
            raise w.ExportError(f'Invalid exact source object: {row["logical_path"]}: {status}')
    summary = compared.get('summary', {})
    if (len(seen) != len(unresolved) or summary.get('exact_objects_verified') != verified
            or summary.get('exact_objects_absent') != len(absent)
            or summary.get('exact_objects_rejected') != 0):
        raise w.ExportError('Source comparison summary is incomplete')
    return sorted(absent, key=lambda r: (r['namespace'], r['logical_path']))

def _peer_candidates(target: Path, rows: list[dict], oodle) -> dict[tuple[str, str], list[int]]:
    h_only = [row for row in rows if _category(row) == 'recovered-h-only']
    if not h_only:
        return {}
    choices = honly.infer_peer_types(target, h_only, oodle=oodle)
    result = {}
    for item in choices:
        key = (item['namespace'], item['logical_path'])
        result[key] = [int(candidate['type_hex'], 16) for candidate in item['peer_candidates']]
    return result

def _collection_reports(project: Path, rows: list[dict], successes: dict) -> None:
    root = project / RECOVERY_DIR
    for category, filename in (('recovered-videos', 'cdn-recovery-v0.1.json'),
            ('recovered-h-only', honly.REPORT_NAME)):
        selected = []
        for row in rows:
            key = (row['namespace'], row['logical_path'])
            if key not in successes or _category(row) != category:
                continue
            type_id, checks = successes[key]
            record = {name: row[name] for name in
                ('namespace', 'logical_path', 'expected_cdn_size_bytes')}
            record.update(status='recovered-validated', **checks)
            record['relative_path'] = _object_path(project, row, type_id).relative_to(root / category).as_posix()
            if category == 'recovered-h-only':
                record.update(expected_hash_base64=row['expected_hash_base64'],
                    manifest_flags=row['manifest_flags'], cdn_type_hex=f'{type_id:X}')
            selected.append(record)
        if not selected:
            continue
        doc = {'version': VERSION, 'kind': 'h-only-cdn-recovery' if category == 'recovered-h-only' else 'video-cdn-recovery',
            'created_utc': _stamp(),
            'summary': {'selected': len(selected), 'recovered_validated': len(selected), 'failed': 0},
            'objects': selected}
        inventory.save_report(root / category / filename, doc)

def run(project: Path, *, download: bool, timeout: float = 20.0,
        head_func=None, get_func=None, oodle=None,
        fresh_sources: tuple[Path, Path, Path | None] | None = None, retries: int = 5) -> dict:
    if not 1 <= timeout <= 120 or not 1 <= retries <= 20:
        raise w.ExportError('Timeout/retry parameters outside safe limits')
    project = project.resolve(strict=True)
    if fresh_sources is not None:
        target, base, source_patch = fresh_sources
        _, missing = inventory.load_manifest_inventory(target, base, project)
        oodle = oodle or w.Oodle(PROJECT)
        comparison = compare_source.compare(missing, source_patch, oodle)
        inventory.save_report(project / COMPARISON_REPORT, comparison)
        rows = _report_inputs(project)
        peers = _peer_candidates(target, rows, oodle)
    else:
        rows = _report_inputs(project)
        peers = {}
    head_func = head_func or triage._head
    get_func = get_func or video._download
    results = []
    successes = {}
    if len(rows) > 512 or sum(len(_type_candidates(r, peers)) for r in rows) > 2048:
        raise w.ExportError('Recovery probe count exceeds safe request budget')
    total_expected = sum(row['expected_cdn_size_bytes'] for row in rows)
    if total_expected > video.MAX_TOTAL_BYTES:
        raise w.ExportError('Recovery exceeds total-byte budget')
    for row in rows:
        logical = row['logical_path']
        key = (row['namespace'], logical)
        candidates = _type_candidates(row, peers)
        record = {'namespace': row['namespace'], 'logical_path': logical,
            'expected_bytes': row['expected_cdn_size_bytes'],
            'type_candidates': [f'{x:X}' for x in candidates], 'download_attempts': []}
        matched = []
        for type_id in candidates:
            url = triage.make_cdn_url(row, type_id)
            path = _object_path(project, row, type_id)
            if path.is_file():
                raw = path.read_bytes()
                oodle = oodle or w.Oodle(PROJECT)
                checks = _validate_payload(raw, row, type_id, oodle)
                matched.append((type_id, url, checks, raw, True))
                continue
            info = head_func(url, timeout=timeout)
            status, size = info.get('http_status'), info.get('content_length')
            if status == 200 and size == row['expected_cdn_size_bytes']:
                matched.append((type_id, url, None, None, False))
            elif (download and len(candidates) == 1 and
                    ((status == 200 and size is None) or status in (405, 501))):
                # Some CDNs reject HEAD or omit its Content-Length even when
                # GET works. A single candidate may be attempted, but only
                # the fully verified GET can establish the asset's identity.
                matched.append((type_id, url, None, None, False))
                record['head_inconclusive'] = {'http_status': status, 'content_length': size}
            else:
                record['download_attempts'].append({'type_hex': f'{type_id:X}',
                    'http_status': status, 'content_length': size})
        if len(matched) != 1:
            record.update(status='unresolved', error='No unique matching CDN type/size' if not matched else 'Ambiguous CDN type')
        else:
            type_id, url, checks, raw, is_local = matched[0]
            record.update(url=url, cdn_type_hex=f'{type_id:X}')
            if checks is not None:
                record.update(status='already-verified-locally', **checks)
                successes[key] = (type_id, checks)
            elif not download:
                record['status'] = 'head-confirmed-payload-not-verified'
            else:
                oodle = oodle or w.Oodle(PROJECT)
                try:
                    raw, checks = fetch_verified(url=url, logical_path=f'{row["namespace"]}{logical}',
                        expected_size=row['expected_cdn_size_bytes'], timeout=timeout,
                        get_func=get_func,
                        verify_func=lambda data: _validate_payload(data, row, type_id, oodle),
                        retries=retries, attempts_log=record['download_attempts'])
                except (OSError, ValueError, w.ExportError) as exc:
                    # Preserve failed attempts in the report and inspect the
                    # remaining assets. The caller still refuses publication.
                    record.update(status='download-failed', error=str(exc)[:400])
                    print_error(f'{row["namespace"]}{logical}: {exc}')
                else:
                    path = _object_path(project, row, type_id)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if path.exists() or path.is_symlink():
                        raise w.ExportError('Download destination appeared during recovery')
                    w.atomic_write(path, raw)
                    record.update(status='recovered-validated', **checks)
                    successes[key] = (type_id, checks)
                    print(f'{color_label("Verified")} {row["namespace"]}{logical} | type {type_id:X} | {len(raw):,} bytes')
        results.append(record)
    if download:
        _collection_reports(project, rows, successes)
    summary = {'required': len(rows), 'fully_verified': len(successes),
        'head_confirmed_only': sum(r['status'] == 'head-confirmed-payload-not-verified' for r in results),
        'unavailable_or_failed': sum(r['status'] in ('unresolved', 'download-failed') for r in results)}
    report = {'version': VERSION, 'kind': 'manifest-cdn-recovery' if download else 'manifest-cdn-probe',
        'created_utc': _stamp(), 'summary': summary, 'objects': results}
    inventory.save_report(project / (RECOVERY_REPORT if download else PROBE_REPORT), report)
    return report

def main(argv: list[str] | None = None) -> int:
    parser = StrictArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--probe', action='store_true')
    action.add_argument('--download', action='store_true')
    parser.add_argument('--target', required=True, type=Path)
    parser.add_argument('--base', required=True, type=Path)
    parser.add_argument('--source-patch', type=Path)
    parser.add_argument('--timeout', type=float, default=20.0)
    parser.add_argument('--retries', type=int, default=5)
    args = parser.parse_args(argv)
    try:
        report = run(PROJECT, download=args.download, timeout=args.timeout,
            fresh_sources=(args.target, args.base, args.source_patch), retries=args.retries)
        counts = report['summary']
        return 0 if counts['fully_verified'] == counts['required'] or (
            args.probe and counts['fully_verified'] + counts['head_confirmed_only'] == counts['required']) else 2
    except KeyboardInterrupt:
        print_error('Interrupted; no output patch was published')
        return 130
    except (OSError, ValueError, w.ExportError) as exc:
        print_error(exc)
        return 2

if __name__ == '__main__':
    sys.exit(main())
