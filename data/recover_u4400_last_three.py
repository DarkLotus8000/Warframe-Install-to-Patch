#!/usr/bin/env python3
"""Probe/recover only the 3 exact U44.0.0 CDN objects absent from U44.0.1.

HEAD requests are opt-in via --probe; GET requires --download. Neither mode
modifies the two installations, the U44.0.1 patch, or any existing patch output.
Recovery objects, resumable reports and fingerprints stay within this project.
All three identities are pinned to the U44.0.0 manifest and independently
checked against the project-local missing-source/base/U44.0.1 reports.
"""
from __future__ import annotations

from common import StrictArgumentParser, http_line, label as color_label, error as print_error
from common import fetch_verified

from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import inspect_unresolved_content as triage
import recover_missing_cdn as video
import recover_remaining_h_only as honly
import restore_u44_complete as restore
import warframe_install_to_patch as w

VERSION = w.VERSION
PROJECT = Path(__file__).resolve().parent
RECOVERY_DIR = 'recovery-u4400-last-three'
PROBE_REPORT = f'u4400-last-three-cdn-probe-v{w.VERSION}.json'
RECOVERY_REPORT = f'u4400-last-three-recovery-v{w.VERSION}.json'
# Exact historical U44.0.0 identities. The H-only type D2 was corroborated by
# prior successful CDN HEAD/GET and CommonHeader validation; AA similarly for video.
PINNED = {
    '/Lotus/Fx/PowersuitAbilities/Decree/SonarWeakSpotCapsuleMat': ('SZJetTq813ezgKwg2nTXlA', 687, 0xD2),
    '/Lotus/Interface/AbilityVideos/NarinPower4_s.bk2': ('R4yaWr6KXE-ZrOlc7mErBw', 2066345, 0xAA),
    '/Lotus/Objects/Natural/Skybox/NinetyNine/HubParallax/Building01a': ('35O5zuNZnbDNtIyw070Bqg', 955, 0xD2),
}

def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()

def _load_inputs(project: Path, comparison_name: str = "u44-0-1-shared-assets-v0.1.json") -> list[dict]:
    def load(name: str) -> dict:
        path = project / name
        if path.is_symlink() or not path.is_file():
            raise w.ExportError(f'Expected ordinary project-local report: {path}')
        value = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(value, dict):
            raise w.ExportError(f'Invalid project-local report: {name}')
        return value

    missing = load('missing-source-v0.1.json')
    inherited = load('base-inheritance-v0.1.json')
    compared = load(comparison_name)
    expected_version = w.VERSION
    if (missing.get('report_version') != expected_version
            or inherited.get('version') != expected_version
            or compared.get('version') != expected_version
            or compared.get('kind') != 'u44.0.0-assets-in-u44.0.1-patch'):
        raise w.ExportError('Input inventory or U44.0.1 comparison version differs from expected clean-start version')
    unresolved = triage._validate_report_inputs(
        dict(missing, report_version=w.VERSION), dict(inherited, version=w.VERSION))
    restore.assert_all_u44_targets(unresolved)
    summary = compared.get('summary', {})
    if (summary.get('required_missing_u44_objects') != 103
            or summary.get('exact_objects_verified') != 100
            or summary.get('exact_objects_absent') != 3
            or summary.get('exact_objects_rejected') != 0):
        raise w.ExportError('U44.0.1 comparison is not the expected 100/103 verified result')
    seen = set()
    absent = {}
    for item in compared.get('objects', []):
        path = item.get('logical_path')
        if (item.get('namespace'), path) in seen:
            raise w.ExportError('Duplicate U44.0.1 comparison entry')
        seen.add((item.get('namespace'), path))
        if item.get('status') == 'exact-object-absent':
            absent[path] = item
    if len(seen) != 103 or set(absent) != set(PINNED):
        raise w.ExportError('Unexpected missing U44.0.1 identities')
    lookup = {x['logical_path']: x for x in unresolved}
    for name, (digest, size, type_id) in PINNED.items():
        row, comp = lookup.get(name), absent[name]
        if (not row or row['namespace'] != '0' or row['manifest_section'] != 'stripped'
                or row['expected_hash_base64'] != digest or row['expected_cdn_size_bytes'] != size
                or row['manifest_flags'] != ('0xA0000000' if type_id == 0xAA else '0x20000000')
                or row['required_pieces'] != (['F'] if type_id == 0xAA else [])
                or comp.get('u44_0_0_hash') != digest or comp.get('u44_0_0_type') != f'{type_id:X}'
                or comp.get('expected_bytes') != size):
            raise w.ExportError('U44.0.0 manifest identity or flags disagree: ' + name)
        expected_name = w._safe_output_path(Path('OpenWF/Content'), '0', name, type_id, digest).as_posix()
        if comp.get('expected_relative_path') != expected_name:
            raise w.ExportError('U44.0.1 comparison CDN identity mismatch: ' + name)
    return [lookup[name] for name in sorted(PINNED)]

def _safe_object_path(project: Path, row: dict) -> Path:
    root = project / RECOVERY_DIR
    name = row['logical_path']
    type_id = PINNED[name][2]
    location = w._safe_output_path(root / ('recovered-videos' if type_id == 0xAA else 'recovered-h-only')
        / 'OpenWF' / 'Content', '0', name,
        type_id, row['expected_hash_base64'])
    if project.is_symlink() or not project.is_dir() or not location.resolve().is_relative_to(project.resolve()):
        raise w.ExportError('Recovery path escapes project directory')
    # Check every existing component, not only the final file.
    for path in (root, *list(location.parents)[:-1], location):
        if path.is_symlink():
            raise w.ExportError(f'Symlink in recovery path: {path}')
    if location.exists() and not location.is_file():
        raise w.ExportError(f'Existing recovery object is not a file: {location}')
    return location

def _validate_payload(raw: bytes, row: dict, oodle) -> dict:
    type_id = PINNED[row['logical_path']][2]
    if type_id == 0xAA:
        return video.validate_cdn_payload(raw, row, oodle)
    return honly.validate_h_only_payload(raw, row, type_id, oodle)

def _existing_checksum(project: Path, row: dict) -> str | None:
    root = project / RECOVERY_DIR
    folder = 'recovered-videos' if PINNED[row['logical_path']][2] == 0xAA else 'recovered-h-only'
    name = 'cdn-recovery-v0.1.json' if folder == 'recovered-videos' else honly.REPORT_NAME
    report = root / folder / name
    if report.is_symlink():
        raise w.ExportError('Recovery report symlink is prohibited')
    if not report.exists():
        return None
    data = json.loads(report.read_text(encoding='utf-8'))
    for item in data.get('objects', []):
        if item.get('logical_path') == row['logical_path']:
            return item.get('sha256')
    return None

def _store_collection_reports(project: Path, rows: list[dict], successes: dict) -> None:
    root = project / RECOVERY_DIR
    for type_id, directory, filename in ((0xAA, 'recovered-videos', 'cdn-recovery-v0.1.json'),
            (0xD2, 'recovered-h-only', honly.REPORT_NAME)):
        selected = []
        for row in rows:
            name = row['logical_path']
            if PINNED[name][2] != type_id or name not in successes:
                continue
            item = {k: row[k] for k in ('namespace', 'logical_path', 'expected_cdn_size_bytes')}
            if type_id == 0xD2:
                item.update(expected_hash_base64=row['expected_hash_base64'], manifest_flags=row['manifest_flags'],
                    cdn_type_hex='D2')
            item.update(status='recovered-validated', url=triage.make_cdn_url(row, type_id), **successes[name])
            item['relative_path'] = _safe_object_path(project, row).relative_to(root / directory).as_posix()
            selected.append(item)
        if not selected:
            continue
        output = root / directory / filename
        if output.is_symlink():
            raise w.ExportError(f'Recovery report is a symlink: {output}')
        doc = {'version': video.RECOVERY_REPORT_FORMAT if type_id == 0xAA else honly.VERSION,
               'generated_by_version': VERSION, 'created_utc': _timestamp(),
               'summary': {'selected': len(selected), 'recovered_validated': len(selected), 'failed': 0},
               'objects': selected}
        if type_id == 0xD2:
            doc['kind'] = 'h-only-cdn-recovery'
        else:
            doc['source'] = 'exact U44.0.0 CDN URLs; U44.0.1 imports are separate'
        restore.save_report(output, doc)

def run(project: Path, *, download: bool, timeout: float = 20.0,
        head_func=None, get_func=None, oodle=None,
        fresh_sources: tuple[Path, Path, Path] | None = None, retries: int = 5) -> dict:
    if not 1 <= timeout <= 120 or not 1 <= retries <= 20:
        raise w.ExportError('Timeout must be 1..120 seconds and retries 1..20')
    project = project.resolve(strict=True)
    if fresh_sources is not None:
        # Never consult old source-inventory reports for this clean-run mode.
        # Regenerate or source-snapshot-validate the inventories against the
        # current pristine final install and untouched Steam base.
        from compare_u4401_sources import compare as compare_u4401
        target, base, patch = fresh_sources
        _summary, unresolved = restore.load_manifest_inventory(target, base, project)
        if oodle is None:
            oodle = w.Oodle(project)
        compared = compare_u4401(unresolved, patch, oodle)
        comparison_name = f'u44-0-1-shared-assets-v{w.VERSION}.json'
        restore.save_report(project / comparison_name, compared)
        rows = _load_inputs(project, comparison_name)
        if {r['logical_path'] for r in rows} != set(PINNED):
            raise w.ExportError('Fresh U44.0.0 source manifests disagree with pinned recovery objects')
    else:
        rows = _load_inputs(project)
    head_func = head_func or triage._head
    get_func = get_func or video._download
    # HEAD-only probe does not need the Oodle DLL. Instantiate only when validating bytes.
    outcomes, successes = [], {}
    for row in rows:
        name = row['logical_path']
        type_id = PINNED[name][2]
        url = triage.make_cdn_url(row, type_id)  # Never accept URLs from local reports.
        dest = _safe_object_path(project, row)
        result = {'namespace': '0', 'logical_path': name, 'url': url,
            'expected_bytes': row['expected_cdn_size_bytes'], 'cdn_type_hex': f'{type_id:X}',
            'download_attempts': []}
        try:
            if dest.is_file():
                raw = dest.read_bytes()
                if oodle is None:
                    oodle = w.Oodle(project)
                checks = _validate_payload(raw, row, oodle)
                prior_sha = _existing_checksum(project, row)
                if prior_sha is not None and (not isinstance(prior_sha, str)
                        or prior_sha.lower() != checks['sha256'].lower()):
                    raise w.ExportError('Existing recovery bytes differ from recorded SHA-256')
                result.update(status='already-verified-locally', **checks)
                successes[name] = checks
                print(f'[Local] {name} | validated; no HEAD/GET')
            else:
                head = head_func(url, timeout=timeout)
                status, length = head.get('http_status'), head.get('content_length')
                result.update(http_status=status, content_length=length)
                if status != 200 or length != row['expected_cdn_size_bytes']:
                    result['status'] = 'unavailable-or-unconfirmed'
                    result['error'] = head.get('error')
                    http_line('HEAD', status if isinstance(status, int) else 0, name, f'length {length}; skipped')
                elif not download:
                    result['status'] = 'head-confirmed-payload-not-verified'
                    http_line('HEAD', 200, name, f'exact size {length:,}; not downloaded')
                else:
                    if oodle is None:
                        oodle = w.Oodle(project)
                    raw, checks = fetch_verified(
                        url=url, logical_path=name, expected_size=row['expected_cdn_size_bytes'],
                        timeout=timeout, get_func=get_func,
                        verify_func=lambda data: _validate_payload(data, row, oodle),
                        retries=retries, attempts_log=result['download_attempts'])
                    # Recheck parent components immediately before write.
                    dest = _safe_object_path(project, row)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if dest.exists() or dest.is_symlink():
                        raise w.ExportError('Recovery path appeared during download; refusing overwrite')
                    w.atomic_write(dest, raw)
                    http_line('GET', 200, name, f'{len(raw):,} bytes; SHA-256 and CDN integrity verified')
                    result.update(status='recovered-validated', **checks)
                    successes[name] = checks
                    print(f'{color_label("Verified")} {name} | {checks["sha256"]}')
        except (OSError, ValueError, w.ExportError) as exc:
            result.update(status='failed', error=str(exc)[:400])
            print_error(f'{name}: {exc}')
        outcomes.append(result)
    if download:
        _store_collection_reports(project, rows, successes)
    report = {'version': VERSION, 'kind': 'u4400-historical-last-three-recovery' if download else 'u4400-historical-last-three-probe',
        'created_utc': _timestamp(),
        'notice': 'A manifest H digest and SHCC CRC32C do not independently authenticate historical F bytes.',
        'network': 'HEAD+explicit-GET' if download else 'HEAD-only',
        'summary': {'required': 3, 'available_locally': len(successes),
        'head_confirmed_only': sum(r['status'] == 'head-confirmed-payload-not-verified' for r in outcomes),
        'unavailable_or_failed': sum(r['status'] in {'unavailable-or-unconfirmed', 'failed'} for r in outcomes),
        'fully_verified': len(successes)},
        'objects': outcomes}
    output = project / (RECOVERY_REPORT if download else PROBE_REPORT)
    if output.is_symlink():
        raise w.ExportError('Report path is symlinked')
    restore.save_report(output, report)
    print(f'[Report] {output}')
    return report

def main(argv: list[str] | None = None) -> int:
    parser = StrictArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--probe', action='store_true', help='opt in to HEAD requests for the three exact historical URLs')
    action.add_argument('--download', action='store_true', help='opt in to HEAD+GET for only the three exact historical URLs')
    parser.add_argument('--timeout', type=float, default=20.0)
    parser.add_argument('--retries', type=int, default=5)
    parser.add_argument('--target', type=Path, help='Clean original final U44.0.0 install')
    parser.add_argument('--base', type=Path, help='Untouched original Steam base')
    parser.add_argument('--u4401-patch', type=Path, help='Exact U44.0.1 source; verified against fresh U44.0.0 inventory')
    args = parser.parse_args(argv)
    try:
        if not all((args.target, args.base, args.u4401_patch)):
            raise w.ExportError('Clean-start recovery requires --target, --base and --u4401-patch')
        report = run(PROJECT, download=args.download, timeout=args.timeout,
            fresh_sources=(args.target, args.base, args.u4401_patch), retries=args.retries)
        return 0 if report['summary']['fully_verified'] == 3 or (
            args.probe and report['summary']['head_confirmed_only'] + report['summary']['available_locally'] == 3) else 2
    except KeyboardInterrupt:
        print('\nInterrupted; prior verified files remain on disk.', file=sys.stderr)
        return 130
    except (OSError, ValueError, w.ExportError) as exc:
        print_error(exc)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
