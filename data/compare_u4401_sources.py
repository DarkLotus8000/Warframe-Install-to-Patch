#!/usr/bin/env python3
"""Read-only exact-identity comparison of U44.0.0's 103 missing files with a U44.0.1 patch.

Search the supplied U44.0.1 OpenWF/Content directory for *exact* U44.0.0
namespace/path/type/H-digest CDN filenames. Revalidate SHCC, CRC, CommonHeader
hash/type, H/B/F slots and manifest CDN size. A newer same-name/different-hash
object is only listed as a diagnostic and is never accepted or substituted.

No network activity, no game/patch modifications, no recovered output copies.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import sys

import recover_missing_cdn as video
import recover_remaining_h_only as honly
import restore_u44_complete as restore
import warframe_install_to_patch as w

PROBE_KIND = 'u44.0.0-assets-in-u44.0.1-patch'

def safe_patch_content(source_patch: Path) -> Path:
    patch = source_patch.resolve(strict=True)
    content = patch / 'OpenWF' / 'Content'
    if not patch.is_dir() or not content.is_dir() or content.is_symlink():
        raise w.ExportError(f'U44.0.1 patch must contain OpenWF/Content: {source_patch}')
    if not content.resolve().is_relative_to(patch):
        raise w.ExportError('Patch Content directory escapes its patch root')
    return content

def expected_type(row: dict) -> int:
    if row['category'] in ('video-preview', 'other-video'):
        if row['namespace'] != '0' or row['required_pieces'] != ['F'] or not row['logical_path'].lower().endswith('.bk2'):
            raise w.ExportError('Unexpected U44 missing video inventory fields')
        return 0xAA
    if row['category'] == 'non-video-resource':
        identity = (row['namespace'], row['logical_path'], row['expected_hash_base64'], row['expected_cdn_size_bytes'])
        if identity not in honly.KNOWN_TARGETS or row['required_pieces'] != []:
            raise w.ExportError('Unexpected H-only U44 source identity')
        # Both H-only types were previously resolved and verified as D2.
        return 0xD2
    raise w.ExportError(f'Unexpected U44 missing source category: {row["category"]}')

def variants_in_parent(expected: Path) -> list[str]:
    """Diagnostic only. Different hashes/types are NEVER considered recoveries."""
    parent = expected.parent
    if not parent.is_dir() or parent.is_symlink():
        return []
    basename = expected.name.split('!', 1)[0] + '!'
    variants = []
    # Only bounded sibling lookups, not a recursive scan of the entire patch.
    for path in parent.iterdir():
        if path.name.startswith(basename) and path.name != expected.name and path.is_file():
            variants.append(path.name)
    return sorted(variants)[:12]

def check_one(row: dict, content: Path, oodle) -> dict:
    type_id = expected_type(row)
    ns, logical, digest = row['namespace'], row['logical_path'], row['expected_hash_base64']
    expected = w._safe_output_path(content, ns, logical, type_id, digest)
    record = {
        'namespace': ns, 'logical_path': logical,
        'u44_0_0_hash': digest, 'u44_0_0_type': f'{type_id:X}',
        'expected_bytes': row['expected_cdn_size_bytes'],
        'expected_relative_path': expected.relative_to(content.parent.parent).as_posix(),
    }
    if expected.is_symlink() or (expected.exists() and not expected.is_file()):
        record.update(status='exact-path-rejected', error='Not a regular file or symlink')
        return record
    if not expected.is_file():
        variants = variants_in_parent(expected)
        record.update(status='exact-object-absent', different_identity_names=variants,
                      different_identity_count_shown=len(variants))
        return record
    if not expected.resolve().is_relative_to(content.resolve()):
        record.update(status='exact-path-rejected', error='File escapes source Content directory')
        return record
    if expected.stat().st_size != row['expected_cdn_size_bytes']:
        record.update(status='exact-object-rejected', error='File size differs from U44.0.0 manifest',
                      found_bytes=expected.stat().st_size)
        return record
    try:
        data = expected.read_bytes()
        checks = (video.validate_cdn_payload(data, row, oodle)
                  if type_id == 0xAA else honly.validate_h_only_payload(data, row, type_id, oodle))
    except (w.ExportError, OSError, ValueError) as exc:
        record.update(status='exact-object-rejected', error=str(exc)[:400])
        return record
    record.update(status='exact-object-verified', actual_sha256=checks['sha256'],
                  validation=checks['validation'],
                  full_payload_identity_limit='U44 manifest pins H CommonHeader, not a historical full-payload SHA256')
    return record

def compare(rows: list[dict], source_patch: Path, oodle) -> dict:
    """Inspect every item. Never ignore a missing/invalid item or alter the source patch."""
    content = safe_patch_content(source_patch)
    if not rows:
        raise w.ExportError('Missing input inventory; refusing an empty success report')
    seen = set()
    records = []
    for row in sorted(rows, key=lambda r: (r['namespace'], r['logical_path'])):
        key = (row['namespace'].casefold(), row['logical_path'].casefold())
        if key in seen:
            raise w.ExportError('Duplicate/case-colliding missing object')
        seen.add(key)
        records.append(check_one(row, content, oodle))
    counts = Counter(r['status'] for r in records)
    alternate_count = sum(bool(r.get('different_identity_names')) for r in records)
    verified = counts['exact-object-verified']
    return {
        'version': w.VERSION, 'kind': PROBE_KIND,
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'source_patch': str(content.parent.parent),
        'notice': 'Read-only. Exact U44.0.0 CDN identity required. No U44.0.1 substitutions or network requests.',
        'summary': {
            'required_missing_u44_objects': len(records),
            'exact_objects_verified': verified,
            'exact_objects_absent': counts['exact-object-absent'],
            'exact_objects_rejected': counts['exact-object-rejected'] + counts['exact-path-rejected'],
            'missing_with_different_identity_candidate': alternate_count,
            'remaining_not_verified': len(records) - verified,
            'all_required_verified': verified == len(records),
        },
        'limitations': [
            'A U44.0.1 incremental patch may omit objects it inherits; absent here does not prove absent from the U44.0.1 installed client.',
            'A filename and digest alone do not prove matching payload; each exact object is also CRC/SHCC/H/flags/size-validated.',
            'The manifest H digest is not an independent cryptographic hash of the entire video F payload.',
            'Different-identity candidates are diagnostic only and are never copied or treated as U44.0.0 matches.',
        ],
        'objects': records,
    }

def validate_probe_paths(target: Path, base: Path, source: Path, workspace: Path) -> None:
    t, b, s, ws = (p.resolve() for p in (target, base, source, workspace))
    if len({t, b, s, ws}) != 4:
        raise w.ExportError('Target, Steam base, U44.0.1 patch and report workspace must be distinct')
    for other in (t, b, s):
        if ws.is_relative_to(other) or other.is_relative_to(ws):
            raise w.ExportError('Report workspace cannot overlap an input directory')

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('target', type=Path, help='Installed U44.0.0 directory')
    p.add_argument('base', type=Path, help='Original Steam base')
    p.add_argument('source_patch', type=Path, help='Existing U44.0.1 patch directory containing OpenWF/Content')
    p.add_argument('--workspace', required=True, type=Path, help='Separate directory for local inventory and comparison JSON')
    args = p.parse_args(argv)
    try:
        validate_probe_paths(args.target, args.base, args.source_patch, args.workspace)
        safe_patch_content(args.source_patch)
        args.workspace.mkdir(parents=True, exist_ok=True)
        print('[U44.0.1] Compare U44.0.0 missing CDN objects against the nearest update patch (offline, read-only)')
        _, rows = restore.load_manifest_inventory(args.target, args.base, args.workspace)
        result = compare(rows, args.source_patch, w.Oodle(Path(w.__file__).resolve().parent))
        report = args.workspace / f'u44-0-1-shared-assets-v{w.VERSION}.json'
        restore.save_report(report, result)
        s = result['summary']
        print(f"[U44.0.1] Exact verified: {s['exact_objects_verified']}/{s['required_missing_u44_objects']}; "
              f"absent {s['exact_objects_absent']}; invalid {s['exact_objects_rejected']}")
        print(f"[U44.0.1] Different-hash/type candidates (NOT usable): {s['missing_with_different_identity_candidate']}")
        print('[Report] ' + str(report))
        print('[Notice] Only exact verified files could be reused. No files were copied or downloaded.')
        return 0  # Reporting absent objects is not a program failure.
    except (w.ExportError, OSError, ValueError, KeyError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
