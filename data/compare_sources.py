#!/usr/bin/env python3
"""Read-only exact-identity comparison of manifest-missing files with a source patch.

Search the source OpenWF/Content directory for exact manifest namespace/path/H
identities without assuming a particular build, file count, or CDN type. Revalidate SHCC, CRC, CommonHeader
hash/type, H/B/F slots and manifest CDN size. A newer same-name/different-hash
object is only listed as a diagnostic and is never accepted or substituted.

No network activity, no game/patch modifications, no recovered output copies.
"""
from __future__ import annotations

from common import StrictArgumentParser, error as print_error

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import sys

import recover_missing_cdn as video
import recover_remaining_h_only as honly
import source_inventory as restore
import warframe_install_to_patch as w

PROBE_KIND = 'manifest-assets-in-source-patch'

def safe_patch_content(source_patch: Path) -> Path:
    patch = source_patch.resolve(strict=True)
    content = patch / 'OpenWF' / 'Content'
    if not patch.is_dir() or not content.is_dir() or content.is_symlink():
        raise w.ExportError(f'Source patch must contain OpenWF/Content: {source_patch}')
    if not content.resolve().is_relative_to(patch):
        raise w.ExportError('Patch Content directory escapes its patch root')
    return content

def expected_type(row: dict) -> int | None:
    """Return a defensible file type, or defer discovery to the source object."""
    if row['category'] in ('video-preview', 'other-video'):
        if row['required_pieces'] != ['F'] or not row['logical_path'].lower().endswith('.bk2'):
            raise w.ExportError('Unsupported missing video flags')
        return 0xAA
    if row['category'] == 'non-video-resource':
        if row['required_pieces'] != []:
            raise w.ExportError('Unsupported non-video recovery flags')
        return None
    raise w.ExportError('Unknown missing asset category')

def exact_candidates(content: Path, row: dict) -> list[tuple[Path, int]]:
    """Find hash-identical filenames without assuming the CDN type number."""
    logical, namespace, digest = (row[k] for k in
        ('logical_path', 'namespace', 'expected_hash_base64'))
    w._validate_manifest_namespace(namespace)
    directory = w._safe_output_path(content, namespace, logical, 0, digest).parent
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise w.ExportError('Source CDN directory is not an ordinary directory')
    if not directory.is_dir():
        return []
    basename = w._validate_logical_path(logical)[-1] + '!'
    suffix = '_' + digest
    result = []
    for item in directory.iterdir():
        if not item.name.startswith(basename) or not item.name.endswith(suffix):
            continue
        if item.is_symlink() or not item.is_file() or not item.resolve().is_relative_to(content):
            raise w.ExportError('Unsafe exact-identity source object')
        number = item.name[len(basename):-len(suffix)]
        if not number or len(number) > 4 or not all(c in '0123456789ABCDEF' for c in number):
            raise w.ExportError('Malformed CDN type in exact source filename')
        type_id = int(number, 16)
        if type_id == 0:
            raise w.ExportError('Invalid zero CDN type')
        result.append((item, type_id))
        if len(result) > 1:
            raise w.ExportError('Ambiguous exact source identity has multiple CDN types')
    return result

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
    hinted_type = expected_type(row)
    namespace, logical, digest = (row[k] for k in
        ('namespace', 'logical_path', 'expected_hash_base64'))
    record = {'namespace': namespace, 'logical_path': logical,
        'manifest_hash': digest, 'expected_bytes': row['expected_cdn_size_bytes'],
        'expected_flags': row['manifest_flags']}
    try:
        candidates = exact_candidates(content, row)
    except (w.ExportError, OSError) as exc:
        record.update(status='exact-path-rejected', error=str(exc)[:400])
        return record
    if not candidates:
        hint = w._safe_output_path(content, namespace, logical, hinted_type or 0, digest)
        variants = variants_in_parent(hint)
        record.update(status='exact-object-absent', different_identity_names=variants,
            different_identity_count_shown=len(variants))
        return record
    path, type_id = candidates[0]
    record['cdn_type_hex'] = f'{type_id:X}'
    record['expected_relative_path'] = path.relative_to(content.parent.parent).as_posix()
    if hinted_type is not None and hinted_type != type_id:
        record.update(status='exact-object-rejected', error='Video type disagrees with installed evidence')
        return record
    if path.stat().st_size != row['expected_cdn_size_bytes']:
        record.update(status='exact-object-rejected', error='File size differs from target manifest',
            found_bytes=path.stat().st_size)
        return record
    try:
        data = path.read_bytes()
        checks = (video.validate_cdn_payload(data, row, oodle)
            if hinted_type == 0xAA else honly.validate_h_only_payload(data, row, type_id, oodle))
    except (w.ExportError, OSError, ValueError) as exc:
        record.update(status='exact-object-rejected', error=str(exc)[:400])
        return record
    record.update(status='exact-object-verified', actual_sha256=checks['sha256'],
        validation=checks['validation'],
        full_payload_identity_limit='Manifest H does not independently authenticate historical F bytes')
    return record

def compare(rows: list[dict], source_patch: Path | None, oodle) -> dict:
    """Inspect every item. Never ignore a missing/invalid item or alter the source patch."""
    content = safe_patch_content(source_patch) if source_patch is not None else None
    seen = set()
    records = []
    for row in sorted(rows, key=lambda r: (r['namespace'], r['logical_path'])):
        key = (row['namespace'].casefold(), row['logical_path'].casefold())
        if key in seen:
            raise w.ExportError('Duplicate/case-colliding missing object')
        seen.add(key)
        records.append(check_one(row, content, oodle) if content is not None else {
            'namespace': row['namespace'], 'logical_path': row['logical_path'],
            'manifest_hash': row['expected_hash_base64'], 'expected_bytes': row['expected_cdn_size_bytes'],
            'expected_flags': row['manifest_flags'], 'status': 'exact-object-absent'})
    counts = Counter(r['status'] for r in records)
    alternate_count = sum(bool(r.get('different_identity_names')) for r in records)
    verified = counts['exact-object-verified']
    return {
        'version': w.VERSION, 'kind': PROBE_KIND,
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'source_patch': str(content.parent.parent) if content is not None else None,
        'notice': 'Read-only. Exact target manifest identity required; no newer-version substitutions.',
        'summary': {
            'required_missing_objects': len(records),
            'exact_objects_verified': verified,
            'exact_objects_absent': counts['exact-object-absent'],
            'exact_objects_rejected': counts['exact-object-rejected'] + counts['exact-path-rejected'],
            'missing_with_different_identity_candidate': alternate_count,
            'remaining_not_verified': len(records) - verified,
            'all_required_verified': verified == len(records),
        },
        'limitations': [
            'An incremental source patch may omit objects inherited from its own base.',
            'A filename and digest alone do not prove matching payload; each exact object is also CRC/SHCC/H/flags/size-validated.',
            'The manifest H digest is not an independent cryptographic hash of the entire video F payload.',
            'Different-identity candidates are diagnostic only and are never copied as exact matches.',
        ],
        'objects': records,
    }

def validate_probe_paths(target: Path, base: Path, source: Path, workspace: Path) -> None:
    t, b, s, ws = (p.resolve() for p in (target, base, source, workspace))
    if len({t, b, s, ws}) != 4:
        raise w.ExportError('Target, Steam base, source patch and report workspace must be distinct')
    for other in (t, b, s):
        if ws.is_relative_to(other) or other.is_relative_to(ws):
            raise w.ExportError('Report workspace cannot overlap an input directory')

def main(argv: list[str] | None = None) -> int:
    p = StrictArgumentParser(description=__doc__)
    p.add_argument('target', type=Path, help='Untouched final installation directory')
    p.add_argument('base', type=Path, help='Original Steam base')
    p.add_argument('source_patch', type=Path, help='Existing source patch directory containing OpenWF/Content')
    p.add_argument('--workspace', required=True, type=Path, help='Separate directory for local inventory and comparison JSON')
    args = p.parse_args(argv)
    try:
        validate_probe_paths(args.target, args.base, args.source_patch, args.workspace)
        safe_patch_content(args.source_patch)
        args.workspace.mkdir(parents=True, exist_ok=True)
        print('[Source] Compare missing CDN objects with the supplied source patch (offline, read-only)')
        _, rows = restore.load_manifest_inventory(args.target, args.base, args.workspace)
        result = compare(rows, args.source_patch, w.Oodle(Path(w.__file__).resolve().parent))
        report = args.workspace / f'manifest-source-comparison-v{w.VERSION}.json'
        restore.save_report(report, result)
        s = result['summary']
        print(f"[Source] Exact verified: {s['exact_objects_verified']}/{s['required_missing_objects']}; "
              f"absent {s['exact_objects_absent']}; invalid {s['exact_objects_rejected']}")
        print(f"[Source] Different-hash/type candidates (NOT usable): {s['missing_with_different_identity_candidate']}")
        print('[Report] ' + str(report))
        print('[Notice] Only exact verified files could be reused. No files were copied or downloaded.')
        return 0  # Reporting absent objects is not a program failure.
    except (w.ExportError, OSError, ValueError, KeyError) as exc:
        print_error(exc)
        return 2

if __name__ == '__main__':
    sys.exit(main())
