#!/usr/bin/env python3
"""Diagnose manifest assets missing from an installed Warframe Cache.Windows.

Read-only towards both installations: uses the same hash/required-piece rule as
warframe_install_to_patch.py. Writes only new JSON/optional CSV report files.
"""
from __future__ import annotations

from common import StrictArgumentParser

import base64
import re
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import warframe_install_to_patch as w

def _parts_for_namespace(index, namespace: str, logical_path: str) -> dict[str, list[w.CacheEntry]]:
    return {kind: w._entries_for(index, namespace, logical_path, kind) for kind in 'HBF'}

def _classify_absence(asset: w.ManifestAsset, index, oodle: w.Oodle) -> dict:
    """Explain a SourceCoverageError, never replacing the exporter's decision."""
    entries = _parts_for_namespace(index, asset.namespace, asset.logical_path)
    required = w._required_piece_kinds(asset.flags)
    matching = []
    actual_hashes = defaultdict(set)
    for entry in entries['H']:
        # The exporter already established this is a coverage miss. If reading
        # now fails, surface an error instead of pretending the cache is absent.
        header = w.decompress_cache_entry(entry, oodle)
        if len(header) >= 16:
            actual_hashes[entry.package].add(w.b64m_encode(header[:16]))
            if header[:16] == asset.manifest_hash:
                matching.append(entry)

    matching_packages = sorted({entry.package for entry in matching}, key=str.casefold)
    if not entries['H']:
        reason = 'no-target-h-entry'
    elif not matching:
        reason = 'target-h-hash-mismatch'
    else:
        reason = 'required-pieces-missing'
        # The underlying validator should already have rejected all the
        # packages with a matching H if this was a SourceCoverageError.
        if any(all(w._piece_in_package(index, asset.namespace, asset.logical_path, kind, pkg)
                for kind in required) for pkg in matching_packages):
            raise w.ExportError(f'Internal mismatch in source-missing classification for {asset.namespace}{asset.logical_path}')

    missing_per_package = {
        package: [kind for kind in required if w._piece_in_package(
            index, asset.namespace, asset.logical_path, kind, package) is None]
        for package in matching_packages
    }
    packages = sorted({entry.package for group in entries.values() for entry in group}, key=str.casefold)
    components = {
        kind: sorted({entry.package for entry in group}, key=str.casefold)
        for kind, group in entries.items()
    }
    return {
        'reason': reason,
        'required_pieces': list(required),
        'present_target_entry_counts': {kind: len(group) for kind, group in entries.items()},
        'present_target_packages_by_kind': components,
        'candidate_cache_packages': packages,
        'matching_h_packages': matching_packages,
        'missing_pieces_by_matching_h_package': missing_per_package,
        'present_target_h_hashes_by_package': {
            pkg: sorted(values) for pkg, values in sorted(actual_hashes.items())
        },
    }

def _base_evidence(asset: w.ManifestAsset, base_index, oodle: w.Oodle) -> dict:
    entries = w._entries_for(base_index, asset.namespace, asset.logical_path, 'H')
    if not entries:
        return {'status': 'no-base-h-entry', 'h_entries': 0, 'packages': [], 'hash_matches': False}
    matched, read_errors = w._base_matches(base_index, asset, oodle)
    return {
        'status': 'same-hash-in-base' if matched else ('base-read-error' if read_errors else 'different-hash-in-base'),
        'h_entries': len(entries),
        'packages': sorted({entry.package for entry in entries}, key=str.casefold),
        'hash_matches': bool(matched),
        'had_read_error': read_errors,
    }

def _folder_prefix(path: str, depth: int) -> str:
    return '/' + '/'.join(path.lstrip('/').split('/')[:depth])

def _counter_dict(counter: Counter) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], str(item[0]))))

def analyze(target_root: Path, base_root: Path, *, progress_every: int = 25_000) -> dict:
    target_cache = w.find_cache_windows_dir(target_root.resolve())
    base_cache = w.find_cache_windows_dir(base_root.resolve())
    if target_cache.resolve() == base_cache.resolve():
        raise w.ExportError('Target and original base must be different installations')
    oodle = w.Oodle(Path(w.__file__).resolve().parent)
    target_index = w.scan_cache(target_cache, 'HBF')
    base_index = w.scan_cache(base_cache, 'H')
    if not base_index:
        raise w.ExportError('Original base has no live H entries')

    _, header = w._select_h_cache(target_index, oodle)
    h_index = w.parse_h_cache_header(header)
    b_records = [record for record in h_index.records
        if record.logical_path.startswith('/B.Cache.') and record.logical_path.endswith('.bin')]
    if not b_records:
        raise w.ExportError('Target H.Cache.bin lists no B.Cache families')
    raw_assets: list[w.ManifestAsset] = []
    sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    omitted_manifests: list[dict] = []
    available = []
    for record in b_records:
        namespace = w._manifest_namespace(record.logical_path)
        try:
            _, manifest_header, _ = w._build_h_only_metadata_object(
                target_index, record.logical_path, record.target_hash, oodle
            )
        except w.SourceCoverageError as exc:
            omitted_manifests.append({'path': record.logical_path, 'reason': str(exc)})
            continue
        assets = w.parse_manifest_header(manifest_header, namespace)
        raw_assets.extend(assets)
        available.append({'path': record.logical_path, 'namespace': namespace, 'objects': len(assets)})
        for asset in assets:
            sources[(asset.namespace, asset.logical_path)].add(record.logical_path)

    if not available:
        raise w.ExportError('No available B.Cache manifests were found')
    inventory, deduplicated = w._dedupe_manifest_assets(raw_assets)
    missing = []
    scanned = 0
    for asset in inventory:
        scanned += 1
        if not (asset.flags & w.MANIFEST_FLAG_H):
            raise w.ExportError(f'Manifest entry without H flag: {asset.namespace}{asset.logical_path}')
        try:
            w._select_h_by_hash(
                target_index, asset.namespace, asset.logical_path, asset.manifest_hash, oodle,
                required_piece_kinds=w._required_piece_kinds(asset.flags),
            )
        except w.SourceCoverageError as exc:
            details = _classify_absence(asset, target_index, oodle)
            original = _base_evidence(asset, base_index, oodle)
            record = {
                'namespace': asset.namespace,
                'logical_path': asset.logical_path,
                'manifest_families': sorted(sources[(asset.namespace, asset.logical_path)]),
                'manifest_section': asset.section,
                'expected_hash_base64': asset.hash_b64,
                'expected_cdn_size_bytes': asset.cdn_size,
                'manifest_hbf_flags_hex': f'0x{asset.flags:08X}',
                'source_error': str(exc),
                **details,
                'original_base': original,
            }
            missing.append(record)
        if progress_every and scanned % progress_every == 0:
            print(f'[Scan] {scanned:,}/{len(inventory):,} | source-missing {len(missing):,}')
    reasons = Counter(item['reason'] for item in missing)
    sections = Counter(item['manifest_section'] for item in missing)
    namespaces = Counter(item['namespace'] for item in missing)
    bases = Counter(item['original_base']['status'] for item in missing)
    folders1 = Counter(_folder_prefix(item['logical_path'], 1) for item in missing)
    folders3 = Counter(_folder_prefix(item['logical_path'], 3) for item in missing)
    manifest_families = Counter(fam for item in missing for fam in item['manifest_families'])
    # Report every manifest object for completeness, but avoid duplicating
    # large manifest inventories in the report itself.
    return {
        'report_version': w.VERSION,
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'target_cache': str(target_cache),
        'base_cache': str(base_cache),
        'scope': 'Only manifest families actually available in the source installation; missing language/DX manifests are excluded',
        'summary': {
            'h_cache_manifest_families_total': len(b_records),
            'available_manifest_families': available,
            'unavailable_manifest_families': omitted_manifests,
            'manifest_objects_scanned': scanned,
            'duplicate_manifest_entries_ignored': deduplicated,
            'source_present': scanned - len(missing),
            'source_missing': len(missing),
            'missing_by_reason': _counter_dict(reasons),
            'missing_by_manifest_section': _counter_dict(sections),
            'missing_by_namespace': _counter_dict(namespaces),
            'missing_by_base_status': _counter_dict(bases),
            'missing_by_top_level_path': _counter_dict(folders1),
            'missing_by_three_level_path_prefix': _counter_dict(folders3),
            'missing_by_manifest_family': _counter_dict(manifest_families),
        },
        'missing_objects': missing,
    }

_CSV_COLUMNS = ('namespace', 'logical_path', 'manifest_section', 'manifest_families',
    'expected_hash_base64', 'expected_cdn_size_bytes', 'manifest_hbf_flags_hex',
    'reason', 'required_pieces', 'candidate_cache_packages', 'matching_h_packages',
    'missing_pieces_by_matching_h_package', 'original_base_status',
    'original_base_packages', 'original_base_hash_matches', 'source_error')

def write_csv(path: Path, report: dict) -> None:
    with path.open('x', newline='', encoding='utf-8-sig') as handle:
        writer = csv.DictWriter(handle, fieldnames=_CSV_COLUMNS)
        writer.writeheader()
        for obj in report['missing_objects']:
            writer.writerow({
                'namespace': obj['namespace'],
                'logical_path': obj['logical_path'],
                'manifest_section': obj['manifest_section'],
                'manifest_families': '; '.join(obj['manifest_families']),
                'expected_hash_base64': obj['expected_hash_base64'],
                'expected_cdn_size_bytes': obj['expected_cdn_size_bytes'],
                'manifest_hbf_flags_hex': obj['manifest_hbf_flags_hex'],
                'reason': obj['reason'],
                'required_pieces': ''.join(obj['required_pieces']),
                'candidate_cache_packages': '; '.join(obj['candidate_cache_packages']),
                'matching_h_packages': '; '.join(obj['matching_h_packages']),
                'missing_pieces_by_matching_h_package': json.dumps(obj['missing_pieces_by_matching_h_package'], sort_keys=True),
                'original_base_status': obj['original_base']['status'],
                'original_base_packages': '; '.join(obj['original_base']['packages']),
                'original_base_hash_matches': obj['original_base']['hash_matches'],
                'source_error': obj['source_error'],
            })

def _outside_sources(report_path: Path, sources: tuple[Path, Path]) -> None:
    resolved = report_path.resolve()
    if any(resolved.is_relative_to(source.resolve()) for source in sources):
        raise w.ExportError(f'Report path must be outside target and base installations: {report_path}')
    if report_path.exists() or report_path.is_symlink():
        raise w.ExportError(f'Report already exists (no overwrite): {report_path}')

def verify_base_inheritance(report: dict, base_root: Path) -> dict:
    objects = report.get('missing_objects')
    if not isinstance(objects, list) or report.get('summary', {}).get('source_missing') != len(objects):
        raise w.ExportError('Invalid missing-source report (object count mismatch)')
    if report.get('report_version') != w.VERSION:
        raise w.ExportError('Unsupported missing-source report version')
    base_cache = w.find_cache_windows_dir(base_root.resolve())
    if base_cache.resolve() != Path(report.get('base_cache', '')).resolve():
        raise w.ExportError('Supplied Steam base is different from the base used in the missing-source report')
    index = w.scan_cache(base_cache, 'HBF')
    oodle = w.Oodle(Path(w.__file__).resolve().parent)
    classified = []
    seen = set()
    for source in objects:
        namespace = source['namespace']
        logical = source['logical_path']
        path_key = (namespace, logical)
        if path_key in seen:
            raise w.ExportError(f'Duplicate asset in source report: {namespace}{logical}')
        seen.add(path_key)
        w._validate_logical_path(logical)
        flags = int(source['manifest_hbf_flags_hex'], 16)
        if not flags & w.MANIFEST_FLAG_H:
            raise w.ExportError(f'Asset has no H flag: {namespace}{logical}')
        try:
            encoded = source['expected_hash_base64']
            if not isinstance(encoded, str) or not re.fullmatch(r'[A-Za-z0-9+\-]{22}', encoded):
                raise ValueError('Bad Base64 manifest hash')
            digest = base64.b64decode(encoded.replace('-', '/') + '==', validate=True)
            if w.b64m_encode(digest) != encoded:
                raise ValueError('Noncanonical manifest hash')
        except (ValueError, AttributeError, TypeError) as exc:
            raise w.ExportError(f'Invalid hash for {namespace}{logical}') from exc
        if len(digest) != 16:
            raise w.ExportError(f'Invalid hash length for {namespace}{logical}')
        required = w._required_piece_kinds(flags)
        status = 'not-fully-in-base'
        reason = None
        package = None
        try:
            entry, header, _type = w._select_h_by_hash(
                index, namespace, logical, digest, oodle, required_piece_kinds=required
            )
            package = entry.package
            if header[:16] != digest:
                raise w.ExportError(f'Internal hash inconsistency for {namespace}{logical}')
            for kind in required:
                piece = w._piece_in_package(index, namespace, logical, kind, package)
                if piece is None:
                    raise w.ExportError(f'Missing selected {kind} piece for {namespace}{logical}')
                w.decompress_cache_entry(piece, oodle)
            status = 'verified-in-base'
        except w.SourceCoverageError as exc:
            status = 'not-fully-in-base'
            reason = str(exc)
        except w.ExportError as exc:
            status = 'base-read-error'
            reason = str(exc)
        classified.append({
            'namespace': namespace,
            'logical_path': logical,
            'status': status,
            'base_package': package,
            'required_pieces': list(required),
            'original_base_h_status': source.get('original_base', {}).get('status'),
            'reason': reason,
        })
    groups = Counter(x['status'] for x in classified)
    return {
        'version': w.VERSION,
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'base_cache': str(base_cache),
        'note': 'Verification requires matching base H hash and readable B/F pieces in the same package. It does not verify the full original CDN bytes.',
        'summary': {
            'source_missing_in_target': len(classified),
            'verified_in_base': groups['verified-in-base'],
            'not_fully_in_base': groups['not-fully-in-base'],
            'base_read_error': groups['base-read-error'],
        },
        'objects': classified,
    }

def _scan_residual_entries(cache: Path, wanted: set[tuple[str, str]]):
    """Index only requested H/F paths, including normally ignored TOC tombstones.

    Reading an old TOC record does not imply its cache bytes still exist. The
    caller verifies offsets, decoding and H identity before reporting candidates.
    """
    index = {}
    for kind in 'HF':
        for toc_path in sorted(cache.glob(f'{kind}.*.toc'), key=lambda p: p.name.casefold()):
            if toc_path.is_symlink() or not toc_path.is_file():
                raise w.ExportError(f'Unsafe cache TOC: {toc_path}')
            package = toc_path.name[2:-4]
            if not package:
                continue
            for deleted in (False, True):
                for entry in w.iter_toc_entries(toc_path, kind, package, deleted_only=deleted):
                    key = (entry.namespace, entry.logical_path)
                    if key in wanted:
                        slot = index.setdefault(key, {}).setdefault(kind, [])
                        if len(slot) >= 64:
                            raise w.ExportError(f'Too many historical TOC records for {entry.namespace}{entry.logical_path}')
                        slot.append((entry, deleted))
    return index

def _probe_residual_source(index: dict, row: dict, oodle: w.Oodle) -> dict:
    """Conservatively classify readable cache pieces; never reconstruct unknown F bytes."""
    namespace, logical = row['namespace'], row['logical_path']
    encoded = row['expected_hash_base64']
    if not isinstance(encoded, str) or not re.fullmatch(r'[A-Za-z0-9+\-]{22}', encoded):
        raise w.ExportError(f'Invalid manifest hash: {namespace}{logical}')
    digest = base64.b64decode(encoded.replace('-', '/') + '==', validate=True)
    if len(digest) != 16 or w.b64m_encode(digest) != encoded:
        raise w.ExportError(f'Noncanonical manifest digest: {namespace}{logical}')
    required = w._required_piece_kinds(int(row['manifest_hbf_flags_hex'], 16))
    if required not in ('', 'F'):
        raise w.ExportError(f'Unexpected missing-asset flags: {namespace}{logical}')
    pieces = index.get((namespace, logical), {})
    found = {'H': {'live': 0, 'deleted': 0}, 'F': {'live': 0, 'deleted': 0}}
    valid_h = []
    valid_f = []
    read_errors = []
    for kind in 'HF':
        for entry, deleted in pieces.get(kind, []):
            label = 'deleted' if deleted else 'live'
            found[kind][label] += 1
            try:
                # Do not trust stale TOC offsets: decompression checks their
                # declared bounds and decoded byte count against cache bytes.
                decoded = w.decompress_cache_entry(entry, oodle)
            except (w.ExportError, OSError, ValueError) as exc:
                if len(read_errors) < 6:
                    read_errors.append(f'{kind} {label} {entry.package}: {exc}')
                continue
            item = {'package': entry.package, 'toc_state': label,
                'decoded_bytes': len(decoded)}
            if kind == 'H' and decoded[:16] == digest:
                valid_h.append(item)
            elif kind == 'F':
                valid_f.append(item)
    paired = sorted({(h['package'], h['toc_state'], f['toc_state'])
        for h in valid_h for f in valid_f if h['package'] == f['package']})
    # A local F without matching H cannot be authenticated from the manifest.
    if valid_h and (not required or paired):
        status = 'candidate-matching-h-and-required-pieces'
    elif valid_h:
        status = 'matching-h-but-required-f-missing'
    elif valid_f:
        status = 'readable-f-without-matching-h'
    else:
        status = 'no-matching-readable-pieces'
    return {'status': status, 'toc_entries': found,
        'matching_h_entries': valid_h,
        'readable_f_entries': valid_f,
        'same_package_h_f_pairs': [{'package': p, 'h_state': h, 'f_state': f}
            for p, h, f in paired], 'read_errors': read_errors}

def _probe_residual_from_run(target: Path, base: Path, run_report: Path) -> dict:
    """Analyze missing objects from one unchanged run, without rescanning all manifests."""
    import source_inventory as inventory
    report = json.loads(run_report.read_text(encoding='utf-8'))
    docs = report.get('details', {})
    missing = docs.get(f'missing-source-v{w.VERSION}.json')
    inherited = docs.get(f'base-inheritance-v{w.VERSION}.json')
    snapshot = docs.get(inventory.SOURCE_SNAPSHOT_NAME)
    if (not isinstance(missing, dict) or not isinstance(inherited, dict)
            or not isinstance(snapshot, dict)
            or missing.get('report_version') != w.VERSION
            or inherited.get('version') != w.VERSION):
        raise w.ExportError('Run JSON lacks compatible missing-source, inheritance or source-snapshot reports')
    if inventory.source_snapshot(target, base) != snapshot:
        raise w.ExportError('Source TOCs/cache files or executable differ from this run; use a current run report')
    candidates = missing.get('missing_objects')
    inheritance = inherited.get('objects')
    if not isinstance(candidates, list) or not isinstance(inheritance, list):
        raise w.ExportError('Invalid inventory arrays in run report')
    if (len(candidates) != missing.get('summary', {}).get('source_missing')
            or len(inheritance) != inherited.get('summary', {}).get('source_missing_in_target')):
        raise w.ExportError('Mismatched source-inventory counts')
    base_status = {}
    for item in inheritance:
        key = (item['namespace'], item['logical_path'])
        if key in base_status:
            raise w.ExportError('Repeated asset in inheritance inventory')
        base_status[key] = item['status']
    remaining = []
    seen = set()
    for row in candidates:
        key = (row['namespace'], row['logical_path'])
        if key in seen or key not in base_status:
            raise w.ExportError('Unmatched or repeated missing asset in inventory')
        seen.add(key)
        if base_status[key] == 'verified-in-base':
            continue
        if base_status[key] != 'not-fully-in-base':
            raise w.ExportError('Original Steam base has unreadable or unclassified assets')
        w._validate_manifest_namespace(key[0])
        w._validate_logical_path(key[1])
        remaining.append(row)
    if len(remaining) > 512:
        raise w.ExportError('Residual probe exceeds 512 missing assets')
    wanted = {(row['namespace'], row['logical_path']) for row in remaining}
    oodle = w.Oodle(Path(w.__file__).resolve().parent)
    sources = {}
    for label, root in (('target', target), ('steam-base', base)):
        cache = w.find_cache_windows_dir(root)
        print(f'[Residual] Scanning live and deleted H/F TOC records in {label}: {cache}')
        sources[label] = _scan_residual_entries(cache, wanted)
    items = []
    for row in remaining:
        item = {'namespace': row['namespace'], 'logical_path': row['logical_path'],
            'manifest_hash': row['expected_hash_base64'],
            'expected_cdn_bytes': row['expected_cdn_size_bytes'],
            'required_pieces': row['required_pieces'],
            'target': _probe_residual_source(sources['target'], row, oodle),
            'steam_base': _probe_residual_source(sources['steam-base'], row, oodle)}
        items.append(item)
    groups = Counter(v['status'] for item in items for v in (item['target'], item['steam_base']))
    possible = [item for item in items if any(
        item[x]['status'] == 'candidate-matching-h-and-required-pieces'
        for x in ('target', 'steam_base'))]
    return {'version': w.VERSION, 'kind': 'offline-cache-residual-probe',
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'input_run': str(run_report.resolve()), 'target': str(target), 'steam_base': str(base),
        'summary': {'external_dependencies_examined': len(items),
            'matching_h_and_required_pieces_candidates': len(possible),
            'no_complete_matching_local_source': len(items) - len(possible),
            'source_statuses': dict(groups)},
        'limitations': [
            'Only TOC-addressable bytes are inspected; arbitrary unindexed cache gaps are not scanned.',
            'Deleted TOC records can point to overwritten bytes; all candidate H bytes are checked against the manifest.',
            'Even a matching H and readable F cannot prove the exact original historical F bytes without stronger evidence.',
            'This probe is read-only and does not use CDN data or a later update patch; candidates are NOT imported into the export.'
        ], 'objects': items}

def main(argv: list[str] | None = None) -> int:
    parser = StrictArgumentParser(description=__doc__)
    parser.add_argument('target', type=Path, help='Warframe target installation (or Cache.Windows directory)')
    parser.add_argument('base', type=Path, help='original Steam depot installation (or Cache.Windows directory)')
    parser.add_argument('-o', '--output', type=Path, default=Path('missing-source-v0.1.json'))
    parser.add_argument('--csv', type=Path, help='optional CSV output file with one row per missing object')
    parser.add_argument('--residual-run-report', type=Path,
        help='Read-only offline probe of live/deleted H/F TOC records for missing assets from a completed run JSON')
    parser.add_argument('--progress-every', type=int, default=25_000,
        help='print scan progress every N manifest objects (0 to suppress)')
    args = parser.parse_args(argv)
    try:
        if args.progress_every < 0:
            raise w.ExportError('--progress-every must be nonnegative')
        target, base = args.target.resolve(), args.base.resolve()
        if not target.is_dir() or not base.is_dir():
            raise w.ExportError('Target and base must be existing directories')
        json_path = args.output.resolve()
        csv_path = args.csv.resolve() if args.csv else None
        if csv_path == json_path:
            raise w.ExportError('JSON and CSV report paths must be different')
        for path in (json_path, csv_path):
            if path is not None:
                _outside_sources(path, (target, base))
        if args.residual_run_report is not None:
            if csv_path is not None:
                raise w.ExportError('--csv cannot be combined with --residual-run-report')
            result = _probe_residual_from_run(target, base, args.residual_run_report)
            json_path.parent.mkdir(parents=True, exist_ok=True)
            with json_path.open('x', encoding='utf-8') as handle:
                json.dump(result, handle, ensure_ascii=False, indent=2)
                handle.write('\n')
            totals = result['summary']
            print(f"[Residual] Matching H + required pieces: {totals['matching_h_and_required_pieces_candidates']}/"
                  f"{totals['external_dependencies_examined']} (candidate only, not exact CDN verification)")
            print(f'[Report] JSON: {json_path}')
            return 0
        print('[Inspect] Source availability follows the exporter\'s H-hash and required B/F-package checks.')
        print('[Inspect] Both installations remain read-only. Missing language/DX manifests are excluded.')
        result = analyze(target, base, progress_every=args.progress_every)
        summary = result['summary']
        print(f"[Inspect] Available manifest families: {len(summary['available_manifest_families'])}/{summary['h_cache_manifest_families_total']}")
        print(f"[Inspect] Source-missing: {summary['source_missing']:,}/{summary['manifest_objects_scanned']:,}")
        for reason, number in summary['missing_by_reason'].items():
            print(f'[Reason] {reason}: {number:,}')
        for key, number in list(summary['missing_by_three_level_path_prefix'].items())[:8]:
            print(f'[Group] {key}: {number:,}')
        for key, number in summary['missing_by_base_status'].items():
            print(f'[Base] {key}: {number:,}')
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with json_path.open('x', encoding='utf-8') as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
        print(f'[Report] JSON: {json_path}')
        if csv_path is not None:
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            write_csv(csv_path, result)
            print(f'[Report] CSV : {csv_path}')
        return 0
    except (w.ExportError, OSError, ValueError) as exc:
        print(f'[Error] {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
