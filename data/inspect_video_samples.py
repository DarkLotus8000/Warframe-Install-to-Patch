"""Compare video asset samples with supplied caches and manifest reports, read-only."""
from pathlib import Path
import hashlib
import json
import struct
import argparse
from collections import Counter
import warframe_install_to_patch as w
from recover_missing_cdn import validate_cdn_payload, _unpack_framed_payload
from inspect_missing_source import _outside_sources
from probe_unindexed_cache import select_rows

def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sample', type=Path)
    parser.add_argument('residual_report', type=Path)
    parser.add_argument('missing_report', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    sample = args.sample
    residual = json.loads(args.residual_report.read_text())
    missing = json.loads(args.missing_report.read_text())
    target = w.find_cache_windows_dir(Path(residual['target']))
    _outside_sources(args.output, (sample, target, Path(residual['steam_base'])))
    requested = select_rows(residual, missing)
    rows = {(x['logical_path'], x['expected_hash_base64']): x for x in missing['missing_objects']}
    if len(rows) != len(missing['missing_objects']):
        raise w.ExportError('Sample report contains ambiguous path/hash identities across namespaces')
    unresolved = {(x['logical_path'], x['expected_hash_base64']) for x in requested}
    oodle = w.Oodle(Path(w.__file__).parent)
    report = {'sample_root': str(sample), 'target_cache': str(target), 'files': [], 'assets': [],
        'limitations': ['Sample origin is user-supplied evidence; filenames alone are not trusted.',
            'SHCC size, CRC32C and H type/hash checks do not cryptographically authenticate original historical F bytes.',
            'No network, later update, cache modification, export or recovery import is used.']}
    for path in sorted(sample.glob('*')):
        if not path.is_file() or path.suffix not in ('.cache', '.toc'):
            continue
        source = target / path.name
        h = sha(path)
        report['files'].append({'file': path.name, 'bytes': path.stat().st_size, 'sha256': h,
            'identical_to_target': source.is_file() and source.stat().st_size == path.stat().st_size and sha(source) == h})
    print('Cache/TOC comparisons complete', flush=True)
    index = {}
    f_hashes = {}
    for toc in sorted(sample.glob('*.toc')):
        kind, package = toc.name[0], toc.name[2:-4]
        for deleted in (False, True):
            for entry in w.iter_toc_entries(toc, kind, package, deleted_only=deleted):
                if not entry.logical_path.lower().endswith('.bk2'):
                    continue
                try:
                    decoded = w.decompress_cache_entry(entry, oodle)
                except w.ExportError:
                    continue
                item = {'kind': kind, 'package': package, 'deleted': deleted,
                    'decoded_bytes': len(decoded), 'sha256': hashlib.sha256(decoded).hexdigest()}
                if kind == 'H':
                    item['header_hash'] = w.b64m_encode(decoded[:16])
                    item['header_hex'] = decoded.hex()
                else:
                    f_hashes.setdefault(item['sha256'], []).append(entry.logical_path)
                index.setdefault(entry.logical_path, []).append(item)
    print('Indexed sample video pieces decoded', flush=True)
    for path in sorted(sample.rglob('*')):
        if not path.is_file() or '!AA_' not in path.name:
            continue
        stem, digest = path.name.rsplit('!AA_', 1)
        candidates = [(k, v) for k,v in rows.items() if Path(k[0]).name == stem and k[1] == digest]
        if len(candidates) > 1:
            raise w.ExportError(f'Ambiguous manifest identity for sample: {path}')
        data = path.read_bytes()
        item = {'file': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        if candidates:
            key, row = candidates[0]
            logical = key[0]
            item['requested'] = key in unresolved
            item['manifest_size_matched'] = len(data) == row['expected_cdn_size_bytes']
        else:
            matches = [logical for logical, entries in index.items() if Path(logical).name == stem
                and any(e.get('header_hash') == digest for e in entries)]
            logical = matches[0] if len(matches) == 1 else None
            row = {'expected_cdn_size_bytes': len(data), 'expected_hash_base64': digest}
            item['requested'] = False
            item['manifest_size_matched'] = None
        item['logical_path'] = logical
        try:
            item['validation'] = validate_cdn_payload(data, row, oodle)
            pos = 8
            chunks = []
            for name in 'HBF':
                kind, decoded_len, packed = struct.unpack_from('<BII', data, pos)
                pos += 9
                raw = data[pos:pos+packed]
                pos += packed
                decoded = raw if kind == 0 else _unpack_framed_payload(raw, decoded_len, oodle)
                chunks.append({'kind': name, 'encoding': kind, 'packed': packed, 'decoded': decoded_len,
                    'sha256': hashlib.sha256(decoded).hexdigest(),
                    **({'header_hex': decoded.hex()} if name == 'H' else {})})
            item['chunks'] = chunks
            item['sample_toc_entries'] = index.get(logical, [])
            item['f_identical_indexed_paths'] = f_hashes.get(chunks[2]['sha256'], [])
            item['status'] = 'validated'
        except (w.ExportError, ValueError) as exc:
            item['status'] = 'failed-validation'
            item['error'] = str(exc)
        report['assets'].append(item)
    report['summary'] = {'sample_files': len(report['files']),
        'sample_files_identical_to_target': sum(x['identical_to_target'] for x in report['files']),
        'sample_assets': len(report['assets']),
        'statuses': dict(Counter(x['status'] for x in report['assets'])),
        'requested_objects': len(requested),
        'requested_samples_validated': sum(x['requested'] and x['status']=='validated' for x in report['assets']),
        'requested_samples_with_identical_indexed_f': sum(x['requested'] and bool(x.get('f_identical_indexed_paths')) for x in report['assets'])}
    output = args.output
    with output.open('x', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report['summary']), flush=True)

if __name__ == '__main__':
    main()
