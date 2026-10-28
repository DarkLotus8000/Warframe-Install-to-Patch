"""Read-only, bounded forensic scan; writes evidence only outside source roots."""
from pathlib import Path
import base64
import hashlib
import json
import mmap
import re
import argparse
from collections import Counter
from datetime import datetime, timezone
import warframe_install_to_patch as w
import inspect_missing_source as prior

def gaps(size, intervals):
    cursor = 0
    for start, end in sorted(intervals):
        start, end = min(size, max(0, start)), min(size, end)
        if start > cursor:
            yield cursor, start
        cursor = max(cursor, end)
    if cursor < size:
        yield cursor, size

def select_rows(residual, missing):
    objects = residual['objects']
    if not isinstance(objects, list) or len(objects) > 512:
        raise w.ExportError('Residual probe accepts at most 512 requested objects')
    rows = {(r['namespace'], r['logical_path']): r for r in missing['missing_objects']}
    if len(rows) != len(missing['missing_objects']):
        raise w.ExportError('Duplicate missing-source identity')
    selected = []
    seen = set()
    for obj in objects:
        key = (obj['namespace'], obj['logical_path'])
        if key in seen or key not in rows:
            raise w.ExportError('Duplicate or unmatched residual identity')
        seen.add(key)
        row = rows[key]
        if row['expected_hash_base64'] != obj['manifest_hash'] or row['required_pieces'] != obj['required_pieces']:
            raise w.ExportError('Residual and missing-source reports disagree')
        w._validate_manifest_namespace(key[0])
        w._validate_logical_path(key[1])
        encoded = obj['manifest_hash']
        digest = base64.b64decode(encoded.replace('-', '/') + '==', validate=True)
        if len(digest) != 16 or w.b64m_encode(digest) != encoded:
            raise w.ExportError('Invalid manifest digest')
        selected.append(row)
    return selected

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('residual_report', type=Path)
    parser.add_argument('missing_report', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    residual_path, missing_path, output = args.residual_report, args.missing_report, args.output
    residual = json.loads(residual_path.read_text())
    missing = json.loads(missing_path.read_text())
    roots = [Path(residual[k]).resolve() for k in ('target', 'steam_base')]
    prior._outside_sources(output, tuple(roots))
    selected = select_rows(residual, missing)
    digests = {}
    for row in selected:
        digest = base64.b64decode(row['expected_hash_base64'].replace('-', '/') + '==', validate=True)
        digests.setdefault(digest, []).append(row['logical_path'])
    oodle = w.Oodle(Path(w.__file__).parent)
    oodle._load()
    report = {'generated_utc': datetime.now(timezone.utc).isoformat(),
        'sources': [str(p) for p in roots],
        'inputs': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (residual_path, missing_path)},
        'objects': [], 'files': [], 'hits': [],
        'limitations': [
            'Raw digest hits are candidate evidence, not complete authenticated objects.',
            'Scans every H cache byte for raw manifest digests, and every H/B/F gap outside live TOC ranges for raw digests and framed blocks.',
            'Framed gap blocks are decoded only when sizes are positive and at most 16 MiB and compression is raw or Oodle.',
            'Unframed compressed data with lost length metadata cannot be exhaustively decoded.',
            'Bink signatures alone cannot identify a video or establish its historical F bytes.',
            'Does not reconstruct or import objects; no CDN or later installation is accessed.']}
    block_re = re.compile(rb'\x80[\s\S]{6}[\x01\x11\x21\x31\x41\x51\x61\x71\x81\x91\xa1\xb1\xc1\xd1\xe1\xf1]')
    wanted = {(r['namespace'], r['logical_path']) for r in selected}
    for label, root in zip(('target', 'steam_base'), roots):
        cache = w.find_cache_windows_dir(root)
        index = prior._scan_residual_entries(cache, wanted)
        for row in selected:
            report['objects'].append({'source': label, 'logical_path': row['logical_path'],
                **prior._probe_residual_source(index, row, oodle)})
        for path in sorted(cache.glob('*.cache')):
            if path.name[0] not in 'HBF':
                continue
            if path.is_symlink():
                raise ValueError('Symlink source rejected')
            before = path.stat()
            toc = path.with_suffix('.toc')
            intervals = []
            if toc.exists():
                intervals = [(e.offset, e.offset + e.compressed_len) for e in
                    w.iter_toc_entries(toc, path.name[0], path.name[2:-6])]
            if any(a < 0 or b > before.st_size for a,b in intervals):
                raise ValueError(f'Live TOC range outside cache: {path}')
            regions = list(gaps(before.st_size, intervals))
            entry = {'source': label, 'file': path.name, 'bytes': before.st_size,
                'gap_bytes': sum(b-a for a,b in regions), 'gap_count': len(regions),
                'decoded_blocks': 0, 'decode_errors': 0, 'oversized_frames': 0,
                'bink_signature_count': 0, 'bink_signature_offsets_sample': []}
            entry['compressed_h_entries_checked'] = 0
            if path.name.startswith('H.') and toc.exists():
                for deleted in (False, True):
                    for h in w.iter_toc_entries(toc, 'H', path.name[2:-6], deleted_only=deleted):
                        if h.compressed_len == h.length:
                            continue
                        try:
                            decoded = w.decompress_cache_entry(h, oodle)
                        except (w.ExportError, OSError) as exc:
                            if not deleted:
                                raise
                            continue
                        entry['compressed_h_entries_checked'] += 1
                        if decoded[:16] in digests:
                            report['hits'].append({'source': label, 'file': path.name,
                                'offset': h.offset, 'kind': 'decoded-indexed-h',
                                'toc_path': h.logical_path, 'deleted': deleted,
                                'objects': digests[decoded[:16]]})
            print(label, path.name, 'gap bytes', entry['gap_bytes'], flush=True)
            with path.open('rb') as handle:
                if before.st_size:
                    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
                        search_regions = [(0, len(data))] if path.name.startswith('H.') else regions
                        for a,b in search_regions:
                            for digest, names in digests.items():
                                pos = data.find(digest, a, b)
                                while pos >= 0:
                                    report['hits'].append({'source': label, 'file': path.name,
                                        'offset': pos, 'kind': 'raw-digest', 'objects': names,
                                        'outside_live_ranges': any(x <= pos and pos+16 <= y for x,y in regions)})
                                    pos = data.find(digest, pos+1, b)
                        for a,b in regions:
                            for signature in (b'KB2', b'BIK'):
                                pos = data.find(signature, a, b)
                                while pos >= 0:
                                    entry['bink_signature_count'] += 1
                                    if len(entry['bink_signature_offsets_sample']) < 20:
                                        entry['bink_signature_offsets_sample'].append(pos)
                                    pos = data.find(signature, pos+1, b)
                            for match in block_re.finditer(data, a, b):
                                pos = match.start()
                                clen, dlen = w._warframe_block_lens(data, pos)
                                if not clen or not dlen or pos+8+clen > b:
                                    continue
                                if max(clen, dlen) > 16*1024*1024:
                                    entry['oversized_frames'] += 1
                                    continue
                                if clen != dlen and data[pos+8] != 0x8c:
                                    continue
                                raw = data[pos+8:pos+8+clen]
                                try:
                                    decoded = raw if clen == dlen else oodle.decompress(raw, dlen)
                                except w.ExportError:
                                    entry['decode_errors'] += 1
                                    continue
                                entry['decoded_blocks'] += 1
                                for digest, names in digests.items():
                                    offset = decoded.find(digest)
                                    if offset >= 0:
                                        report['hits'].append({'source': label, 'file': path.name,
                                            'offset': pos, 'decoded_offset': offset,
                                            'kind': 'decoded-gap-block-digest', 'objects': names})
            after = path.stat()
            entry['size_and_mtime_unchanged'] = (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
            if not entry['size_and_mtime_unchanged']:
                raise RuntimeError('Source changed during scan')
            report['files'].append(entry)
    report['summary'] = {'objects_examined': len(selected), 'files_examined': len(report['files']),
        'cache_bytes': sum(f['bytes'] for f in report['files']),
        'gap_bytes': sum(f['gap_bytes'] for f in report['files']),
        'decoded_gap_blocks': sum(f['decoded_blocks'] for f in report['files']),
        'digest_hits': len(report['hits']),
        'toc_statuses': dict(Counter(o['status'] for o in report['objects']))}
    with output.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps(report['summary']), flush=True)

if __name__ == '__main__':
    main()
