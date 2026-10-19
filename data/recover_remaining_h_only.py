#!/usr/bin/env python3
"""Opt-in, fail-closed recovery of two U44 H-only resources.

Offline mode ranks installed H CommonHeader *peer* types. This is only a
heuristic and never asserts the missing object's type. --probe-cdn issues
bounded HEAD requests to canonical Warframe CDN URLs. --recover uses the
resulting HEAD report to GET and validate SHCC CRC32C, H bytes/hash/type,
empty B/F slots, and size. Original installs and patch outputs are read-only.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
from urllib.error import HTTPError, URLError

import inspect_unresolved_content as triage
import recover_missing_cdn as video
import warframe_install_to_patch as w

VERSION = w.VERSION
REPORT_NAME = 'cdn-h-only-recovery-v0.1.json'
MAX_ASSETS = 2
MAX_TYPES_PER_ASSET = 12
MAX_ITEM_BYTES = 8192
# These entries are *manifest hash-locked*, not loose paths or inferred types.
KNOWN_TARGETS = {
    ('0', '/Lotus/Fx/PowersuitAbilities/Decree/SonarWeakSpotCapsuleMat',
     'SZJetTq813ezgKwg2nTXlA', 687),
    ('0', '/Lotus/Objects/Natural/Skybox/NinetyNine/HubParallax/Building01a',
     '35O5zuNZnbDNtIyw070Bqg', 955),
}

def target_rows(source: dict) -> list[dict]:
    if source.get('version') != w.VERSION:
        raise w.ExportError('Expected v0.1 unresolved-content report')
    summary = source.get('summary', {})
    if summary.get('unresolved_in_both') != len(source.get('objects', [])):
        raise w.ExportError('Unresolved-content report count mismatch')
    found = []
    seen = set()
    for row in source['objects']:
        if row.get('category') != 'non-video-resource':
            continue
        key = (row.get('namespace'), row.get('logical_path'),
               row.get('expected_hash_base64'), row.get('expected_cdn_size_bytes'))
        if key not in KNOWN_TARGETS or key in seen:
            raise w.ExportError('Unexpected or duplicate H-only resource in source report')
        seen.add(key)
        w._validate_logical_path(row['logical_path'])
        if (row.get('manifest_flags') != '0x20000000' or
                row.get('manifest_section') != 'stripped' or row.get('required_pieces') != []):
            raise w.ExportError('H-only manifest flags/section differ from U44 report')
        found.append(row)
    if set((r['namespace'], r['logical_path'], r['expected_hash_base64'],
            r['expected_cdn_size_bytes']) for r in found) != KNOWN_TARGETS:
        raise w.ExportError('Source report does not contain both expected U44 H-only resources')
    return found

def similarity(target: str, peer: str) -> int:
    """Ranks paths, never labels a type as correct by itself."""
    a = target.strip('/').split('/')
    b = peer.strip('/').split('/')
    if peer == target or not peer.startswith('/Lotus/'):
        return -1
    same = 0
    for x, y in zip(a[:-1], b[:-1]):
        if x != y:
            break
        same += 1
    if same < 2:
        return -1
    stem_a, stem_b = a[-1], b[-1]
    score = same * 35
    if same == len(a) - 1:
        score += 75
    if stem_a.endswith('Mat') and stem_b.endswith('Mat'):
        score += 75
    elif stem_a.startswith('Building') and stem_b.startswith('Building'):
        score += 105
    elif stem_a.lower()[:5] == stem_b.lower()[:5]:
        score += 30
    if len(b) == len(a):
        score += 7
    return score

def infer_peer_types(target: Path, rows: list[dict], *, max_samples: int = 140,
                     max_types: int = MAX_TYPES_PER_ASSET,
                     cache_index=None, oodle=None) -> list[dict]:
    if not 2 <= max_samples <= 500 or not 1 <= max_types <= MAX_TYPES_PER_ASSET:
        raise w.ExportError('Invalid sampling budget')
    index = cache_index
    if index is None:
        index = w.scan_cache(w.find_cache_windows_dir(target.resolve()), 'H')
    oodle = oodle or w.Oodle(Path(w.__file__).resolve().parent)
    peers = []
    for (ns, path), kinds in index.items():
        if ns != '0' or not path.startswith('/Lotus/'):
            continue
        if kinds.get('H'):
            peers.append((path, kinds['H'][0]))
    results = []
    for row in rows:
        ranked = sorted(((similarity(row['logical_path'], path), path, entry)
                         for path, entry in peers), key=lambda x: (-x[0], x[1]))
        counts: Counter[int] = Counter()
        weighted: Counter[int] = Counter()
        examples = {}
        successes = 0
        for score, name, entry in ranked:
            if score < 0 or successes >= max_samples:
                break
            try:
                raw = w.decompress_cache_entry(entry, oodle)
                digest, type_id = w.parse_common_header(raw)
                if digest != raw[:16] or not 0 < type_id <= 0xFFFF:
                    continue
            except (w.ExportError, ValueError, OSError, struct.error):
                continue
            counts[type_id] += 1
            weighted[type_id] += score
            examples.setdefault(type_id, name)
            successes += 1
        ordered = sorted(counts, key=lambda t: (-weighted[t], -counts[t], t))[:max_types]
        results.append({
            'namespace': row['namespace'], 'logical_path': row['logical_path'],
            'expected_hash_base64': row['expected_hash_base64'],
            'expected_cdn_size_bytes': row['expected_cdn_size_bytes'],
            'manifest_flags': row['manifest_flags'],
            'peer_sample_count': successes,
            'peer_candidates': [{'type_hex': f'{t:X}', 'peer_count': counts[t],
                                 'weighted_score': weighted[t], 'example_peer': examples[t]}
                                for t in ordered],
            'cdn_checks': [],
        })
    return results

def build_probe_report(report: dict, samples: list[dict]) -> dict:
    rows = target_rows(report)
    if {x['logical_path'] for x in samples} != {x['logical_path'] for x in rows}:
        raise w.ExportError('Missing peer result')
    return {'version': VERSION, 'kind': 'h-only-cdn-type-probe',
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'note': 'Types are peer suggestions, not proven; HEAD only checks current HTTP status and length.',
            'objects': samples}

def run_probes(probe: dict, *, timeout: float = 15, head_func=None) -> None:
    if head_func is None:
        head_func = triage._head
    if not 1 <= timeout <= 120:
        raise w.ExportError('Invalid HEAD timeout')
    for item in probe['objects']:
        item['cdn_checks'] = []
        for candidate in item['peer_candidates']:
            type_id = int(candidate['type_hex'], 16)
            url = triage.make_cdn_url(item, type_id)
            response = head_func(url, timeout=timeout)
            status = response.get('http_status')
            length = response.get('content_length')
            matched = status == 200 and length == item['expected_cdn_size_bytes']
            check = {'type_hex': candidate['type_hex'], 'url': url,
                     'http_status': status, 'content_length': length,
                     'size_matched': matched}
            item['cdn_checks'].append(check)
            print(f"[HEAD] {item['logical_path']} | type 0x{type_id:X} | HTTP {status} | size {'matched' if matched else 'unconfirmed'}")

def validate_h_only_payload(raw: bytes, item: dict, expected_type: int, oodle) -> dict:
    if not isinstance(raw, bytes) or len(raw) != item['expected_cdn_size_bytes']:
        raise w.ExportError('H-only CDN byte length mismatch')
    if not raw.startswith(w.SHCC_PREAMBLE) or len(raw) < 8 + 3 * 9 + 5:
        raise w.ExportError('Expected a direct SHCC CDN container')
    if raw[-5] != 0x52 or int.from_bytes(raw[-4:], 'little') != w.crc32c(raw[:-4]):
        raise w.ExportError('SHCC CRC32C footer mismatch')
    offset = 8
    chunks = []
    for kind in 'HBF':
        if offset + 9 > len(raw) - 5:
            raise w.ExportError('Missing SHCC chunk header')
        codec, decoded, packed = struct.unpack_from('<BII', raw, offset)
        offset += 9
        if offset + packed > len(raw) - 5:
            raise w.ExportError('Truncated SHCC chunk payload')
        data = raw[offset:offset+packed]
        offset += packed
        if codec == 0 and decoded != packed:
            raise w.ExportError('Stored SHCC chunk has invalid lengths')
        if codec == 2 and not w._validate_oodle_chunk_payload(data, decoded):
            raise w.ExportError('Invalid compressed SHCC chunk')
        if codec not in (0, 2):
            raise w.ExportError('Unrecognized SHCC chunk encoding')
        chunks.append((codec, decoded, packed, data))
    if offset != len(raw) - 5:
        raise w.ExportError('Extra SHCC data')
    h, b, f = chunks
    if not 16 <= h[1] <= (1 << 20) or not h[2]:
        raise w.ExportError('Invalid H CommonHeader size')
    if any(x[1] or x[2] for x in (b, f)):
        raise w.ExportError('H-only manifest must have empty B and F slots')
    header = h[3] if h[0] == 0 else video._unpack_framed_payload(h[3], h[1], oodle)
    digest, type_id = w.parse_common_header(header)
    expected_digest = base64.b64decode(item['expected_hash_base64'].replace('-', '/') + '==', validate=True)
    if digest != expected_digest or type_id != expected_type:
        raise w.ExportError('Downloaded H hash/type differs from U44 manifest and CDN filename')
    return {'validation': 'shcc-crc32c-and-h-commonheader-hash-type-matched',
            'sha256': hashlib.sha256(raw).hexdigest(), 'actual_bytes': len(raw),
            'h_bytes': h[1], 'cdn_type_hex': f'{type_id:X}'}

def verified_probe_candidates(original: dict, probe: dict) -> list[tuple[dict, int, str]]:
    rows = target_rows(original)
    if probe.get('version') != VERSION or probe.get('kind') != 'h-only-cdn-type-probe':
        raise w.ExportError('Expected H-only HEAD probe report')
    listed = probe.get('objects')
    if not isinstance(listed, list) or len(listed) != len(rows):
        raise w.ExportError('Incorrect H-only probe object count')
    by_path = {r['logical_path']: r for r in rows}
    eligible = []
    for row in listed:
        original_row = by_path.pop(row.get('logical_path'), None)
        if original_row is None:
            raise w.ExportError('Unexpected or repeated H-only report asset')
        for k in ('namespace', 'expected_hash_base64', 'expected_cdn_size_bytes', 'manifest_flags'):
            if row.get(k) != original_row.get(k):
                raise w.ExportError('H-only probe data does not match original manifest')
        choices = []
        peer_types = {c.get('type_hex') for c in row.get('peer_candidates', [])}
        for check in row.get('cdn_checks', []):
            t = check.get('type_hex')
            if t not in peer_types or not isinstance(t, str) or not re.fullmatch(r'[A-Fa-f0-9]{1,4}', t):
                raise w.ExportError('Probe type not supported by peer evidence')
            type_id = int(t, 16)
            expected_url = triage.make_cdn_url(row, type_id)
            if check.get('url') != expected_url:
                raise w.ExportError('Probe URL does not match manifest-derived URL')
            if (check.get('size_matched') is True and check.get('http_status') == 200 and
                    check.get('content_length') == row['expected_cdn_size_bytes']):
                choices.append((type_id, expected_url))
        if len(choices) == 1:
            eligible.append((row, *choices[0]))
        elif len(choices) > 1:
            raise w.ExportError('Ambiguous HEAD type matches; do not download blindly')
        else:
            print('[Unresolved HEAD] ' + row['logical_path'] + ' | no matching type candidate')
    if by_path:
        raise w.ExportError('Missing H-only probe rows')
    return eligible

def recover(source: dict, probe: dict, output: Path, *, timeout: float = 20,
            get_func=None, oodle=None) -> dict:
    eligible = verified_probe_candidates(source, probe)
    if get_func is None:
        get_func = video._download
    if not 1 <= timeout <= 120:
        raise w.ExportError('Invalid GET timeout')
    if not eligible:
        raise w.ExportError('No unambiguous length-matching CDN HEAD results; nothing to download')
    if output.exists() or output.is_symlink():
        raise w.ExportError('Recovery output must be a new, non-existing directory')
    if any(p.name.lower() in {'cache.windows', 'openwf', 'content'} for p in (output, *output.parents)):
        raise w.ExportError('Recovery output cannot be inside a cache or patch content tree')
    output.mkdir(parents=True, exist_ok=False)
    oodle = oodle or w.Oodle(Path(w.__file__).resolve().parent)
    statuses = []
    for row, type_id, url in eligible:
        result = {key: row[key] for key in ('namespace', 'logical_path', 'expected_hash_base64',
                                           'expected_cdn_size_bytes', 'manifest_flags')}
        result['url'] = url
        result['cdn_type_hex'] = f'{type_id:X}'
        try:
            raw = get_func(url, row['expected_cdn_size_bytes'], timeout)
            details = validate_h_only_payload(raw, row, type_id, oodle)
            path = w._safe_output_path(output / 'OpenWF' / 'Content', row['namespace'],
                                       row['logical_path'], type_id, row['expected_hash_base64'])
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as f:
                f.write(raw)
            result.update(details)
            result['status'] = 'recovered-validated'
            result['relative_path'] = path.relative_to(output).as_posix()
            print(f"[Recovered] {row['logical_path']} | {len(raw):,} B | SHCC/H validated")
        except (w.ExportError, OSError, ValueError, HTTPError, URLError, TimeoutError) as exc:
            result['status'] = 'failed-not-saved'
            result['reason'] = str(exc)[:350]
            print(f"[Failed] {row['logical_path']} | {exc}")
        statuses.append(result)
    doc = {'version': VERSION, 'kind': 'h-only-cdn-recovery',
           'created_utc': datetime.now(timezone.utc).isoformat(),
           'summary': {'selected': len(statuses),
                       'recovered_validated': sum(x['status'] == 'recovered-validated' for x in statuses),
                       'failed': sum(x['status'] != 'recovered-validated' for x in statuses)},
           'objects': statuses,
           'note': 'SHA-256 is newly recorded, not an independently published historical full-CDN digest.'}
    with (output / REPORT_NAME).open('x', encoding='utf-8') as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write('\n')
    return doc

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source_report', type=Path, help='unresolved-cdn-all-v0.1.json')
    p.add_argument('--target', type=Path, help='target Warframe installation (only for offline peer inference)')
    p.add_argument('--probe-cdn', action='store_true', help='opt in to bounded CDN HEAD checks')
    p.add_argument('--probe-report', type=Path, help='v0.1 HEAD report required with --recover')
    p.add_argument('--recover', action='store_true', help='opt in to validated CDN GET requests')
    p.add_argument('-o', '--output', type=Path, help='probe JSON filename or NEW recovery folder')
    p.add_argument('--timeout', type=float, default=20)
    args = p.parse_args(argv)
    try:
        if args.probe_cdn and args.recover:
            raise w.ExportError('Use separate HEAD probe and GET recovery commands')
        if args.target is None:
            raise w.ExportError('--target is required to protect the original installation')
        target_root = args.target.resolve(strict=True)
        if not target_root.is_dir():
            raise w.ExportError('--target must be an installation directory')
        target_cache = w.find_cache_windows_dir(target_root).resolve()
        if args.output is None or not 1 <= args.timeout <= 120:
            raise w.ExportError('Provide -o and a timeout from 1..120 seconds')
        source_path = args.source_report.resolve(strict=True)
        source = json.loads(source_path.read_text(encoding='utf-8'))
        targets = target_rows(source)
        if args.recover:
            if args.probe_report is None:
                raise w.ExportError('--recover requires --probe-report')
            probe_path = args.probe_report.resolve(strict=True)
            probe = json.loads(probe_path.read_text(encoding='utf-8'))
            out = args.output.resolve()
            if (out == source_path or out == probe_path or out == target_root or
                out.is_relative_to(target_root) or out == target_cache or out.is_relative_to(target_cache)):
                raise w.ExportError('Recovery destination overlaps the original installation or input report')
            result = recover(source, probe, out, timeout=args.timeout)
            print(f"[Summary] {result['summary']['recovered_validated']}/{result['summary']['selected']} validated; {result['summary']['failed']} failed")
            print('[Report] ' + str(out / REPORT_NAME))
            return 0 if result['summary']['failed'] == 0 else 2
        samples = infer_peer_types(target_root, targets)
        report = build_probe_report(source, samples)
        for row in report['objects']:
            print(f"[Type peers] {row['logical_path']} | {row['peer_sample_count']} sampled | " +
                  ', '.join(f"0x{x['type_hex']} ({x['peer_count']})" for x in row['peer_candidates']))
        if not args.probe_cdn:
            print('[Dry run] No network requests and no output written. Add --probe-cdn for HEAD-only report.')
            return 0
        outfile = args.output.resolve()
        if (outfile.exists() or outfile.is_symlink() or outfile == target_root or
                outfile.is_relative_to(target_root) or outfile == target_cache or
                outfile.is_relative_to(target_cache) or outfile == source_path):
            raise w.ExportError('Probe report already exists or would modify original installation/input')
        run_probes(report, timeout=args.timeout)
        outfile.parent.mkdir(parents=True, exist_ok=True)
        with outfile.open('x', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            f.write('\n')
        print('[Report] ' + str(outfile))
        return 0
    except (w.ExportError, OSError, ValueError, KeyError, TypeError) as exc:
        print('[Error] ' + str(exc), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
