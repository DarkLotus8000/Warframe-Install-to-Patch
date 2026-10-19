#!/usr/bin/env python3
"""Read-only triage of unresolved manifest objects; optional historical CDN HEAD checks.

Takes the missing-source and base-inheritance JSONs.
No installation rescan is necessary in offline mode. A network check is never
initiated unless --probe-cdn is explicitly supplied. HTTP HEAD is evidence
of CURRENT HTTP availability only, not historical existence or usability.
"""
from __future__ import annotations

from common import StrictArgumentParser

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPRedirectHandler

import warframe_install_to_patch as w

HOST = 'https://content.warframe.com'
HASH_RE = re.compile(r'[A-Za-z0-9+\-]{22}\Z')

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def _validate_report_inputs(missing: dict, inherited: dict) -> list[dict]:
    if missing.get('report_version') != w.VERSION or inherited.get('version') != w.VERSION:
        raise w.ExportError('Expected missing-source and base-inheritance reports')
    missing_list = missing.get('missing_objects')
    inherited_list = inherited.get('objects')
    if not isinstance(missing_list, list) or not isinstance(inherited_list, list):
        raise w.ExportError('Missing or invalid object lists in input reports')
    if (missing.get('summary', {}).get('source_missing') != len(missing_list)
            or inherited.get('summary', {}).get('source_missing_in_target') != len(inherited_list)):
        raise w.ExportError('Input report count mismatch')
    if Path(missing.get('base_cache', '')).resolve() != Path(inherited.get('base_cache', '')).resolve():
        raise w.ExportError('Reports were generated from different Steam bases')
    by_key = {}
    for row in inherited_list:
        key = (row['namespace'], row['logical_path'])
        if key in by_key:
            raise w.ExportError('Duplicate asset in base report')
        by_key[key] = row
    if len(missing_list) != len(by_key):
        raise w.ExportError('Different asset counts between reports')
    unresolved = []
    for row in missing_list:
        key = (row['namespace'], row['logical_path'])
        base = by_key.pop(key, None)
        if base is None:
            raise w.ExportError('Asset missing from base report: ' + '/'.join(key))
        if base['status'] == 'verified-in-base':
            continue
        if base['status'] != 'not-fully-in-base':
            raise w.ExportError('Cannot triage assets with base verification errors')
        w._validate_logical_path(row['logical_path'])
        digest = row['expected_hash_base64']
        if not isinstance(digest, str) or not HASH_RE.fullmatch(digest):
            raise w.ExportError('Invalid manifest digest: ' + row['logical_path'])
        flags = int(row['manifest_hbf_flags_hex'], 16)
        kinds = list(w._required_piece_kinds(flags))
        if kinds != row['required_pieces']:
            raise w.ExportError('Required H/B/F mismatch: ' + row['logical_path'])
        size = row['expected_cdn_size_bytes']
        if not isinstance(size, int) or not 0 < size < (1 << 29):
            raise w.ExportError('Invalid manifest CDN size')
        logical = row['logical_path']
        if logical.lower().endswith('.bk2'):
            category = 'video-preview' if logical.startswith('/Lotus/Interface/AbilityVideos/') else 'other-video'
            interpretation = 'Video content; likely UI/demo media. Runtime optionality NOT verified.'
        else:
            category = 'non-video-resource'
            interpretation = 'Game resource with unknown runtime dependencies; cannot classify as optional.'
        unresolved.append({
            'namespace': row['namespace'], 'logical_path': logical,
            'expected_hash_base64': digest, 'expected_cdn_size_bytes': size,
            'manifest_section': row['manifest_section'], 'manifest_flags': row['manifest_hbf_flags_hex'],
            'required_pieces': kinds, 'source_reason': row['reason'],
            'category': category, 'interpretation': interpretation,
            'cdn_probe': {'status': 'not-requested'},
        })
    if by_key:
        raise w.ExportError('Additional objects in base report')
    return unresolved

def summarize(unresolved: list[dict], missing: dict, inherited: dict) -> dict:
    by_cat = Counter(x['category'] for x in unresolved)
    return {
        'version': w.VERSION,
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'cdn_probe_scope': 'No remote requests unless --probe-cdn; HEAD cannot validate CDN payload bytes or historical availability.',
        'summary': {
            'source_missing_in_target': len(missing['missing_objects']),
            'verified_in_base': inherited['summary']['verified_in_base'],
            'unresolved_in_both': len(unresolved),
            'unresolved_by_category': dict(sorted(by_cat.items())),
            'unresolved_by_required_pieces': dict(sorted(Counter('+'.join(x['required_pieces']) or 'H-only' for x in unresolved).items())),
            'unresolved_expected_cdn_bytes': sum(x['expected_cdn_size_bytes'] for x in unresolved),
            'cdn_head_requests': 0,
        },
        'objects': unresolved,
    }

def infer_video_type(target_root: Path, *, max_samples: int = 40) -> dict:
    """Infer a tentative CDN type from installed H entries for OTHER .bk2 files.

    For the report's missing entries this is a peer heuristic, not an
    independent proof of their individual type ID. No guess from extension
    alone is made if local evidence conflicts or is unavailable.
    """
    target_cache = w.find_cache_windows_dir(target_root.resolve())
    index = w.scan_cache(target_cache, 'H')
    entries = []
    for (namespace, logical), kinds in index.items():
        if namespace == '0' and logical.lower().endswith('.bk2'):
            entries.extend(kinds['H'])
    # prefer sibling UI/AbilityVideos entries; don't sample user-missing names
    entries.sort(key=lambda e: (not e.logical_path.startswith('/Lotus/Interface/AbilityVideos/'), e.logical_path, e.package))
    oodle = w.Oodle(Path(w.__file__).resolve().parent)
    guesses = Counter()
    samples = []
    for entry in entries[:max_samples]:
        try:
            payload = w.decompress_cache_entry(entry, oodle)
            digest, type_id = w.parse_common_header(payload)
            if type_id is None or not (0 < type_id <= 0xFFFF):
                continue
            guesses[type_id] += 1
            samples.append({'path': entry.logical_path, 'type_hex': f'{type_id:X}'})
        except (w.ExportError, OSError, ValueError):
            continue
    result = {'candidate_types': {f'{key:X}': count for key, count in sorted(guesses.items())},
        'samples': samples[:8], 'sampled_headers': len(samples), 'type_hex': None,
        'type_confidence': 'not-established'}
    if len(guesses) == 1 and sum(guesses.values()) >= 2:
        result['type_hex'] = f'{next(iter(guesses)):X}'
        result['type_confidence'] = 'same-extension-cache-peers-not-per-file-proof'
    return result

def make_cdn_url(item: dict, type_id: int) -> str:
    if not 0 < type_id <= 0xFFFF:
        raise ValueError('Invalid CDN type')
    w._validate_logical_path(item['logical_path'])
    if not HASH_RE.fullmatch(item['expected_hash_base64']):
        raise ValueError('Invalid CDN hash')
    # Canonical Warframe endpoint: /0{namespace-suffix}/...!TYPE_hash.
    rel = f"/{item['namespace']}{item['logical_path']}!{type_id:X}_{item['expected_hash_base64']}"
    return HOST + quote(rel, safe='/!_-.+').replace('%2D', '-')

def _head(url: str, *, timeout: float) -> dict:
    # Do not follow redirects to other hosts, including user/proxy injected URLs.
    req = Request(url, headers={'User-Agent': 'Warframe-Install-to-Patch/0.1 (read-only CDN HEAD)'}, method='HEAD')
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as reply:
            status = reply.status
            raw_size = reply.headers.get('Content-Length')
            try:
                size = int(raw_size) if raw_size is not None else None
            except (ValueError, TypeError):
                size = None
            return {'http_status': status, 'content_length': size}
    except HTTPError as exc:
        return {'http_status': exc.code, 'content_length': None}
    except (URLError, TimeoutError, OSError) as exc:
        return {'http_status': None, 'error': str(exc)[:256]}

def probe_cdn(report: dict, *, video_type: int | None, target: Path | None,
        limit: int, timeout: float, head_func=_head) -> None:
    if video_type is None:
        if target is None:
            raise w.ExportError('--probe-cdn needs --target to infer the video type, or --video-type HEX')
        evidence = infer_video_type(target)
        report['video_type_evidence'] = evidence
        if evidence['type_hex'] is not None:
            video_type = int(evidence['type_hex'], 16)
    else:
        report['video_type_evidence'] = {'type_hex': f'{video_type:X}', 'type_confidence': 'explicit-user-supplied'}
    video_items = [x for x in report['objects'] if x['category'] in ('video-preview', 'other-video')]
    # Representative coverage across entire list, not just first alphabetic names.
    selected = ([video_items[(i * len(video_items)) // min(limit, len(video_items))]
        for i in range(min(limit, len(video_items)))] if video_items else [])
    if video_type is None:
        for item in selected:
            item['cdn_probe'] = {'status': 'not-checked-type-unresolved'}
        print('[CDN] Could not independently infer a .bk2 CDN type. No network requests were sent.')
        return
    for item in selected:
        url = make_cdn_url(item, video_type)
        head_result = head_func(url, timeout=timeout)
        code = head_result.get('http_status')
        size = head_result.get('content_length')
        if code == 200 and size == item['expected_cdn_size_bytes']:
            status = 'http-200-length-matched-unverified-payload'
        elif code == 200:
            status = 'http-200-length-unknown-or-different'
        elif code is not None:
            status = 'http-response-inconclusive'
        else:
            status = 'network-error-inconclusive'
        item['cdn_probe'] = {'status': status, 'url': url,
            'http_status': code, 'content_length': size}
        if head_result.get('error'):
            item['cdn_probe']['error'] = head_result['error']
        report['summary']['cdn_head_requests'] += 1
        print(f"[CDN] {item['logical_path']} | HTTP {code if code is not None else 'error'} | {status}")

def _int_hex(text: str) -> int:
    try:
        n = int(text, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Expected hexadecimal type, e.g. 0x1A') from exc
    if not 0 < n <= 0xFFFF:
        raise argparse.ArgumentTypeError('CDN type must be 1..FFFF (hex)')
    return n

def main(argv: list[str] | None = None) -> int:
    parser = StrictArgumentParser(description=__doc__)
    parser.add_argument('missing_report', type=Path)
    parser.add_argument('base_report', type=Path)
    parser.add_argument('-o', '--output', type=Path, default=Path('unresolved-content-v0.1.json'))
    parser.add_argument('--probe-cdn', action='store_true', help='opt in to HTTP HEAD against historical content.warframe.com paths')
    parser.add_argument('--target', type=Path, help='source installation for tentative .bk2 type inference; read-only')
    parser.add_argument('--video-type', type=_int_hex, help='override CDN type ID for missing .bk2 files; hexadecimal')
    parser.add_argument('--max-probes', type=int, default=12, help='max HEAD requests (default 12; 0 disables)')
    parser.add_argument('--timeout', type=float, default=6, help='timeout per HEAD request in seconds (default 6)')
    args = parser.parse_args(argv)
    try:
        if not 0 <= args.max_probes <= 2048 or not 0.5 <= args.timeout <= 30:
            raise w.ExportError('max-probes must be 0..2048 and timeout 0.5..30')
        source = args.missing_report.resolve()
        base = args.base_report.resolve()
        out = args.output.resolve()
        if source == base or out in (source, base) or out.exists() or out.is_symlink():
            raise w.ExportError('Refusing to overwrite input or existing output report')
        a = json.loads(source.read_text(encoding='utf-8'))
        b = json.loads(base.read_text(encoding='utf-8'))
        output_roots = [Path(a['target_cache']).resolve().parent, Path(a['base_cache']).resolve().parent]
        if args.target is not None:
            target_root = w.find_cache_windows_dir(args.target.resolve())
            if target_root.resolve() != Path(a['target_cache']).resolve():
                raise w.ExportError('Target installation does not match the missing-source report')
        else:
            target_root = None
        if any(out == root or out.is_relative_to(root) for root in output_roots):
            raise w.ExportError('Refusing to write report inside target/base installations')
        unresolved = _validate_report_inputs(a, b)
        result = summarize(unresolved, a, b)
        if args.probe_cdn and args.max_probes:
            probe_cdn(result, video_type=args.video_type, target=target_root,
                limit=args.max_probes, timeout=args.timeout)
        print(f"[Triage] Inherited: {result['summary']['verified_in_base']} | still unresolved: {len(unresolved)}")
        for kind, count in result['summary']['unresolved_by_category'].items():
            print(f'[Group] {kind}: {count}')
        print('[Note] Asset filenames indicate likely usage but do not establish runtime optionality.')
        print('[Note] HEAD cannot verify asset bytes; HTTP 404/405 do not prove historical unavailability.')
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open('x', encoding='utf-8') as file:
            json.dump(result, file, indent=2, ensure_ascii=False)
            file.write('\n')
        print(f'[Report] {out}')
        return 0
    except (OSError, ValueError, TypeError, KeyError, w.ExportError) as exc:
        print(f'[Error] {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
