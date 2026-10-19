#!/usr/bin/env python3
"""Opt-in, bounded recovery of missing CDN videos into an isolated new folder.

Inputs are an unresolved-content HEAD report. The report's URL and type are re-derived
and must agree with the original manifest fields; arbitrary remote URLs are
never used. This utility does not edit Warframe installations or patch outputs.

A recovered object is checked for length, SHCC CRC32C, three chunk boundaries,
required F data, and the manifest CommonHeader hash. SHA-256 is recorded as a
new archival fingerprint; it is NOT compared with an original CDN SHA-256.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener

import inspect_unresolved_content as triage
import warframe_install_to_patch as w

MAX_ITEM_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
RECOVERY_REPORT_FORMAT = w.VERSION

def validate_report(report: dict) -> list[dict]:
    if report.get('version') != w.VERSION:
        raise w.ExportError('Expected an unresolved-content report')
    evidence = report.get('video_type_evidence')
    if not isinstance(evidence, dict) or evidence.get('type_hex') != 'AA':
        raise w.ExportError('The report does not establish the sampled U44 video CDN type AA')
    if evidence.get('type_confidence') != 'same-extension-cache-peers-not-per-file-proof':
        raise w.ExportError('The CDN type is not supported by installed-cache peer evidence')
    if evidence.get('sampled_headers', 0) < 2 or evidence.get('candidate_types') != {'AA': evidence['sampled_headers']}:
        raise w.ExportError('Conflicting or insufficient cache header type evidence')
    rows = report.get('objects')
    if not isinstance(rows, list) or len(rows) != report.get('summary', {}).get('unresolved_in_both'):
        raise w.ExportError('Report object count is inconsistent')
    by_key = set()
    validated = []
    total_bytes = 0
    for item in rows:
        if not isinstance(item, dict):
            raise w.ExportError('Malformed asset record')
        namespace = item.get('namespace')
        logical = item.get('logical_path')
        if namespace != '0' or not isinstance(logical, str):
            raise w.ExportError('Unexpected asset namespace/path')
        w._validate_logical_path(logical)
        key = (namespace, logical)
        if key in by_key:
            raise w.ExportError('Duplicate asset path in report')
        by_key.add(key)
        if item.get('category') not in ('video-preview', 'other-video'):
            continue
        if not logical.lower().endswith('.bk2') or item.get('manifest_flags') != '0xA0000000' or item.get('required_pieces') != ['F']:
            raise w.ExportError('Unexpected video format or manifest flags')
        digest = item.get('expected_hash_base64')
        if not isinstance(digest, str) or not triage.HASH_RE.fullmatch(digest):
            raise w.ExportError('Invalid CommonHeader manifest hash')
        size = item.get('expected_cdn_size_bytes')
        if type(size) is not int or not 40 <= size <= MAX_ITEM_BYTES:
            raise w.ExportError('Unexpected CDN video size')
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise w.ExportError('Total CDN video budget exceeded')
        probe = item.get('cdn_probe')
        expected_url = triage.make_cdn_url(item, 0xAA)
        if not isinstance(probe, dict) or probe.get('status') != 'http-200-length-matched-unverified-payload' or probe.get('http_status') != 200 or probe.get('content_length') != size or probe.get('url') != expected_url:
            raise w.ExportError('Missing matching HEAD evidence for ' + logical)
        validated.append(item)
    if not validated:
        raise w.ExportError('No verified-HEAD CDN video candidates')
    return validated

def _unpack_framed_payload(data: bytes, expected_decoded: int, oodle: w.Oodle) -> bytes:
    out = bytearray()
    pos = 0
    while pos < len(data):
        packed, unpacked = w._warframe_block_lens(data, pos)
        if not packed or not unpacked or pos + 8 + packed > len(data):
            raise w.ExportError('Invalid framed H cache block')
        block = data[pos+8:pos+8+packed]
        pos += 8 + packed
        if packed == unpacked:
            out.extend(block)
        elif block.startswith(b'\x8c'):
            out.extend(oodle.decompress(block, unpacked))
        else:
            raise w.ExportError('Unsupported H cache block encoding')
        if len(out) > expected_decoded:
            raise w.ExportError('Decoded H exceeds declared length')
    if len(out) != expected_decoded:
        raise w.ExportError('Decoded H length mismatch')
    return bytes(out)

def validate_cdn_payload(data: bytes, row: dict, oodle: w.Oodle) -> dict:
    """Validate standard direct SHCC and identity of its H header.

    Not a cryptographic proof of original CDN F bytes: CRC32C is non-cryptographic
    and the manifest hash identifies H, not a whole-CDN SHA-256 digest.
    """
    if len(data) != row['expected_cdn_size_bytes']:
        raise w.ExportError('GET payload does not match manifest CDN size')
    if not data.startswith(w.SHCC_PREAMBLE) or len(data) < 40:
        raise w.ExportError('CDN response is not a standard direct SHCC container')
    if data[-5] != 0x52 or int.from_bytes(data[-4:], 'little') != w.crc32c(data[:-4]):
        raise w.ExportError('SHCC footer CRC32C failed')
    offset = 8
    chunks = []
    for name in ('H', 'B', 'F'):
        if offset + 9 > len(data) - 5:
            raise w.ExportError('Truncated SHCC chunk header')
        kind, decoded, packed = struct.unpack_from('<BII', data, offset)
        offset += 9
        if offset + packed > len(data) - 5:
            raise w.ExportError('Truncated SHCC chunk payload')
        payload = data[offset:offset+packed]
        offset += packed
        if kind == 0 and decoded != packed:
            raise w.ExportError('Stored SHCC chunk size mismatch')
        if kind == 2 and not w._validate_oodle_chunk_payload(payload, decoded):
            raise w.ExportError('Invalid framed SHCC compressed chunk')
        if kind not in (0, 2):
            raise w.ExportError('Unknown SHCC chunk type')
        chunks.append((name, kind, decoded, packed, payload))
    if offset != len(data) - 5:
        raise w.ExportError('Unexpected bytes after third SHCC chunk')
    h, b, f = chunks
    if h[2] < 16 or h[2] > (1 << 20) or h[3] == 0:
        raise w.ExportError('Missing or unreasonable H CommonHeader')
    if b[2] or b[3] or f[2] == 0 or f[3] == 0:
        raise w.ExportError('Video must contain H + F with an empty B slot')
    header = h[4] if h[1] == 0 else _unpack_framed_payload(h[4], h[2], oodle)
    expected_hash = base64.b64decode(row['expected_hash_base64'].replace('-', '/') + '==', validate=True)
    if header[:16] != expected_hash:
        raise w.ExportError('H CommonHeader hash does not match U44 manifest')
    # CDN paths use the sampled type ID 0xAA; verify each retrieved H independently.
    found_hash, type_id = w.parse_common_header(header)
    if found_hash != expected_hash or type_id != 0xAA:
        raise w.ExportError('CDN CommonHeader type/hash mismatch')
    return {'validation': 'shcc-structure-crc32c-and-commonheader-type-hash-matched',
            'sha256': hashlib.sha256(data).hexdigest(),
            'actual_bytes': len(data),
            'h_bytes': h[2], 'f_bytes': f[2]}

def _download(url: str, expected_size: int, timeout: float) -> bytes:
    req = Request(url, headers={'User-Agent': 'Warframe-Install-to-Patch/0.1 (opt-in archival CDN GET)', 'Accept-Encoding': 'identity'}, method='GET')
    opener = build_opener(triage._NoRedirect())
    with opener.open(req, timeout=timeout) as response:
        if response.status != 200:
            raise w.ExportError(f'Unexpected HTTP status {response.status}')
        raw_length = response.headers.get('Content-Length')
        if raw_length is not None:
            try:
                if int(raw_length) != expected_size:
                    raise w.ExportError('HTTP GET content length mismatch')
            except ValueError as exc:
                raise w.ExportError('Malformed HTTP Content-Length') from exc
        if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
            raise w.ExportError('HTTP content encoding changed CDN payload bytes')
        data = bytearray()
        while len(data) < expected_size:
            chunk = response.read(min(128 * 1024, expected_size + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > expected_size:
                raise w.ExportError('HTTP body exceeded manifest size')
        if len(data) != expected_size or response.read(1):
            raise w.ExportError('HTTP body length differs from manifest size')
        return bytes(data)

def run(report: dict, destination: Path, *, limit: int, timeout: float,
        get_func=_download, oodle=None) -> dict:
    eligible = validate_report(report)
    if not 1 <= limit <= len(eligible):
        raise w.ExportError(f'--limit must be 1..{len(eligible)}')
    if destination.exists() or destination.is_symlink():
        raise w.ExportError('Refusing to overwrite existing recovery output directory')
    # Prevent a new output folder being created inside an install/cache/patch tree.
    if any(p.name.lower() in {'cache.windows', 'openwf', 'content'} for p in (destination, *destination.parents)):
        raise w.ExportError('Recovery destination cannot be within Cache.Windows or OpenWF/Content')
    destination.mkdir(parents=True, exist_ok=False)
    oodle = oodle or w.Oodle(Path(w.__file__).resolve().parent)
    outcomes = []
    for row in eligible[:limit]:
        name = row['logical_path']
        url = triage.make_cdn_url(row, 0xAA)
        result = {'namespace': row['namespace'], 'logical_path': name, 'url': url,
                  'expected_cdn_size_bytes': row['expected_cdn_size_bytes']}
        try:
            data = get_func(url, row['expected_cdn_size_bytes'], timeout)
            checks = validate_cdn_payload(data, row, oodle)
            output = w._safe_output_path(destination / 'OpenWF' / 'Content', row['namespace'], name, 0xAA, row['expected_hash_base64'])
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open('xb') as f:
                f.write(data)
            result.update(checks)
            result['status'] = 'recovered-validated'
            result['relative_path'] = output.relative_to(destination).as_posix()
            print(f'[Recovered] {name} | {len(data):,} B | SHCC CRC and H type/hash matched')
        except (OSError, ValueError, HTTPError, URLError, w.ExportError) as exc:
            result['status'] = 'failed-not-saved'
            result['reason'] = str(exc)[:350]
            print(f'[Failed] {name} | {exc}')
        outcomes.append(result)
    result_report = {
        'version': RECOVERY_REPORT_FORMAT,
        'generated_by_version': w.VERSION,
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'source': 'opt-in GET from exact CDN URLs in HEAD report',
        'notice': 'SHA-256 is newly calculated; the U44 manifest identifies the H header, not the SHA-256 of full CDN bytes.',
        'summary': {'selected': len(outcomes),
                    'recovered_validated': sum(x['status'] == 'recovered-validated' for x in outcomes),
                    'failed': sum(x['status'] != 'recovered-validated' for x in outcomes)},
        'objects': outcomes,
    }
    with (destination / 'cdn-recovery-v0.1.json').open('x', encoding='utf-8') as file:
        json.dump(result_report, file, indent=2, ensure_ascii=False)
        file.write('\n')
    return result_report

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cdn_report', type=Path, help='unresolved-cdn-all-v0.1.json')
    parser.add_argument('-o', '--output-dir', type=Path, help='new, nonexistent destination folder outside installations')
    parser.add_argument('--download', action='store_true', help='explicitly opt in to CDN GET requests')
    parser.add_argument('--limit', type=int, default=1, help='number of CDN videos to recover (default: one)')
    parser.add_argument('--timeout', type=float, default=20, help='GET timeout per request, seconds (default 20)')
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.limit <= 101 or not 1 <= args.timeout <= 120:
            raise w.ExportError('Invalid --limit or --timeout')
        report_path = args.cdn_report.resolve(strict=True)
        report = json.loads(report_path.read_text(encoding='utf-8'))
        eligible = validate_report(report)
        if args.limit > len(eligible):
            raise w.ExportError(f'Only {len(eligible)} probed CDN videos are eligible')
        selected = eligible[:args.limit]
        total = sum(x['expected_cdn_size_bytes'] for x in selected)
        print(f'[Plan] {len(selected)} video files | {total:,} B | GET only with --download')
        print('[Note] This requires standard SHCC+CRC32C and a matching individual H CommonHeader hash/type.')
        print('[Note] This does not certify CDN byte identity against an independent historic archive.')
        if not args.download:
            print('[Dry run] No network requests or files written.')
            return 0
        if args.output_dir is None:
            raise w.ExportError('--output-dir is required with --download')
        out = args.output_dir.resolve()
        if out == report_path:
            raise w.ExportError('Unsafe output path')
        result = run(report, out, limit=args.limit, timeout=args.timeout)
        print(f"[Summary] {result['summary']['recovered_validated']}/{result['summary']['selected']} validated; "
              f"{result['summary']['failed']} failed")
        print('[Report] ' + str(out / 'cdn-recovery-v0.1.json'))
        return 0 if not result['summary']['failed'] else 2
    except (OSError, ValueError, KeyError, TypeError, w.ExportError) as exc:
        print(f'[Error] {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
