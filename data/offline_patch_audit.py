#!/usr/bin/env python3
"""Offline read-only target/base/patch manifest audit for Warframe Install-to-Patch.

All available B.Cache families are inventoried. No CDN requests or cache writes.
A reference install is NOT expected to have the same cache TOC layout as a
patched install: the optional --patch verifies exported CDN files. Applied runtime caches
are not expected to have every on-demand CDN object locally installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import warframe_install_to_patch as w

def inspect_piece(entry: w.CacheEntry, size_cache: dict[Path, int], oodle: w.Oodle, deep: bool) -> None:
    """Verify the TOC's referenced byte range; optionally decompress each payload."""
    size = size_cache.get(entry.cache_path)
    if size is None:
        try:
            size = entry.cache_path.stat().st_size
        except OSError as exc:
            raise w.ExportError(f'Cannot stat cache payload {entry.cache_path}: {exc}') from exc
        size_cache[entry.cache_path] = size
    if entry.offset < 0 or entry.compressed_len < 0 or entry.offset + entry.compressed_len > size:
        raise w.ExportError(f'{entry.kind} piece exceeds cache file bounds: {entry.namespace}{entry.logical_path} in {entry.package}')
    if deep:
        w.decompress_cache_entry(entry, oodle)

def validate_selected_pieces(index, asset: w.ManifestAsset, h_entry: w.CacheEntry,
                             sizes: dict[Path, int], oodle: w.Oodle, *, deep: bool) -> None:
    inspect_piece(h_entry, sizes, oodle, False)  # H has already been decoded to match its hash.
    for kind in w._required_piece_kinds(asset.flags):
        entries = [e for e in w._entries_for(index, asset.namespace, asset.logical_path, kind)
                   if e.package == h_entry.package]
        if len(entries) != 1:
            raise w.ExportError(f'Required {kind} piece count is {len(entries)} for '
                                f'{asset.namespace}{asset.logical_path} in {h_entry.package}')
        inspect_piece(entries[0], sizes, oodle, deep)

def parse_shcc_sections(payload: bytes, asset: w.ManifestAsset, oodle: w.Oodle, *, with_trailer: bool) -> None:
    """Validate outer or direct SHCC: CRC checked by caller; H hash and B/F slots checked here."""
    if not payload.startswith(w.SHCC_PREAMBLE):
        raise w.ExportError('Payload is not SHCC')
    end = len(payload) - (5 if with_trailer else 0)
    pos = len(w.SHCC_PREAMBLE)
    chunks = []
    for kind in 'HBF':
        if pos + 9 > end:
            raise w.ExportError(f'Truncated {kind} SHCC chunk')
        codec, plain_len, stored_len = struct.unpack_from('<BII', payload, pos)
        pos += 9
        if stored_len > end - pos:
            raise w.ExportError(f'Oversized {kind} SHCC chunk')
        content = payload[pos:pos + stored_len]
        pos += stored_len
        if codec == 0:
            if plain_len != stored_len:
                raise w.ExportError(f'{kind} stored length mismatch')
        elif codec == 2:
            if not w._validate_oodle_chunk_payload(content, plain_len):
                raise w.ExportError(f'Invalid framed {kind} chunk')
        else:
            raise w.ExportError(f'Unsupported {kind} chunk codec {codec}')
        chunks.append((codec, plain_len, stored_len, content))
    if pos != end:
        raise w.ExportError('SHCC has unexpected trailing content')
    header_codec, h_len, h_stored, h_payload = chunks[0]
    if h_len < 16 or h_stored == 0:
        raise w.ExportError('Missing H chunk')
    if header_codec == 0:
        header = h_payload
    else:
        # Use the same decompressor as the validated recovery tools.
        from recover_missing_cdn import _unpack_framed_payload
        header = _unpack_framed_payload(h_payload, h_len, oodle)
    if header[:16] != asset.manifest_hash:
        raise w.ExportError('SHCC H hash differs from target manifest')
    for index, kind in ((1, 'B'), (2, 'F')):
        required = kind in w._required_piece_kinds(asset.flags)
        present = chunks[index][1] > 0 and chunks[index][2] > 0
        if present != required:
            raise w.ExportError(f'SHCC {kind} presence differs from manifest flags')

class UnsupportedCdnFormatError(w.ExportError):
    """Recognizably unsupported, CRC-valid envelope: retrying is not useful.

    The original bytes remain rejected; never substitute a newer asset.
    """
    retryable = False

def verify_cdn_bytes(data: bytes, asset: w.ManifestAsset, oodle: w.Oodle) -> str:
    """Verify exact manifest size, CRC32C, decoded SHCC hash and H/B/F sections.

    A CDN outer Oodle stream may use a different compressor than our historical
    reconstruction profile. Decode such streams only after independent codec
    identification and full SHCC validation; never infer validity from size.
    """
    if len(data) != asset.cdn_size:
        raise w.ExportError('CDN payload byte count differs from manifest')
    if len(data) < 14 or int.from_bytes(data[-4:], 'little') != w.crc32c(data[:-4]):
        raise w.ExportError('CDN CRC32C mismatch')
    if data.startswith(w.SHCC_PREAMBLE):
        if data[-5] != 0x52:
            raise w.ExportError('Direct SHCC footer marker mismatch')
        parse_shcc_sections(data, asset, oodle, with_trailer=True)
        return 'direct-shcc-crc-h-sections'

    def unknown(detail: str) -> UnsupportedCdnFormatError:
        # The payload already passed exact length and CRC32C. Log only short
        # fingerprints, so we can diagnose a new historical envelope format.
        return UnsupportedCdnFormatError(
            f'Unknown outer CDN format ({detail}; first8={data[:8].hex()}; '
            f'footer-marker=0x{data[-5]:02X}; '
            f'last9={data[-9:].hex()}; '
            f'sha256={hashlib.sha256(data).hexdigest()}; CRC32C valid)')

    if data[-5:-4] != w.CDN_OUTER_FOOTER_MARKER:
        raise unknown('unrecognized footer marker')
    decoded_size = int.from_bytes(data[-9:-5], 'little')
    if decoded_size <= len(w.SHCC_PREAMBLE) or decoded_size > 512 * 1024 * 1024:
        raise w.ExportError('Unsafe outer CDN decoded length')
    prefix = data[:-9]
    if prefix[0] != 0x8C:
        # No fixed 0x8C assumption for alternative valid Oodle codecs.
        try:
            oodle.identify_compressed_stream(prefix)
        except w.ExportError as exc:
            raise unknown('unrecognized Oodle stream') from exc
    plain = oodle.decompress(prefix, decoded_size)
    parse_shcc_sections(plain, asset, oodle, with_trailer=False)
    return 'outer-oodle-crc-h-sections'

def verify_cdn_payload(path: Path, asset: w.ManifestAsset, oodle: w.Oodle) -> str:
    """On-disk wrapper for the single-buffer CDN verifier."""
    return verify_cdn_bytes(path.read_bytes(), asset, oodle)

def audit(*, target: Path, base: Path, patch: Path | None = None,
          recovered_cdn: Path | None = None, recovered_h_only: Path | None = None,
          u4401_patch: Path | None = None, u4401_report: Path | None = None,
          deep_pieces: bool = False, deep_patch: bool = False,
          max_examples: int = 100, progress: int = 25000, manifest_type: int = 0xE,
          type_evidence_path: Path | None = None, allow_cross_version_types: bool = False,
          allow_bundled_types: bool = True, require_complete: bool = False,
          required_manifest_families: tuple[str, ...] = (),
          static_type_recovery: bool = False, require_static_types: bool = False,
          oodle: w.Oodle | None = None) -> dict:
    """Return a structured, bounded report; no filesystem writes or network calls."""
    if require_static_types and not static_type_recovery:
        raise w.ExportError("--require-static-types conflicts with --no-static-type-recovery")
    if not 1 <= max_examples <= 10000 or progress < 0 or not 0 <= manifest_type <= 0xFFFF:
        raise w.ExportError('max_examples must be 1..10000 and progress must be >= 0')
    target, base = Path(target).resolve(), Path(base).resolve()
    tc, bc = w.find_cache_windows_dir(target), w.find_cache_windows_dir(base)
    if tc.resolve() == bc.resolve():
        raise w.ExportError('Target and base must use different cache directories')
    if patch is not None:
        patch = Path(patch).resolve()
        if not patch.is_dir() or not (patch / 'OpenWF' / 'Content').is_dir():
            raise w.ExportError(f'Cannot find patch OpenWF/Content directory: {patch}')
    if allow_cross_version_types and type_evidence_path is None:
        raise w.ExportError('--allow-cross-version-types requires --type-evidence')
    hints = (w.load_type_evidence(type_evidence_path, allow_cross_version=allow_cross_version_types)
             if type_evidence_path is not None else {})
    oodle = oodle or w.Oodle(Path(w.__file__).resolve().parent)
    print(f'[Audit] Reference: {target}')
    print(f'[Audit] Steam base: {base}')
    ti = w.scan_cache(tc)
    bi = w.scan_cache(bc)
    _, h = w._select_h_cache(ti, oodle)
    records = [r for r in w.parse_h_cache_header(h).records if r.logical_path.startswith('/B.Cache.')]
    assets_raw = []
    missing_families = []
    metadata = []
    for record in records:
        if not w.H_CACHE_B_CACHE_RE.fullmatch(record.logical_path):
            raise w.ExportError(f'Unknown manifest family: {record.logical_path}')
        try:
            _, header, _ = w._build_h_only_metadata_object(ti, record.logical_path, record.target_hash, oodle)
        except w.SourceCoverageError as exc:
            missing_families.append({'family': record.logical_path, 'reason': str(exc)})
            continue
        parsed = w.parse_manifest_header(header, w._manifest_namespace(record.logical_path))
        assets_raw.extend(parsed)
        metadata.append({'family': record.logical_path, 'objects': len(parsed), 'source': 'installed-target'})
    if not metadata:
        raise w.ExportError('No manifest families are available')
    assets, duplicates = w._dedupe_manifest_assets(assets_raw)
    missing_required = w._missing_required_manifest_families(
        records, (item['family'] for item in metadata), required_manifest_families)
    if required_manifest_families:
        print(f'[Manifest scope] {len(required_manifest_families) - len(missing_required)}/'
              f'{len(required_manifest_families)} explicitly required families verified')
    print(f'[Audit] {len(assets):,} unique entries, {len(metadata)}/{len(records)} installed manifest families')

    installed_resolver = None
    if static_type_recovery:
        from installed_type_resolver import prepare, preflight_pinned_types
        try:
            target_exe = w._find_target_exe(target)
        except w.ExportError:
            if require_static_types:
                raise
            print('[Audit static types] No installed executable; native recovery unavailable')
        else:
            installed_resolver = prepare(target_exe, ti, oodle, required=require_static_types)
            if installed_resolver is not None:
                preflight_pinned_types(installed_resolver, ti, oodle, assets,
                                       required=require_static_types)

    from recovery_imports import RecoveredCdnCollection
    from recovery_imports import RecoveredHOnlyCollection
    videos = RecoveredCdnCollection(recovered_cdn) if recovered_cdn is not None else None
    h_only = RecoveredHOnlyCollection(recovered_h_only) if recovered_h_only is not None else None
    from recovery_imports import U4401ExactCollection
    u4401 = U4401ExactCollection(u4401_patch, u4401_report) if u4401_patch is not None else None
    if u4401 is not None:
        for protected in (target, base, patch):
            if protected is not None and (protected == u4401.root or protected.is_relative_to(u4401.root)
                                          or u4401.root.is_relative_to(protected)):
                raise w.ExportError('U44.0.1 source overlaps target/base/output patch')
    video_keys = set(videos.rows) if videos else set()
    h_only_keys = set(h_only.rows) if h_only else set()
    u4401_keys = set(u4401.rows) if u4401 else set()
    if (u4401_keys & video_keys) or (u4401_keys & h_only_keys):
        raise w.ExportError("U44.0.1 exact source overlaps a recovery folder")
    if video_keys & h_only_keys:
        raise w.ExportError('Overlapping recovered CDN sources')
    used_video, used_h_only, used_u4401 = set(), set(), set()
    patch_root = patch / 'OpenWF' / 'Content' if patch else None
    counts = Counter()
    issue_counts = Counter()
    type_counts = Counter()
    examples: list[dict] = []
    unchecked_type_examples: list[dict] = []
    size_cache = {}
    expected_patch_files: set[str] = set()

    def issue(code: str, asset: w.ManifestAsset, detail: str) -> None:
        issue_counts[code] += 1
        if len(examples) < max_examples:
            examples.append({'issue': code, 'namespace': asset.namespace, 'path': asset.logical_path,
                             'manifest_hash': asset.hash_b64, 'detail': detail[:320]})

    if missing_required and not require_complete:
        issue_counts['required-manifest-family-unavailable'] += len(missing_required)
        for path in missing_required[:max(0, max_examples - len(examples))]:
            examples.append({'issue': 'required-manifest-family-unavailable', 'path': path})
    if require_complete:
        # Missing manifest families contain unknown assets; a zero-issue result
        # must not mean that we simply skipped those assets. The exporter has
        # the corresponding --require-complete safeguard.
        issue_counts['manifest-family-unavailable'] += len(missing_families)
        for family in missing_families[:max(0, max_examples - len(examples))]:
            examples.append({'issue': 'manifest-family-unavailable',
                             'path': family['family'], 'detail': family['reason'][:320]})

    def verify_file(asset: w.ManifestAsset, type_id: int) -> None:
        if patch_root is None:
            return
        expected = w._safe_output_path(patch_root, asset.namespace, asset.logical_path, type_id, asset.hash_b64)
        expected_patch_files.add(expected.relative_to(patch_root).as_posix())
        if expected.is_symlink() or not expected.resolve().is_relative_to(patch_root):
            issue('patch-symlink', asset, str(expected))
            return
        if not expected.is_file():
            # A different type with the same hash is a diagnostic distinction,
            # not silently accepted as an equivalent object.
            matches = list(expected.parent.glob(expected.name.split('!')[0] + '!*_' + asset.hash_b64))
            if matches:
                issue('patch-cdn-type-mismatch', asset, 'Expected ' + expected.name + '; found ' + ', '.join(m.name for m in matches[:4]))
            else:
                issue('patch-file-missing', asset, str(expected.relative_to(patch_root)))
            return
        if expected.stat().st_size != asset.cdn_size:
            issue('patch-size-mismatch', asset, f'{expected.name}: {expected.stat().st_size} vs manifest {asset.cdn_size}')
            return
        counts['patch_files_valid_name_size'] += 1
        if deep_patch:
            try:
                mode = verify_cdn_payload(expected, asset, oodle)
                counts['patch_deep_verified'] += 1
                counts[f'patch_deep_{mode}'] += 1
            except (OSError, w.ExportError) as exc:
                issue('patch-payload-invalid', asset, str(exc))

    for n, asset in enumerate(assets, 1):
        if progress and n % progress == 0:
            print(f'[Audit] {n:,}/{len(assets):,} | candidates {counts["export_candidates"]:,} | issues {sum(issue_counts.values()):,}')
        if not (asset.flags & w.MANIFEST_FLAG_H):
            issue('unsupported-no-H-manifest', asset, 'Manifest entry does not require H')
            continue
        required = w._required_piece_kinds(asset.flags)
        identity = (asset.namespace, asset.logical_path)
        selected = None
        try:
            selected = w._select_h_by_hash(ti, asset.namespace, asset.logical_path,
                                           asset.manifest_hash, oodle, required_piece_kinds=required)
        except w.SourceCoverageError:
            pass
        except w.ExportError as exc:
            issue('target-H-unreadable-or-ambiguous', asset, str(exc))
            continue
        if selected is None:
            # Validate that inherited objects have all required pieces, not H alone.
            try:
                inherited = w._base_has_complete_inherited_asset(bi, asset, oodle)
            except w.ExportError as exc:
                issue('base-inheritance-error', asset, str(exc))
                continue
            if inherited:
                counts['inherited_base'] += 1
            elif identity in video_keys:
                used_video.add(identity)
                try:
                    videos.validate_asset(asset, oodle)
                    counts['recovered_videos'] += 1
                    verify_file(asset, 0xAA)
                except (OSError, w.ExportError) as exc:
                    issue('recovered-video-invalid', asset, str(exc))
            elif identity in h_only_keys:
                used_h_only.add(identity)
                try:
                    _, typ = h_only.validate_asset(asset, oodle)
                    counts['recovered_h_only'] += 1
                    verify_file(asset, typ)
                except (OSError, w.ExportError) as exc:
                    issue('recovered-H-only-invalid', asset, str(exc))
            elif identity in u4401_keys:
                used_u4401.add(identity)
                try:
                    _, typ = u4401.validate_asset(asset, oodle)
                    counts['recovered_u4401_exact'] += 1
                    verify_file(asset, typ)
                except (OSError, w.ExportError) as exc:
                    issue('recovered-u4401-invalid', asset, str(exc))
            else:
                # Sources are explicitly optional. Report installed-cache gaps
                # honestly rather than treating an old recovery folder as required.
                counts['local_source_unresolved'] += 1
                if asset.logical_path.lower().endswith('.bk2'):
                    counts['local_source_unresolved_video'] += 1
                elif asset.flags == w.MANIFEST_FLAG_H:
                    counts['local_source_unresolved_h_only'] += 1
                else:
                    counts['local_source_unresolved_other'] += 1
                issue('source-unresolved', asset, 'No matching complete asset in the installed target or original base; '
                      'external recovery data was not supplied or does not contain this object')
            continue
        entry, header, h_type = selected
        try:
            validate_selected_pieces(ti, asset, entry, size_cache, oodle, deep=deep_pieces)
        except (OSError, w.ExportError) as exc:
            issue('reference-piece-invalid', asset, str(exc))
            continue
        counts['reference_H_validated'] += 1
        if required:
            counts['reference_required_piece_objects'] += 1
            if deep_pieces:
                counts['reference_payloads_deep_read'] += len(required)

        # Do not silently accept a matching base H hash without B/F coverage.
        same, had_error = w._base_matches(bi, asset, oodle)
        if had_error:
            issue('base-H-read-error', asset, 'One or more matching-path base headers could not be decoded')
            continue
        if same:
            try:
                base_selected = w._select_h_by_hash(bi, asset.namespace, asset.logical_path,
                                                      asset.manifest_hash, oodle, required_piece_kinds=required)
                validate_selected_pieces(bi, asset, base_selected[0], size_cache, oodle, deep=deep_pieces)
                counts['matching_base_required_pieces_verified'] += len(required)
            except (OSError, w.ExportError) as exc:
                issue('base-incomplete-matching-H', asset, str(exc))
                # Matches current exporter omission risk; don't mark unchanged as safe.
                continue
        is_fontcache = '/Temp/FontCache/' in asset.logical_path
        stale_duplicate_packages = []
        if same:
            try:
                stale_duplicate_packages = w._duplicate_target_packages_not_updated(ti, bi, asset, oodle)
            except w.ExportError as exc:
                issue('duplicate-package-unreadable', asset, str(exc))
                continue
        if same and not is_fontcache and not stale_duplicate_packages:
            counts['unchanged_base'] += 1
            continue
        counts['export_candidates'] += 1
        if same and is_fontcache:
            counts['proactive_fontcache'] += 1
        if stale_duplicate_packages:
            counts['proactive_duplicate_package_refresh'] += 1
            if len(examples) < max_examples:
                examples.append({'issue': 'duplicate-package-refresh-required',
                                 'namespace': asset.namespace, 'path': asset.logical_path,
                                 'manifest_hash': asset.hash_b64,
                                 'detail': 'Stale/missing packages: ' + ', '.join(stale_duplicate_packages)})
        try:
            from installed_type_resolver import evidence_for_asset
            cdn_type, type_source = w.resolve_common_header_type(
                asset, h_type, hints, allow_bundled=allow_bundled_types,
                installed_type=evidence_for_asset(installed_resolver, asset, h_type),
            )
        except w.ExportError as exc:
            issue('export-type-unresolved', asset, str(exc))
            continue
        if type_source is None:
            type_counts['header-inferred-unconfirmed'] += 1
            if len(unchecked_type_examples) < min(12, max_examples):
                unchecked_type_examples.append({'namespace': asset.namespace, 'path': asset.logical_path,
                                                'header_type': f'{h_type:X}', 'cdn_type': f'{cdn_type:X}'})
        else:
            type_counts[type_source] += 1
        verify_file(asset, cdn_type)
    if patch_root is not None:
        # Authenticate the full decoded H.Cache against pristine H bytes; B.Cache metadata remains byte-exact.
        try:
            h_entry, _ = w._select_h_cache(ti, oodle)
            expected_metadata = [(f'H.Cache.bin!{manifest_type:X}_' + w.H_CACHE_SENTINEL_HASH,
                                  w.build_shcc(h_entry, None, None))]
            for rec in records:
                if rec.logical_path not in {m['family'] for m in metadata}:
                    continue
                obj, _header, _package = w._build_h_only_metadata_object(
                    ti, rec.logical_path, rec.target_hash, oodle)
                expected_metadata.append((rec.logical_path.lstrip('/') + f'!{manifest_type:X}_' + w.b64m_encode(rec.target_hash), obj))
            for filename, payload in expected_metadata:
                relative = '0/' + filename
                expected_patch_files.add(relative)
                file = patch_root / relative
                if not file.is_file() or file.is_symlink() or not file.resolve().is_relative_to(patch_root):
                    issue_counts['patch-metadata-missing'] += 1
                    if len(examples) < max_examples:
                        examples.append({'issue': 'patch-metadata-missing', 'path': relative})
                else:
                    contents = file.read_bytes()
                    try:
                        if filename.startswith('H.Cache.bin!'):
                            w.verify_h_cache_metadata_object(contents, h, oodle)
                        elif contents != payload:
                            raise w.ExportError('B.Cache exact bytes differ from pristine reconstruction')
                    except w.ExportError as exc:
                        issue_counts['patch-metadata-content-mismatch'] += 1
                        if len(examples) < max_examples:
                            examples.append({'issue': 'patch-metadata-content-mismatch', 'path': relative, 'detail': str(exc)})
                    else:
                        counts['patch_metadata_verified'] += 1
            unmanaged = patch_root / '0' / 'UNMANAGED'
            expected_patch_files.add('0/UNMANAGED')
            if not unmanaged.is_file() or unmanaged.stat().st_size:
                issue_counts['patch-UNMANAGED-invalid'] += 1
            executable = patch / 'Warframe.x64.exe'
            original_exe = w._find_target_exe(target)
            if (executable.is_symlink() or not executable.is_file()
                    or executable.stat().st_size != original_exe.stat().st_size):
                issue_counts['patch-client-exe-missing-or-size-mismatch'] += 1
            else:
                with executable.open('rb') as exported, original_exe.open('rb') as original:
                    if hashlib.file_digest(exported, 'sha256').digest() != hashlib.file_digest(original, 'sha256').digest():
                        issue_counts['patch-client-exe-hash-mismatch'] += 1
        except (OSError, w.ExportError) as exc:
            issue_counts['patch-metadata-audit-failed'] += 1
            if len(examples) < max_examples:
                examples.append({'issue': 'patch-metadata-audit-failed', 'detail': str(exc)[:320]})
        for file in patch_root.rglob('*'):
            if file.is_dir():
                continue
            relative = file.relative_to(patch_root).as_posix()
            if relative not in expected_patch_files:
                issue_counts['patch-unexpected-file'] += 1
                if len(examples) < max_examples:
                    examples.append({'issue': 'patch-unexpected-file', 'path': relative})

    if patch is not None:
        for marker_name in ('.install-to-patch.in-progress', '.install-to-patch.failed'):
            marker = patch / marker_name
            if marker.is_symlink() or marker.exists():
                issue_counts['patch-export-not-finished'] += 1
                if len(examples) < max_examples:
                    examples.append({'issue': 'patch-export-not-finished',
                                     'path': str(marker),
                                     'detail': 'Patch export is interrupted or failed; do not use this output'})
    if video_keys - used_video:
        issue_counts['unused-video-recovery-evidence'] += len(video_keys - used_video)
        for key in sorted(video_keys - used_video)[:max(0, max_examples - len(examples))]:
            examples.append({'issue': 'unused-video-recovery-evidence', 'namespace': key[0], 'path': key[1]})
    if h_only_keys - used_h_only:
        issue_counts['unused-H-only-recovery-evidence'] += len(h_only_keys - used_h_only)
        for key in sorted(h_only_keys - used_h_only)[:max(0, max_examples - len(examples))]:
            examples.append({'issue': 'unused-H-only-recovery-evidence', 'namespace': key[0], 'path': key[1]})
    if u4401_keys - used_u4401:
        issue_counts['unused-u4401-recovery-evidence'] += len(u4401_keys - used_u4401)
        for key in sorted(u4401_keys - used_u4401)[:max(0, max_examples - len(examples))]:
            examples.append({'issue': 'unused-u4401-recovery-evidence', 'namespace': key[0], 'path': key[1]})
    # Include an explicit zero-valued summary when the local-only run succeeds.
    for key in ('local_source_unresolved', 'local_source_unresolved_video',
                'local_source_unresolved_h_only', 'local_source_unresolved_other'):
        counts.setdefault(key, 0)
    if counts['local_source_unresolved']:
        print(f'[Local-only coverage] Missing {counts["local_source_unresolved"]:,} manifest objects: '
              f'{counts["local_source_unresolved_video"]:,} video, '
              f'{counts["local_source_unresolved_h_only"]:,} H-only, '
              f'{counts["local_source_unresolved_other"]:,} other. '
              'See source-unresolved entries in the JSON report.')
    counts['manifest_objects'] = len(assets)
    counts['manifest_duplicate_entries'] = duplicates
    counts['manifest_families_available'] = len(metadata)
    counts['manifest_families_total'] = len(records)
    counts['manifest_families_explicitly_required'] = len(required_manifest_families)
    counts['manifest_families_required_available'] = len(required_manifest_families) - len(missing_required)
    expected_written = (counts['export_candidates'] + counts['recovered_videos']
                        + counts['recovered_h_only'] + counts['recovered_u4401_exact'])
    counts['expected_export_files'] = expected_written
    # No metadata or unchanged/inherited file needs a CDN payload in the patch.
    report = {
        'version': w.VERSION, 'kind': 'offline-preexport-cache-and-cdn-audit',
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'reference': str(target), 'base': str(base), 'patch_checked': str(patch) if patch else None,
        'modes': {'deep_pieces': deep_pieces, 'deep_patch': deep_patch,
                  'static_type_recovery': static_type_recovery,
                  'require_static_types': require_static_types,
                  'require_complete': require_complete,
                  'required_manifest_families': list(required_manifest_families),
                  'bundled_type_hints': allow_bundled_types,
                  'prior_recovery_cdn_source_provided': recovered_cdn is not None,
                  'prior_recovery_h_only_source_provided': recovered_h_only is not None,
                  'u4401_exact_source_provided': u4401_patch is not None},
        'manifest_coverage': {
            'all_h_cache_families_available': not missing_families,
            'required_installed_scope_available': not missing_required,
            'coverage_label': ('all-families' if not missing_families else
                               'verified-declared-scope-only' if required_manifest_families and not missing_required else
                               'partial-not-fully-scoped'),
        },
        'counts': dict(sorted(counts.items())), 'cdn_type_evidence': dict(sorted(type_counts.items())),
        'header_inferred_not_independently_confirmed_examples': unchecked_type_examples,
        'hard_issue_counts': dict(sorted(issue_counts.items())), 'hard_issue_total': sum(issue_counts.values()),
        'issues_truncated': sum(issue_counts.values()) > len(examples), 'issue_examples': examples,
        'available_manifests': metadata, 'unavailable_manifest_families': missing_families,
        'limitations': [
            'Unavailable H.Cache-listed families are reported but are not falsely counted as audited objects.',
            'Unchanged means matching H digest AND structurally present required base B/F; it does not prove byte-identical entire cache packages.',
            'Default B/F verification checks cache-file bounds and manifest participation; --deep-pieces also decompresses required payloads.',
            'Header-inferred CDN type IDs are not independently confirmed from an external CDN or live client trace.',
            'This audits local coverage and on-disk objects, not byte-for-byte historical CDN object identity or all possible missions.',
            'A patch filename/length match alone does not prove payload integrity; --deep-patch verifies CRC, SHCC H hash and H/B/F slots.',
            'A runtime cache-hash match does not establish that every shader permutation has been installed locally.',
        ],
    }
    return report

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', type=Path, help='Untouched reference Final-U44 install')
    parser.add_argument('base', type=Path, help='Untouched original Steam base')
    parser.add_argument('--patch', type=Path, help='Already exported patch folder (optional post-export check)')
    parser.add_argument('--recovered-cdn', type=Path, help='Validated 101-video offline source folder')
    parser.add_argument('--recovered-h-only', type=Path, help='Validated 2-resource offline source folder')
    parser.add_argument('--u4401-patch', type=Path, help='Verified exact-identity U44.0.1 source; read-only, offline')
    parser.add_argument('--deep-pieces', action='store_true', help='Decompress all required B/F cache payloads (slow)')
    parser.add_argument('--deep-patch', action='store_true', help='Validate full emitted CDN payloads, CRC32C and SHCC H/B/F')
    parser.add_argument('--max-examples', type=int, default=100)
    parser.add_argument('--progress', type=int, default=25000)
    parser.add_argument('--manifest-type', type=w._parse_manifest_type, default=0xE)
    parser.add_argument('--type-evidence', type=Path, help='Optional external exact-hash type evidence JSON')
    parser.add_argument('--allow-cross-version-types', action='store_true')
    parser.add_argument('--no-bundled-type-hints', action='store_true')
    parser.add_argument('--static-type-recovery', action='store_true',
                        help='recover native CDN type IDs from verified installed EXE and Packages.bin')
    parser.add_argument('--require-static-types', action='store_true',
                        help='require static type recovery and five pinned type preflights')
    parser.add_argument('--required-manifest-family', action='append', default=[], metavar='/B.Cache.NAME.bin',
                        help='require this exact H.Cache-listed family; repeat for explicitly audited installed configuration')
    parser.add_argument('--require-complete', action='store_true',
                        help='treat B.Cache families unavailable from both target and matching-hash Steam base as hard issues')
    parser.add_argument('-o', '--output', type=Path, default=Path(f'offline-patch-audit-v{w.VERSION}.json'))
    args = parser.parse_args(argv)
    if args.deep_patch and args.patch is None:
        parser.error('--deep-patch requires --patch')
    try:
        output = args.output.resolve()
        for source in (args.target, args.base, args.patch, args.recovered_cdn, args.recovered_h_only, args.u4401_patch):
            if source is not None and (output == source.resolve() or output.is_relative_to(source.resolve())):
                raise w.ExportError('Audit report must be outside source, patch, and recovery folders')
        report = audit(target=args.target, base=args.base, patch=args.patch,
                       recovered_cdn=args.recovered_cdn, recovered_h_only=args.recovered_h_only,
                       u4401_patch=args.u4401_patch, u4401_report=args.u4401_report,
                       deep_pieces=args.deep_pieces, deep_patch=args.deep_patch,
                       max_examples=args.max_examples, progress=args.progress, manifest_type=args.manifest_type,
                       type_evidence_path=args.type_evidence, allow_cross_version_types=args.allow_cross_version_types,
                       allow_bundled_types=not args.no_bundled_type_hints,
                       static_type_recovery=args.static_type_recovery or args.require_static_types,
                       require_static_types=args.require_static_types,
                       require_complete=args.require_complete,
                       required_manifest_families=tuple(args.required_manifest_family))
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        c = report['counts']
        print(f'[Audit summary] {c["manifest_objects"]:,} manifest objects | unchanged {c.get("unchanged_base", 0):,} | '
              f'candidates {c.get("export_candidates", 0):,} | inherited {c.get("inherited_base", 0):,} | '
              f'recovered {c.get("recovered_videos", 0) + c.get("recovered_h_only", 0) + c.get("recovered_u4401_exact", 0):,} | planned {c["expected_export_files"]:,}')
        print(f'[Type evidence] {report["cdn_type_evidence"]}')
        print(f'[Manifest coverage] {c["manifest_families_available"]}/{c["manifest_families_total"]} families '
              f'({report["manifest_coverage"]["coverage_label"]})')
        print(f'[Hard issues] {report["hard_issue_total"]:,} {report["hard_issue_counts"]}')
        if args.patch:
            print(f'[Patch files] {c.get("patch_files_valid_name_size", 0):,}/{c["expected_export_files"]:,} names+sizes matched')
        print(f'[Report] {output}')
        return 2 if report['hard_issue_total'] else 0
    except KeyboardInterrupt:
        print('[Audit] Interrupted', file=sys.stderr)
        return 130
    except (OSError, w.ExportError, ValueError) as exc:
        print(f'[Audit error] {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
