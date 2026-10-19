"""Optional U44 installed-scope stripped asset enrichment.

Never reads runtime 404 inventories or previous recovery reports. All identities
come from the pristine U44 manifest; no same-path newer-version substitutions.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import stat
import struct
from pathlib import Path
import shutil
import tempfile

import warframe_install_to_patch as w
import offline_patch_audit as audit
import common as fingerprint
from restore_u44_complete import REQUIRED_FAMILIES
import inspect_unresolved_content as cdn
import recover_missing_cdn as fetcher
import recover_u4400_last_three as historical
import compare_u4401_sources as compare_sources
from common import label as color_label, warning as print_warning
from common import fetch_verified

class StrippedError(w.ExportError):
    pass

def _is_redirect(path: Path) -> bool:
    """Recognize ordinary symlinks and Windows NTFS junction/reparse points."""
    if path.is_symlink():
        return True
    try:
        return bool(getattr(path.lstat(), 'st_file_attributes', 0)
            & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0))
    except FileNotFoundError:
        return False

def _require_regular_path(path: Path, root: Path) -> None:
    """Reject symlinked ancestors, including symlinks pointing inside the patch.

    Path.resolve() confinement alone is insufficient: a link within Content can
    redirect writes to otherwise unrelated existing patch files.
    """
    path, root = Path(path).absolute(), Path(root).absolute()
    if not path.is_relative_to(root) or path == root:
        raise StrippedError(f'Object is outside its Content/staging root: {path}')
    current = path
    while current != root:
        if _is_redirect(current):
            raise StrippedError(f'Symlinked object or ancestor: {current}')
        if current != path and current.exists() and not current.is_dir():
            raise StrippedError(f'Non-directory object ancestor: {current}')
        current = current.parent

def _verify_asset_bytes(raw: bytes, asset: w.ManifestAsset, oodle: w.Oodle,
        expected_type: int) -> None:
    """Validate the same immutable buffer used for provenance and staging."""
    audit.verify_cdn_bytes(raw, asset, oodle)
    if (asset.namespace == '0' and asset.logical_path.lower().endswith('.bk2')
            and expected_type == 0xAA):
        embedded_hash, embedded_type = w.parse_common_header(
            _decoded_sections(raw, oodle, kinds='H')['H'])
        if embedded_hash != asset.manifest_hash or embedded_type != expected_type:
            raise StrippedError(f'Video CommonHeader hash/type disagrees with manifest: '
                f'{asset.namespace}{asset.logical_path}')

def _verify_asset(path: Path, asset: w.ManifestAsset, oodle: w.Oodle,
        expected_type: int) -> None:
    """On-disk verification; read the file only once."""
    _verify_asset_bytes(path.read_bytes(), asset, oodle, expected_type)

def installed_stripped(target: Path, oodle: w.Oodle, target_index=None) -> list[w.ManifestAsset]:
    idx = target_index if target_index is not None else w.scan_cache(w.find_cache_windows_dir(target))
    _, raw = w._select_h_cache(idx, oodle)
    records = [r for r in w.parse_h_cache_header(raw).records if r.logical_path.startswith('/B.Cache.')]
    all_assets = []
    available = []
    for rec in records:
        if not w.H_CACHE_B_CACHE_RE.fullmatch(rec.logical_path):
            raise StrippedError(f'Unexpected manifest name: {rec.logical_path}')
        if rec.logical_path not in REQUIRED_FAMILIES:
            continue
        try:
            _, header, _ = w._build_h_only_metadata_object(idx, rec.logical_path, rec.target_hash, oodle)
        except w.SourceCoverageError as exc:
            raise StrippedError(f'Required manifest missing: {rec.logical_path}: {exc}') from exc
        all_assets.extend(w.parse_manifest_header(header, w._manifest_namespace(rec.logical_path)))
        available.append(rec.logical_path)
    missing = set(REQUIRED_FAMILIES) - set(available)
    if missing:
        raise StrippedError('Installed scope is incomplete: ' + ', '.join(sorted(missing)))
    assets, _ = w._dedupe_manifest_assets(all_assets)
    return [asset for asset in assets if asset.section == 'stripped']

def validate_patch_identity(patch: Path, target: Path, oodle: w.Oodle, idx) -> None:
    """Authenticate patch's original metadata against pristine installed U44."""
    if _is_redirect(patch) or not patch.is_dir():
        raise StrippedError(f'Existing patch is not an ordinary directory: {patch}')
    root = patch / 'OpenWF' / 'Content'
    if _is_redirect(patch / 'OpenWF') or _is_redirect(root) or not root.is_dir():
        raise StrippedError('Patch has no ordinary OpenWF/Content folder')
    exe = patch / 'Warframe.x64.exe'
    source_exe = w._find_target_exe(target)
    if exe.is_symlink() or not exe.is_file() or exe.stat().st_size != source_exe.stat().st_size:
        raise StrippedError('Patch executable does not match pristine reference')
    with exe.open('rb') as got, source_exe.open('rb') as expected:
        if hashlib.file_digest(got, 'sha256').digest() != hashlib.file_digest(expected, 'sha256').digest():
            raise StrippedError('Patch executable SHA-256 differs from pristine reference')
    h_entry, h_data = w._select_h_cache(idx, oodle)
    expected = [(f'H.Cache.bin!E_{w.H_CACHE_SENTINEL_HASH}', w.build_shcc(h_entry, None, None))]
    for rec in w.parse_h_cache_header(h_data).records:
        if rec.logical_path in REQUIRED_FAMILIES:
            obj, _, _ = w._build_h_only_metadata_object(idx, rec.logical_path, rec.target_hash, oodle)
            expected.append((f'{rec.logical_path.lstrip("/")}!E_{w.b64m_encode(rec.target_hash)}', obj))
    for rel, data in expected:
        path = root / '0' / rel
        _require_regular_path(path, root)
        if path.is_symlink() or not path.is_file():
            raise StrippedError(f'Patch metadata missing from pristine U44.0.0: {rel}')
        actual = path.read_bytes()
        if rel.startswith('H.Cache.bin!'):
            w.verify_h_cache_metadata_object(actual, h_data, oodle)
        elif actual != data:
            raise StrippedError(f'Patch metadata differs from pristine U44.0.0: {rel}')
    unmanaged = root / '0' / 'UNMANAGED'
    _require_regular_path(unmanaged, root)
    if unmanaged.is_symlink() or not unmanaged.is_file() or unmanaged.stat().st_size != 0:
        raise StrippedError('Patch UNMANAGED marker missing or invalid')
    for marker in ('.install-to-patch.failed', '.install-to-patch.in-progress'):
        if (patch / marker).exists() or (patch / marker).is_symlink():
            raise StrippedError(f'Cannot enrich unfinished patch ({marker})')

def _expected_type(asset: w.ManifestAsset, ti, bi, oodle, resolver) -> int:
    """Never accept a filename type solely because an existing patch used it."""
    from installed_type_resolver import evidence_for_asset
    for index in (ti, bi):
        try:
            _h, _header, parsed_type = w._select_h_by_hash(
                index, asset.namespace, asset.logical_path, asset.manifest_hash,
                oodle, required_piece_kinds=w._required_piece_kinds(asset.flags))
        except w.SourceCoverageError:
            continue
        resolved, _evidence = w.resolve_common_header_type(
            asset, parsed_type, {}, allow_bundled=False,
            installed_type=evidence_for_asset(resolver, asset, parsed_type))
        return resolved
    # The only permitted cache-absent exceptions are the independently
    # validated U44.0.0 historical exact identities (one video + two H-only)
    # and the 100 precise original stripped .bk2 identities already in patch.
    pinned = historical.PINNED.get(asset.logical_path)
    if pinned is not None and (asset.hash_b64, asset.cdn_size) == pinned[:2]:
        return pinned[2]
    if (asset.namespace == '0' and asset.logical_path.lower().endswith('.bk2')
            and asset.flags == (w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F)):
        return 0xAA
    raise StrippedError(f'Unable to independently establish CDN type for {asset.namespace}{asset.logical_path}')

def _existing_asset(root: Path, asset: w.ManifestAsset, oodle: w.Oodle, expected_type: int,
        *, verify: bool = True) -> Path | None:
    # Find exact hash only. A different current CDN hash is never considered.
    relative = w._safe_output_path(root, asset.namespace, asset.logical_path, 0, asset.hash_b64)
    parent = relative.parent
    _require_regular_path(relative, root)
    name = w._validate_logical_path(asset.logical_path)[-1]
    if parent.is_symlink():
        raise StrippedError(f'Symlinked CDN directory: {parent}')
    matches = ([item for item in parent.iterdir() if
        item.name.startswith(name + '!') and item.name.endswith('_' + asset.hash_b64)]
        if parent.is_dir() else [])
    if len(matches) > 1:
        raise StrippedError(f'Ambiguous CDN type for {asset.namespace}{asset.logical_path}')
    if not matches:
        # Detect a wrong-hash version at the exact logical path instead of
        # silently treating it as an alternative version of the requested asset.
        return None
    candidate = matches[0]
    if candidate.is_symlink() or not candidate.is_file() or not candidate.resolve().is_relative_to(root.resolve()):
        raise StrippedError(f'Unsafe existing CDN object: {candidate}')
    suffix = candidate.name.removeprefix(name + '!')
    if not suffix.split('_', 1)[0] or '_' not in suffix:
        raise StrippedError(f'Invalid existing CDN object filename: {candidate}')
    try:
        actual_type = int(suffix.split('_', 1)[0], 16)
    except ValueError as exc:
        raise StrippedError(f'Invalid existing CDN type: {candidate}') from exc
    if actual_type != expected_type or suffix.split('_', 1)[0] != f'{expected_type:X}':
        raise StrippedError(f'Existing stripped CDN type does not match original identity: {candidate}')
    if verify:
        _verify_asset(candidate, asset, oodle, expected_type)
    return candidate

def _download_exact(asset: w.ManifestAsset, type_id: int, oodle: w.Oodle,
        timeout: float, max_bytes: int, *, retries: int = 5,
        verify_func=None, attempts_log=None, before_attempt=None) -> bytes:
    if not 0 < asset.cdn_size <= max_bytes:
        raise StrippedError(f'CDN fallback size exceeds per-object limit: {asset.namespace}{asset.logical_path}')
    item = dict(namespace=asset.namespace, logical_path=asset.logical_path,
        expected_hash_base64=asset.hash_b64)
    url = cdn.make_cdn_url(item, type_id)
    print(f'{color_label("CDN")} Exact manifest identity | {asset.namespace}{asset.logical_path} | {asset.cdn_size:,} bytes')
    raw, _checks = fetch_verified(
        url=url, logical_path=f'{asset.namespace}{asset.logical_path}',
        expected_size=asset.cdn_size, timeout=timeout, get_func=fetcher._download,
        verify_func=verify_func if verify_func is not None else lambda data: None,
        retries=retries, attempts_log=attempts_log, before_attempt=before_attempt)
    return raw

def _source_contents(sources: tuple[Path, ...], protected: tuple[Path, ...]) -> list[tuple[Path, Path]]:
    """Validate independent read-only patches before staging or CDN requests."""
    results: list[tuple[Path, Path]] = []
    for original in sources:
        source = Path(original)
        if _is_redirect(source):
            raise StrippedError(f'Symlinked source patch root: {source}')
        patch = source.resolve(strict=True)
        for other in (*protected, *(r[0] for r in results)):
            if patch == other or patch.is_relative_to(other) or other.is_relative_to(patch):
                raise StrippedError(f'Source patch overlaps another input/output: {patch}')
        for fragment in ('OpenWF', 'Content'):
            segment = patch / ('OpenWF' if fragment == 'OpenWF' else 'OpenWF/Content')
            if _is_redirect(segment) or not segment.is_dir():
                raise StrippedError(f'Source patch contains unsafe/missing {fragment} directory: {patch}')
        content = compare_sources.safe_patch_content(patch)
        results.append((patch, content))
    return results

def _decoded_sections(raw: bytes, oodle: w.Oodle, *, kinds: str = 'HBF') -> dict[str, bytes]:
    """Decode only requested SHCC pieces from a structurally verified payload."""
    if raw.startswith(w.SHCC_PREAMBLE):
        data = raw[:-5]
    else:
        decoded_size = int.from_bytes(raw[-9:-5], 'little')
        data = oodle.decompress(raw[:-9], decoded_size)
    pos = len(w.SHCC_PREAMBLE)
    result = {}
    from recover_missing_cdn import _unpack_framed_payload
    for kind in 'HBF':
        codec, unpacked, stored = struct.unpack_from('<BII', data, pos)
        pos += 9
        block = data[pos:pos + stored]
        pos += stored
        if kind in kinds:
            result[kind] = (block if codec == 0 else _unpack_framed_payload(block, unpacked, oodle))
    return result

def _crosscheck_installed_pieces(asset: w.ManifestAsset, raw: bytes, ti, bi,
        oodle: w.Oodle) -> str:
    """Compare every surviving matching H/B/F package, even partial ones.

    An H hash is not a hash of video frames. The first matching H package may
    have lost its F data while another package still retains the original F.
    Both pristine and Steam-base caches must agree with any imported object.
    """
    chunks = None
    evidence = []
    observed = set()
    for index, label in ((ti, 'pristine'), (bi, 'base')):
        try:
            chosen, header, _type = w._select_h_by_hash(
                index, asset.namespace, asset.logical_path, asset.manifest_hash, oodle)
        except w.SourceCoverageError:
            continue
        if chunks is None:
            chunks = _decoded_sections(raw, oodle)
        matches = [(chosen, header)]
        seen_packages = {chosen.package}
        for h in w._entries_for(index, asset.namespace, asset.logical_path, 'H'):
            if h.package in seen_packages:
                continue
            try:
                h_data = w.decompress_cache_entry(h, oodle)
            except w.ExportError:
                # A corrupt entry for a different H hash is not evidence for
                # this asset. _select_h_by_hash already established a valid H.
                continue
            if h_data[:16] == asset.manifest_hash:
                seen_packages.add(h.package)
                matches.append((h, h_data))
        checked = {'H'}
        for h, h_data in matches:
            if chunks['H'] != h_data:
                raise StrippedError(f'H bytes differ from original {label} cache: '
                    f'{asset.namespace}{asset.logical_path}')
            for kind in w._required_piece_kinds(asset.flags):
                piece = w._piece_in_package(index, asset.namespace,
                    asset.logical_path, kind, h.package)
                if piece is None:
                    continue
                if chunks[kind] != w.decompress_cache_entry(piece, oodle):
                    raise StrippedError(f'{kind} bytes differ from original {label} cache: '
                        f'{asset.namespace}{asset.logical_path}')
                checked.add(kind)
        observed.update(checked)
        evidence.append(label + '-' + ''.join(c for c in 'HBF' if c in checked) + '-match')
    if evidence:
        missing = ''.join(c for c in w._required_piece_kinds(asset.flags) if c not in observed)
        return ('+'.join(evidence) + (f'; original-{missing}-not-independently-known'
            if missing else ''))
    missing = w._required_piece_kinds(asset.flags)
    return ('manifest-H-identity-only; original-' + (missing or 'H') +
            '-not-independently-known')

def _exact_source_object(asset: w.ManifestAsset, type_id: int,
        sources: list[tuple[Path, Path]], oodle: w.Oodle,
        ti, bi) -> tuple[bytes, Path, str] | None:
    """Search ordered patches by namespace/path/type/H hash, never by name alone.

    Invalid exact-identity candidates fail closed. Newer same-path/different-hash
    files are ignored even if they could be copied under a target filename.
    """
    selected = None
    for source, content in sources:
        candidate = w._safe_output_path(content, asset.namespace, asset.logical_path,
            type_id, asset.hash_b64)
        _require_regular_path(candidate, content)
        if candidate.is_symlink() or (candidate.exists() and not candidate.is_file()):
            raise StrippedError(f'Unsafe exact-identity source object: {candidate}')
        if not candidate.exists():
            continue
        if not candidate.resolve().is_relative_to(content.resolve()):
            raise StrippedError(f'Source object escapes source patch: {candidate}')
        if candidate.stat().st_size != asset.cdn_size:
            raise StrippedError(f'Exact-identity source object has wrong manifest size: {candidate}')
        # Validate the bytes we will actually stage, not a previous read of
        # a source file that another process could replace between reads.
        raw = candidate.read_bytes()
        _verify_asset_bytes(raw, asset, oodle, type_id)
        if selected is None:
            # Original cache F/B data, when present, protect ability videos
            # whose frames changed without changing their H identifier.
            check = _crosscheck_installed_pieces(asset, raw, ti, bi, oodle)
            selected = (raw, source, check)
            print(f'{color_label("Verified")} Exact source object | {source.name} | '
                  f'{asset.namespace}{asset.logical_path} | {check}')
        elif raw != selected[0]:
            # Equal H/size/CRC/SHCC is not a full historical payload hash.
            # The older patch is preferred only when copies agree; never
            # silently pick arbitrary video bytes when sources conflict.
            raise StrippedError(f'Conflicting full CDN payloads under the same original manifest '
                f'identity: {asset.namespace}{asset.logical_path}; '
                f'{selected[1]} vs {source}')
    return selected

def _compare_video_source(asset: w.ManifestAsset, original: bytes, frames: bytes,
        source: Path, content: Path, oodle: w.Oodle) -> dict:
    """Check any same-path source .bk2, even when its H identity changed.

    Unlike enrichment, this is *comparison*, not recovery. A source patch
    can be incremental and have no copy of an unchanged video. Its filename
    hash is not independent proof that it originally shipped in that build.
    """
    result = {'source_patch': str(source), 'status': 'not_present'}
    path = w._safe_output_path(content, asset.namespace, asset.logical_path,
        0xAA, asset.hash_b64)
    parent = path.parent
    _require_regular_path(parent, content)
    if not parent.is_dir():
        return result
    basename = w._validate_logical_path(asset.logical_path)[-1] + '!'
    candidates = [entry for entry in parent.iterdir() if entry.name.startswith(basename)]
    if not candidates:
        return result
    if len(candidates) != 1:
        result.update(status='ambiguous', error=f'{len(candidates)} objects share the same logical path')
        return result
    candidate = candidates[0]
    try:
        _require_regular_path(candidate, content)
        if not candidate.is_file() or _is_redirect(candidate):
            raise StrippedError('Source video is not an ordinary file')
        suffix = candidate.name[len(basename):]
        if not suffix.startswith('AA_'):
            raise StrippedError(f'Expected .bk2 CDN type AA, got {suffix.split("_", 1)[0]}')
        encoded = suffix[3:]
        if len(encoded) != 22:
            raise StrippedError('Invalid source video H identifier length')
        try:
            digest = base64.b64decode((encoded.replace('-', '/') + '==').encode('ascii'), validate=True)
        except (ValueError, UnicodeError, binascii.Error) as exc:
            raise StrippedError('Invalid source video H identifier') from exc
        if len(digest) != 16 or w.b64m_encode(digest) != encoded:
            raise StrippedError('Non-canonical source video H identifier')
        if not 14 <= candidate.stat().st_size <= 64 * 1024 * 1024:
            raise StrippedError('Source video exceeds safe object size limit')
        raw = candidate.read_bytes()
        from_source = w.ManifestAsset(asset.namespace, asset.section,
            asset.logical_path, digest,
            len(raw) | w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F)
        _verify_asset_bytes(raw, from_source, oodle, 0xAA)
        source_frames = _decoded_sections(raw, oodle, kinds='F')['F']
        if not source_frames:
            raise StrippedError('Source .bk2 has empty F data')
        same_f = frames == source_frames
        same_h = asset.manifest_hash == digest
        result.update(status='f_match' if same_f else 'f_different',
            source_manifest_hash=encoded,
            same_h_identity=same_h,
            same_full_cdn_bytes=(original == raw),
            cdn_size=len(raw),
            cdn_sha256=hashlib.sha256(raw).hexdigest(),
            f_bytes=len(source_frames),
            f_sha256=hashlib.sha256(source_frames).hexdigest())
    except (OSError, w.ExportError, ValueError, struct.error) as exc:
        result.update(status='invalid', error=f'{type(exc).__name__}: {exc}')
    return result

def audit_existing_videos(*, patch: Path, target: Path, base: Path,
        source_patches: tuple[Path, ...] = ()) -> dict:
    """Read-only U44.0.0 stripped .bk2 audit, including original F-byte checks.

    H/size/CRC validation alone cannot establish the historical F (video)
    contents. Only a matching F section in the pristine U44.0.0 cache counts
    as byte-for-byte historical video proof. Older Steam-base or additional
    update-patch F bytes are comparison evidence, not U44.0.0 proof.

    This checks the manifest-declared *stripped* .bk2 objects; it does not
    assert anything about packed/non-stripped movies or full CDN envelope
    byte identity (which requires an independent historical CDN object).
    """
    if any(_is_redirect(Path(x)) for x in (patch, target, base)):
        raise StrippedError('Symlinked patch or source root is not permitted')
    patch, target, base = (Path(x).resolve(strict=True) for x in (patch, target, base))
    if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
           for a, b in ((patch, target), (patch, base), (target, base))):
        raise StrippedError('Patch, pristine installation and Steam base must be independent directories')
    sources = _source_contents(tuple(source_patches), (patch, target, base))
    oodle = w.Oodle(Path(w.__file__).resolve().parent)
    ti = w.scan_cache(w.find_cache_windows_dir(target))
    bi = w.scan_cache(w.find_cache_windows_dir(base))
    validate_patch_identity(patch, target, oodle, ti)
    videos = [asset for asset in installed_stripped(target, oodle, ti)
        if asset.namespace == '0' and asset.logical_path.lower().endswith('.bk2')]
    if not videos:
        raise StrippedError('Original installed manifest declares no stripped .bk2 videos to audit')
    print(f'[Videos] {len(videos):,} original-manifest stripped .bk2 objects; read-only comparison')
    source_counts = {'f_match': 0, 'f_different': 0, 'not_present': 0,
        'invalid': 0, 'ambiguous': 0, 'same_h_different_f': 0}
    results = []
    counts = {'target_f_verified': 0, 'base_only': 0, 'inconclusive': 0, 'failed': 0}
    content = patch / 'OpenWF' / 'Content'
    for number, asset in enumerate(videos, 1):
        record = {'namespace': asset.namespace, 'logical_path': asset.logical_path,
            'manifest_hash': asset.hash_b64, 'cdn_size': asset.cdn_size}
        try:
            if asset.flags != (w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F):
                raise StrippedError('Unexpected stripped .bk2 manifest piece flags')
            candidate = _existing_asset(content, asset, oodle, 0xAA, verify=False)
            if candidate is None:
                raise StrippedError('Original-manifest CDN object is missing from patch')
            # Verify the actual buffer being compared, not a prior disk read.
            raw = candidate.read_bytes()
            _verify_asset_bytes(raw, asset, oodle, 0xAA)
            frames = _decoded_sections(raw, oodle, kinds='F')['F']
            if not frames:
                raise StrippedError('Decoded video F section is empty')
            record.update(cdn_sha256=hashlib.sha256(raw).hexdigest(),
                f_sha256=hashlib.sha256(frames).hexdigest(), f_bytes=len(frames))
            if sources:
                comparisons = []
                for source, source_content in sources:
                    comparison = _compare_video_source(asset, raw, frames,
                        source, source_content, oodle)
                    comparisons.append(comparison)
                    source_counts[comparison['status']] += 1
                    if comparison['status'] == 'f_different' and comparison['same_h_identity']:
                        source_counts['same_h_different_f'] += 1
                    if comparison['status'] in ('invalid', 'ambiguous'):
                        print_warning(f'Source video comparison {comparison["status"]}: '
                            f'{source.name} | {asset.namespace}{asset.logical_path} | '
                            f'{comparison["error"]}')
                    elif comparison['status'] == 'f_different':
                        print(f'[Compare] F differs | {source.name} | '
                              f'{asset.namespace}{asset.logical_path} | '
                              f'same H: {comparison["same_h_identity"]}')
                record['source_comparisons'] = comparisons
            evidence = _crosscheck_installed_pieces(asset, raw, ti, bi, oodle)
            record['cache_evidence'] = evidence
            if 'pristine-HF-match' in evidence:
                status = 'target_f_verified'
            elif 'base-HF-match' in evidence:
                status = 'base_only'
            else:
                status = 'inconclusive'
        except (w.ExportError, OSError, ValueError, struct.error) as exc:
            status = 'failed'
            record['error'] = f'{type(exc).__name__}: {exc}'
        record['status'] = status
        counts[status] += 1
        results.append(record)
        if status == 'failed':
            print_warning(f'Video verification failed: {asset.namespace}{asset.logical_path} | {record["error"]}')
        elif status != 'target_f_verified':
            print(f'[Video] {status} | {asset.namespace}{asset.logical_path} | {record["cache_evidence"]}')
        if number % 25 == 0 or number == len(videos):
            print(f'[Videos] {number:,}/{len(videos):,} checked')
    print(f'[Videos] Original U44.0.0 F-byte matches: {counts["target_f_verified"]:,}; '
          f'older-base-only: {counts["base_only"]:,}; '
          f'inconclusive: {counts["inconclusive"]:,}; failed: {counts["failed"]:,}')
    if sources:
        print(f'[Compare] Source videos: F match {source_counts["f_match"]:,}; '
              f'F different {source_counts["f_different"]:,}; '
              f'not present {source_counts["not_present"]:,}; '
              f'invalid/ambiguous {source_counts["invalid"] + source_counts["ambiguous"]:,}; '
              f'same-H/different-F {source_counts["same_h_different_f"]:,}')
    return {'total': len(videos), **counts, 'videos': results,
            'source_comparison_counts': source_counts,
            'source_patches': [str(path) for path, _content in sources],
            'scope': 'original-manifest-stripped-bk2',
            'full_cdn_bytes_proven': False}

def add_missing(*, patch: Path, target: Path, base: Path, allow_cdn: bool = False,
        timeout: float = 30.0, max_cdn_bytes: int = 64 * 1024 * 1024,
        max_total_cdn_bytes: int = 512 * 1024 * 1024,
        full_source_hash: bool = False, retries: int = 5,
        source_patches: tuple[Path, ...] = (),
        attempt_history: list[dict] | None = None,
        dry_run: bool = False) -> dict:
    """All-or-nothing additive enrichment, never overwrite an existing object.

    The only mutation of the supplied patch is new manifest-exact CDN files.
    The pristine reference and base are always read-only. A check-only run
    stages and verifies all missing objects but does not publish any files.
    Returned counts can be included in the transactional deep-audit report.
    """
    if _is_redirect(Path(patch)) or _is_redirect(Path(target)) or _is_redirect(Path(base)):
        raise StrippedError("Symlinked source or patch root is not permitted")
    patch, target, base = (Path(x).resolve(strict=True) for x in (patch, target, base))
    if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
           for a, b in ((patch, target), (patch, base), (target, base))):
        raise StrippedError('Patch, pristine installation and Steam base must be independent directories')
    if not 1 <= timeout <= 120 or not 1 <= retries <= 20 or max_cdn_bytes <= 0 or max_total_cdn_bytes <= 0:
        raise StrippedError('Invalid CDN safety limits')
    sources = _source_contents(tuple(source_patches), (patch, target, base))
    before_target = fingerprint.snapshot(target, all_cache=full_source_hash)
    before_base = fingerprint.snapshot(base, all_cache=full_source_hash)
    pristine_exe = w._find_target_exe(target)
    with pristine_exe.open('rb') as file:
        before_exe_sha256 = hashlib.file_digest(file, 'sha256').digest()
    oodle = w.Oodle(Path(w.__file__).resolve().parent)
    ti = w.scan_cache(w.find_cache_windows_dir(target))
    bi = w.scan_cache(w.find_cache_windows_dir(base))
    validate_patch_identity(patch, target, oodle, ti)
    assets = installed_stripped(target, oodle, ti)
    from installed_type_resolver import prepare
    resolver = prepare(w._find_target_exe(target), ti, oodle, required=True)
    root = patch / 'OpenWF' / 'Content'
    typed_assets = [(asset, _expected_type(asset, ti, bi, oodle, resolver))
        for asset in assets]
    pending = [(asset, type_id) for asset, type_id in typed_assets
        if _existing_asset(root, asset, oodle, type_id) is None]
    print(f'[Stripped] {len(assets):,} declared; {len(assets)-len(pending):,} already verified; '
          f'{len(pending):,} exact objects to add')
    if not pending:
        return dict(total=len(assets), already=len(assets), added=0, would_add=0,
            dry_run=dry_run, local=0, source=0, source_bytes=0,
            cdn=0, cdn_bytes=0, unresolved=0, unresolved_assets=[],
            provenance=[])
    from installed_type_resolver import evidence_for_asset
    staging = Path(tempfile.mkdtemp(prefix='.wf-stripped-', dir=patch.parent))
    staged = []
    added = []
    created_dirs: set[Path] = set()
    local = reused = reused_bytes = downloaded = download_bytes = reserved_bytes = 0
    provenance = []
    unresolved_assets = []
    cdn_attempts: list[dict] = attempt_history if attempt_history is not None else []
    def reserve_attempt(_attempt: int, size: int) -> None:
        nonlocal reserved_bytes
        # Reserve a full expected payload for EVERY attempt, including failed
        # and corrupt downloads, so repeated GETs cannot evade the total cap.
        if reserved_bytes + size > max_total_cdn_bytes:
            raise StrippedError('Total exact-CDN retry download budget exceeded')
        reserved_bytes += size
    try:
        for i, (asset, cdn_type) in enumerate(pending, 1):
            source = None
            for label, index in (('pristine', ti), ('base', bi)):
                try:
                    selected = w._select_h_by_hash(index, asset.namespace, asset.logical_path,
                        asset.manifest_hash, oodle,
                        required_piece_kinds=w._required_piece_kinds(asset.flags))
                    source = (label, index, selected)
                    break
                except w.SourceCoverageError:
                    continue
            # Resolve type independently from the original installation/native
            # metadata; never trust a source patch's filename as type evidence.
            # Validate both Windows paths before performing any possible CDN GET.
            destination = w._safe_output_path(root, asset.namespace, asset.logical_path, cdn_type, asset.hash_b64)
            _require_regular_path(destination, root)
            if destination.exists() or destination.is_symlink() or not destination.resolve().is_relative_to(root.resolve()):
                raise StrippedError(f'Refusing to use unsafe or existing CDN path: {destination}')
            w._validate_windows_export_path(destination, atomic=True)
            scratch = w._safe_output_path(staging, asset.namespace, asset.logical_path, cdn_type, asset.hash_b64)
            _require_regular_path(scratch, staging)
            w._validate_windows_export_path(scratch, atomic=True)
            raw = None
            if source is not None:
                label, index, selected = source
                _h, _header, header_type = selected
                confirmed_type, _evidence = w.resolve_common_header_type(
                    asset, header_type, {}, allow_bundled=False,
                    installed_type=evidence_for_asset(resolver, asset, header_type))
                if confirmed_type != cdn_type:
                    raise StrippedError(f'Internal CDN type disagreement: {asset.namespace}{asset.logical_path}')
                try:
                    raw, final_type, _package, _type_source = w._build_object_for_asset(
                        asset, index, oodle, installed_resolver=resolver,
                        allow_bundled_types=False)
                    if cdn_type != final_type:
                        raise StrippedError(f'Internal CDN type disagreement: {asset.namespace}{asset.logical_path}')
                    method = 'local-' + label
                    piece_check = 'original-cache'
                except w.CdnSizeMismatchError:
                    print_warning(f'Local CDN encoding does not match U44 manifest size: '
                        f'{asset.namespace}{asset.logical_path}')
            # Prefer supplied older exact objects BEFORE contacting a live CDN.
            if raw is None:
                match = _exact_source_object(asset, cdn_type, sources, oodle, ti, bi)
                if match is not None:
                    raw, source_path, piece_check = match
                    method = 'source-patch:' + str(source_path)
            if raw is None:
                if not allow_cdn:
                    if dry_run:
                        unresolved_assets.append({'namespace': asset.namespace,
                            'logical_path': asset.logical_path,
                            'manifest_hash': asset.hash_b64})
                        print_warning(f'No exact offline source for '
                            f'{asset.namespace}{asset.logical_path}')
                        continue
                    raise StrippedError(f'No locally reconstructed or source-patch object for '
                        f'{asset.namespace}{asset.logical_path}; '
                        'use --cdn-fallback to try its exact U44.0.0 CDN URL')
                print_warning(f'No exact offline object for {asset.namespace}{asset.logical_path}; '
                    'trying original-manifest CDN identity')
                attempts: list[dict] = []
                def validate_candidate(data: bytes):
                    w.atomic_write(scratch, data)
                    _verify_asset(scratch, asset, oodle, cdn_type)
                    return _crosscheck_installed_pieces(asset, data, ti, bi, oodle)
                try:
                    raw = _download_exact(asset, cdn_type, oodle, timeout, max_cdn_bytes,
                        retries=retries, verify_func=validate_candidate,
                        attempts_log=attempts, before_attempt=reserve_attempt)
                except StrippedError:
                    # Local safety-limit or authorization errors are not
                    # recoverable asset gaps, even in check-only mode.
                    raise
                except (w.ExportError, OSError, TimeoutError) as exc:
                    if not dry_run:
                        raise
                    unresolved_assets.append({'namespace': asset.namespace,
                        'logical_path': asset.logical_path,
                        'manifest_hash': asset.hash_b64,
                        'reason': f'{type(exc).__name__}: {exc}'})
                    print_warning(f'Exact CDN object could not be validated: '
                        f'{asset.namespace}{asset.logical_path} | {exc}')
                    continue
                finally:
                    cdn_attempts.append({'namespace': asset.namespace, 'logical_path': asset.logical_path,
                        'attempts': attempts})
                download_bytes += len(raw)
                method = 'historical-cdn-exact-id'
                piece_check = _crosscheck_installed_pieces(asset, raw, ti, bi, oodle)
            w.atomic_write(scratch, raw)
            _verify_asset(scratch, asset, oodle, cdn_type)
            staged.append((scratch, destination, asset, cdn_type))
            if method == 'historical-cdn-exact-id':
                print(f'{color_label("Verified")} Exact stripped CDN object | {asset.namespace}{asset.logical_path}')
            provenance.append({'namespace': asset.namespace, 'logical_path': asset.logical_path,
                'manifest_hash': asset.hash_b64, 'cdn_type': f'{cdn_type:X}',
                'sha256': hashlib.sha256(raw).hexdigest(),
                'method': method, 'piece_check': piece_check})
            if method.startswith('local-'):
                local += 1
            elif method.startswith('source-patch:'):
                reused += 1
                reused_bytes += len(raw)
            else:
                downloaded += 1
            if i % 25 == 0 or i == len(pending):
                print(f'[Stripped] {i:,}/{len(pending):,} staged and deeply verified')
        # Source integrity must still hold BEFORE any mutation of patch output.
        for source, baseline in ((target, before_target), (base, before_base)):
            counts = fingerprint.compare(baseline, fingerprint.snapshot(source, all_cache=full_source_hash))['counts']
            if any(counts.get(k, 0) for k in ('added', 'removed', 'content_changed', 'stat_changed_unhashed')):
                raise StrippedError(f'Original source cache changed during stripped-asset reconstruction: {source}')
        with pristine_exe.open('rb') as file:
            after_exe_sha256 = hashlib.file_digest(file, 'sha256').digest()
        if before_exe_sha256 != after_exe_sha256:
            raise StrippedError('Pristine reference executable changed during enrichment; patch unchanged')
        if dry_run:
            print(f'[Stripped] Check-only complete: {len(staged):,} verified, '
                  f'{len(unresolved_assets):,} unresolved; patch unchanged')
            return dict(total=len(assets), already=len(assets)-len(pending),
                added=0, would_add=len(staged), dry_run=True,
                local=local, source=reused, source_bytes=reused_bytes,
                cdn=downloaded, cdn_bytes=download_bytes, provenance=provenance,
                unresolved=len(unresolved_assets), unresolved_assets=unresolved_assets,
                cdn_reserved_bytes=reserved_bytes, cdn_attempts=cdn_attempts)
        for src, dest, asset, cdn_type in staged:
            _require_regular_path(dest, root)
            if dest.exists() or dest.is_symlink() or not dest.resolve().is_relative_to(root.resolve()):
                raise StrippedError(f'Patch object appeared or directory became unsafe: {dest}')
            # Remember only folders created by this invocation. A failure
            # must not leave empty namespace/path scaffolding in the user's
            # existing, previously working patch.
            ancestor = dest.parent
            missing_dirs = []
            while not ancestor.exists() and not ancestor.is_symlink():
                if not ancestor.resolve().is_relative_to(root.resolve()):
                    raise StrippedError(f'Unsafe destination parent: {ancestor}')
                missing_dirs.append(ancestor)
                ancestor = ancestor.parent
            created_dirs.update(missing_dirs)
            dest.parent.mkdir(parents=True, exist_ok=True)
            # Exclusive create: avoid race-induced overwrite from another process.
            with src.open('rb') as input_file, dest.open('xb') as output_file:
                added.append(dest)
                shutil.copyfileobj(input_file, output_file)
            # Verify bytes on the final filesystem too, not just staging.
            _verify_asset(dest, asset, oodle, cdn_type)
            if hashlib.sha256(src.read_bytes()).digest() != hashlib.sha256(dest.read_bytes()).digest():
                raise StrippedError(f'New CDN object changed during copy: {dest}')
        return dict(total=len(assets), already=len(assets)-len(pending),
            added=len(pending), would_add=len(pending), dry_run=False,
            local=local, source=reused, source_bytes=reused_bytes,
            cdn=downloaded, cdn_bytes=download_bytes, provenance=provenance,
            unresolved=0, unresolved_assets=[],
            cdn_reserved_bytes=reserved_bytes, cdn_attempts=cdn_attempts)
    except BaseException:
        for path in reversed(added):
            path.unlink(missing_ok=True)
        # Only directories created by this run, and only if still empty.
        # Never remove pre-existing folders or unrelated user content.
        for directory in sorted(created_dirs, key=lambda p: len(p.parts), reverse=True):
            try:
                directory.rmdir()
            except OSError:
                pass
        raise
    finally:
        shutil.rmtree(staging)
