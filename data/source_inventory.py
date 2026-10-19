#!/usr/bin/env python3
"""Inventory and validate missing manifest objects from pristine installations."""
from __future__ import annotations

import json
from pathlib import Path

import inspect_missing_source as missing_mod
import inspect_unresolved_content as triage
import recover_missing_cdn as video
import warframe_install_to_patch as w

SOURCE_SNAPSHOT_NAME = 'workspace-source-snapshot-v0.1.json'

def save_report(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    w.atomic_write(path, (json.dumps(doc, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))

def source_snapshot(target: Path, base: Path) -> dict:
    """Fast, conservative source-change guard for reusable cache inventory reports.

    This captures metadata of every package TOC/payload, not a cryptographic
    checksum; it detects ordinary installation/cache modifications between
    recovery attempts without rehashing hundreds of gigabytes of source data.
    """
    def snapshot_one(root: Path) -> dict:
        cache = w.find_cache_windows_dir(root).resolve()
        if not cache.is_dir():
            raise w.ExportError(f'Cache.Windows folder missing: {cache}')
        stats = []
        for entry in sorted(cache.iterdir(), key=lambda item: item.name.casefold()):
            if entry.suffix.lower() not in {'.toc', '.cache'}:
                continue
            if entry.is_symlink() or not entry.is_file():
                raise w.ExportError(f'Cache source is not an ordinary file: {entry}')
            info = entry.stat()
            stats.append([entry.name, info.st_size, info.st_mtime_ns])
        if not stats:
            raise w.ExportError(f'No TOC/cache files in source: {cache}')
        return {'path': str(cache), 'files': stats}

    result = {'version': w.VERSION, 'target_cache': snapshot_one(target),
        'base_cache': snapshot_one(base)}
    exe = w._find_target_exe(target)
    st = exe.stat()
    result['target_exe'] = [str(exe.resolve()), st.st_size, st.st_mtime_ns]
    return result

def load_manifest_inventory(target: Path, base: Path, workspace: Path) -> tuple[dict, list[dict]]:
    miss_path = workspace / 'missing-source-v0.1.json'
    base_path = workspace / 'base-inheritance-v0.1.json'
    snapshot_path = workspace / SOURCE_SNAPSHOT_NAME
    current_snapshot = source_snapshot(target, base)
    if miss_path.is_file() and base_path.is_file():
        if not snapshot_path.is_file():
            raise w.ExportError('Existing inventory has no input-source snapshot. Use a new workspace to safely rescan.')
        if json.loads(snapshot_path.read_text(encoding='utf-8')) != current_snapshot:
            raise w.ExportError('Installed target/Steam base changed since cached reports were created. Use a new workspace.')
        missing = json.loads(miss_path.read_text(encoding='utf-8'))
        inherited = json.loads(base_path.read_text(encoding='utf-8'))
        if (Path(missing.get('target_cache', '')).resolve() != w.find_cache_windows_dir(target).resolve()
                or Path(missing.get('base_cache', '')).resolve() != w.find_cache_windows_dir(base).resolve()
                or Path(inherited.get('base_cache', '')).resolve() != w.find_cache_windows_dir(base).resolve()):
            raise w.ExportError('Existing workspace reports belong to different installation paths')
    else:
        if miss_path.exists() or base_path.exists():
            raise w.ExportError('Incomplete manifest report pair in workspace. Use a new workspace for a fresh scan')
        print('[1/5] Inventory target manifest assets and independently validate base inheritance')
        missing = missing_mod.analyze(target, base, progress_every=25000)
        inherited = missing_mod.verify_base_inheritance(missing, base)
        if inherited['summary']['base_read_error']:
            raise w.ExportError('Steam base inheritance verification failed')
        if source_snapshot(target, base) != current_snapshot:
            raise w.ExportError('Source cache changed during inventory scan; refusing stale results.')
        save_report(miss_path, missing)
        save_report(base_path, inherited)
        save_report(snapshot_path, current_snapshot)
    if source_snapshot(target, base) != current_snapshot:
        raise w.ExportError('Source cache changed while validating reusable reports.')
    counts = inherited['summary']
    if counts['source_missing_in_target'] != len(missing['missing_objects']):
        raise w.ExportError('Input manifest and base inventory counts disagree')
    if counts['base_read_error']:
        raise w.ExportError('Base H/B/F verification had read errors')
    remaining = triage._validate_report_inputs(missing, inherited)
    if counts['not_fully_in_base'] != len(remaining):
        raise w.ExportError('Unresolved resource count differs from base verification')
    print(f"[Sources] {counts['source_missing_in_target']} absent from target; "
          f"{counts['verified_in_base']} inherited; {len(remaining)} require source recovery")
    validate_recovery_inventory(remaining)
    return triage.summarize(remaining, missing, inherited), remaining

def validate_recovery_inventory(rows: list[dict]) -> None:
    """Validate target-manifest recovery identities, not a build-specific list."""
    seen = set()
    budget = 0
    for row in rows:
        namespace, logical = row['namespace'], row['logical_path']
        w._validate_manifest_namespace(namespace)
        key = (namespace.casefold(), logical.casefold())
        if key in seen:
            raise w.ExportError(f'Duplicate or case-conflicting recovery object: {namespace}{logical}')
        seen.add(key)
        w._validate_logical_path(logical)
        if row['manifest_section'] != 'stripped' or not row['manifest_flags'].startswith('0x'):
            raise w.ExportError(f'Unsupported missing manifest section: {namespace}{logical}')
        flags = int(row['manifest_flags'], 16)
        required = list(w._required_piece_kinds(flags))
        if required != row['required_pieces']:
            raise w.ExportError(f'Inconsistent manifest H/B/F flags: {namespace}{logical}')
        if flags not in (w.MANIFEST_FLAG_H, w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F):
            raise w.ExportError(f'Recovery does not yet support this H/B/F combination: {namespace}{logical}')
        if logical.lower().endswith('.bk2') != (flags == w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F):
            raise w.ExportError(f'Unrecognized video/resource flag combination: {namespace}{logical}')
        size = row['expected_cdn_size_bytes']
        if type(size) is not int or not 40 <= size <= video.MAX_ITEM_BYTES:
            raise w.ExportError(f'Recovery object is outside the safe byte limit: {namespace}{logical}')
        budget += size
        if budget > video.MAX_TOTAL_BYTES:
            raise w.ExportError('Recovery exceeds the maximum total byte budget')

