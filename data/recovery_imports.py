"""Fail-closed offline collectors for recovered CDN, H-only, and U44.0.1 objects.

Each collection revalidates the exact target manifest identity and its local
payload; these classes do not make network requests.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import recover_missing_cdn as recovery
import recover_missing_cdn as videos
import recover_remaining_h_only as hrec
import recover_remaining_h_only as honly
import compare_u4401_sources as compare
import warframe_install_to_patch as w

# ---- recovered_cdn_import ----
class RecoveredCdnCollection:
    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise w.ExportError(f'Recovery source is not a directory: {root}')
        report_path = self.root / 'cdn-recovery-v0.1.json'
        try:
            doc = json.loads(report_path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise w.ExportError(f'Cannot read recovery report: {exc}') from exc
        if not isinstance(doc, dict) or doc.get('version') != w.VERSION:
            raise w.ExportError('Expected a CDN recovery report')
        rows = doc.get('objects')
        totals = doc.get('summary')
        if not isinstance(rows, list) or not isinstance(totals, dict) or not rows:
            raise w.ExportError('Recovery report has no objects or no summary')
        if (totals.get('selected') != len(rows) or
            totals.get('recovered_validated') != len(rows) or
            totals.get('failed') != 0):
            raise w.ExportError('Recovery report is incomplete; only fully validated reports are accepted')
        self.rows = {}
        total_bytes = 0
        seen_casefold = set()
        for row in rows:
            if not isinstance(row, dict) or row.get('status') != 'recovered-validated':
                raise w.ExportError('Recovery report contains an unverified object')
            namespace = row.get('namespace')
            logical_path = row.get('logical_path')
            if namespace != '0' or not isinstance(logical_path, str) or not logical_path.lower().endswith('.bk2'):
                raise w.ExportError('Unexpected CDN recovery namespace or logical path')
            w._validate_logical_path(logical_path)
            key = (namespace, logical_path)
            if key in self.rows or (namespace.casefold(), logical_path.casefold()) in seen_casefold:
                raise w.ExportError('Duplicate/case-conflicting object in recovery report')
            seen_casefold.add((namespace.casefold(), logical_path.casefold()))
            if not isinstance(row.get('sha256'), str) or len(row['sha256']) != 64:
                raise w.ExportError('Missing SHA-256 in recovery report')
            try:
                int(row['sha256'], 16)
            except ValueError as exc:
                raise w.ExportError('Non-hex SHA-256 in recovery report') from exc
            if (type(row.get('expected_cdn_size_bytes')) is not int or
                row['expected_cdn_size_bytes'] < 40 or
                row['expected_cdn_size_bytes'] > recovery.MAX_ITEM_BYTES):
                raise w.ExportError('Unexpected recovered CDN byte length')
            total_bytes += row['expected_cdn_size_bytes']
            if total_bytes > recovery.MAX_TOTAL_BYTES:
                raise w.ExportError('Recovery input exceeds the maximum total byte budget')
            self.rows[key] = row

    def _expected_file(self, row: dict, asset: w.ManifestAsset) -> Path:
        canonical = w._safe_output_path(
            self.root / 'OpenWF' / 'Content', asset.namespace, asset.logical_path, 0xAA, asset.hash_b64)
        relative = canonical.relative_to(self.root).as_posix()
        if row.get('relative_path') != relative:
            raise w.ExportError(f'Recovery filename/type/hash does not match current manifest: {asset.namespace}{asset.logical_path}')
        if not canonical.is_file() or canonical.is_symlink() or not canonical.resolve().is_relative_to(self.root):
            raise w.ExportError(f'Recovered asset missing, a symlink or outside the source folder: {relative}')
        return canonical

    def validate_asset(self, asset: w.ManifestAsset, oodle: w.Oodle) -> bytes | None:
        row = self.rows.get((asset.namespace, asset.logical_path))
        if row is None:
            return None
        if (asset.section != 'stripped' or asset.flags != (w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F) or
                not asset.logical_path.lower().endswith('.bk2')):
            raise w.ExportError(f'Recovered video does not have expected H+F stripped flags: {asset.namespace}{asset.logical_path}')
        if row['expected_cdn_size_bytes'] != asset.cdn_size:
            raise w.ExportError(f'Recovery size differs from current manifest: {asset.namespace}{asset.logical_path}')
        path = self._expected_file(row, asset)
        if path.stat().st_size != asset.cdn_size:
            raise w.ExportError(f'Recovered asset length differs from manifest: {asset.namespace}{asset.logical_path}')
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise w.ExportError(f'Failed to read recovered asset {path}: {exc}') from exc
        if len(data) != asset.cdn_size:
            raise w.ExportError(f'Recovered asset length differs from manifest: {asset.namespace}{asset.logical_path}')
        if hashlib.sha256(data).hexdigest().lower() != row['sha256'].lower():
            raise w.ExportError(f'Recovered asset SHA-256 differs from recovery report: {asset.namespace}{asset.logical_path}')
        manifest_row = {'expected_cdn_size_bytes': asset.cdn_size, 'expected_hash_base64': asset.hash_b64}
        try:
            check = recovery.validate_cdn_payload(data, manifest_row, oodle)
        except (w.ExportError, ValueError) as exc:
            raise w.ExportError(f'Recovered CDN structure/hash validation failed: {asset.namespace}{asset.logical_path}: {exc}') from exc
        if check['sha256'].lower() != row['sha256'].lower():
            raise w.ExportError('Unexpected SHA-256 disagreement during recovered asset validation')
        return data

# ---- recovered_h_only_import ----
class RecoveredHOnlyCollection:
    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise w.ExportError('H-only recovery source is not a directory')
        report = self.root / hrec.REPORT_NAME
        try:
            doc = json.loads(report.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise w.ExportError('Cannot read H-only recovery report') from exc
        if doc.get('version') != hrec.VERSION or doc.get('kind') != 'h-only-cdn-recovery':
            raise w.ExportError('Expected an H-only recovery report')
        rows = doc.get('objects')
        counts = doc.get('summary')
        if not isinstance(rows, list) or not isinstance(counts, dict) or not rows:
            raise w.ExportError('Missing H-only recovery objects')
        if (counts.get('selected') != len(rows) or counts.get('recovered_validated') != len(rows)
                or counts.get('failed') != 0 or len(rows) > hrec.MAX_ASSETS):
            raise w.ExportError('H-only recovery report incomplete; refused')
        self.rows = {}
        for row in rows:
            if not isinstance(row, dict) or row.get('status') != 'recovered-validated':
                raise w.ExportError('Unverified H-only object in recovery report')
            key = (row.get('namespace'), row.get('logical_path'), row.get('expected_hash_base64'),
                   row.get('expected_cdn_size_bytes'))
            if key not in hrec.KNOWN_TARGETS or row.get('manifest_flags') != '0x20000000':
                raise w.ExportError('Unknown or mismatched U44 H-only recovery object')
            identity = key[:2]
            if identity in self.rows:
                raise w.ExportError('Duplicate H-only recovery asset')
            type_hex = row.get('cdn_type_hex')
            if not isinstance(type_hex, str) or not type_hex or len(type_hex) > 4:
                raise w.ExportError('Invalid recovered H-only type')
            try:
                type_id = int(type_hex, 16)
            except ValueError as exc:
                raise w.ExportError('Invalid H-only type hex') from exc
            if not 0 < type_id <= 0xFFFF or f'{type_id:X}' != type_hex:
                raise w.ExportError('Noncanonical H-only type ID')
            digest = row.get('sha256')
            if not isinstance(digest, str) or len(digest) != 64:
                raise w.ExportError('Missing recovery SHA-256')
            try:
                int(digest, 16)
            except ValueError as exc:
                raise w.ExportError('Nonhex recovery SHA-256') from exc
            self.rows[identity] = row

    def validate_asset(self, asset: w.ManifestAsset, oodle) -> tuple[bytes, int] | None:
        row = self.rows.get((asset.namespace, asset.logical_path))
        if row is None:
            return None
        key = (asset.namespace, asset.logical_path, asset.hash_b64, asset.cdn_size)
        if key not in hrec.KNOWN_TARGETS or asset.section != 'stripped' or asset.flags != w.MANIFEST_FLAG_H:
            raise w.ExportError('Recovered H-only entry differs from current target manifest')
        type_id = int(row['cdn_type_hex'], 16)
        canonical = w._safe_output_path(self.root / 'OpenWF' / 'Content', asset.namespace,
                                        asset.logical_path, type_id, asset.hash_b64)
        expected_relative = canonical.relative_to(self.root).as_posix()
        if row.get('relative_path') != expected_relative:
            raise w.ExportError('Recovered H-only filename does not match manifest')
        if not canonical.is_file() or canonical.is_symlink() or not canonical.resolve().is_relative_to(self.root):
            raise w.ExportError('Recovered H-only file missing, symlinked or escaped recovery root')
        if canonical.stat().st_size != asset.cdn_size:
            raise w.ExportError('Recovered H-only file size changed')
        data = canonical.read_bytes()
        if hashlib.sha256(data).hexdigest().lower() != row['sha256'].lower():
            raise w.ExportError('Recovered H-only SHA-256 differs from its recovery report')
        checks = hrec.validate_h_only_payload(data, row, type_id, oodle)
        if checks['sha256'].lower() != row['sha256'].lower():
            raise w.ExportError('H-only SHA-256 changed during validation')
        return data, type_id

# ---- u4401_exact_import ----
REPORT_NAME = f'u44-0-1-shared-assets-v{w.VERSION}.json'

class U4401ExactCollection:
    def __init__(self, source_patch: Path, report_path: Path | None = None):
        self.content = compare.safe_patch_content(source_patch)
        self.root = self.content.parent.parent
        source_report = (report_path if report_path is not None
                         else Path(__file__).resolve().parent / REPORT_NAME)
        try:
            doc = json.loads(source_report.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise w.ExportError(f'Cannot read U44.0.1 comparison report: {exc}') from exc
        if (doc.get('kind') != compare.PROBE_KIND or doc.get('version') != w.VERSION
                or Path(doc.get('source_patch', '')).resolve() != self.root.resolve()):
            raise w.ExportError('U44.0.1 report does not belong to the supplied source patch')
        records = doc.get('objects')
        summary = doc.get('summary')
        if not isinstance(records, list) or len(records) != 103 or not isinstance(summary, dict):
            raise w.ExportError('Expected complete 103-object U44.0.1 comparison report')
        self.rows: dict[tuple[str, str], dict] = {}
        distinct = set()
        absent = 0
        for row in records:
            if not isinstance(row, dict):
                raise w.ExportError('Invalid U44.0.1 report row')
            ns, logical = row.get('namespace'), row.get('logical_path')
            if ns != '0' or not isinstance(logical, str):
                raise w.ExportError('Unexpected namespace or logical path in U44.0.1 report')
            w._validate_logical_path(logical)
            key = (ns.casefold(), logical.casefold())
            if key in distinct:
                raise w.ExportError('Duplicate U44.0.1 report asset')
            distinct.add(key)
            status = row.get('status')
            if status == 'exact-object-absent':
                absent += 1
                continue
            if status != 'exact-object-verified':
                raise w.ExportError(f'Unverified U44.0.1 report entry: {logical}: {status}')
            digest = row.get('actual_sha256')
            if not isinstance(digest, str) or len(digest) != 64:
                raise w.ExportError(f'Missing SHA-256 for U44.0.1 asset: {logical}')
            try:
                bytes.fromhex(digest)
            except ValueError as exc:
                raise w.ExportError('Nonhex U44.0.1 SHA-256') from exc
            type_hex = row.get('u44_0_0_type')
            if not (type_hex == 'AA' if logical.lower().endswith('.bk2') else type_hex == 'D2'):
                raise w.ExportError(f'Unexpected U44.0.1 asset type for {logical}')
            if not isinstance(row.get('u44_0_0_hash'), str) or type(row.get('expected_bytes')) is not int:
                raise w.ExportError('Missing manifest identity in U44.0.1 report')
            self.rows[(ns, logical)] = row
        if (len(self.rows) != 100 or absent != 3
                or summary.get('exact_objects_verified') != 100
                or summary.get('exact_objects_absent') != 3
                or summary.get('exact_objects_rejected') != 0
                or summary.get('remaining_not_verified') != 3):
            raise w.ExportError('U44.0.1 comparison totals disagree or source coverage changed')

    def validate_asset(self, asset: w.ManifestAsset, oodle: w.Oodle) -> tuple[bytes, int] | None:
        row = self.rows.get((asset.namespace, asset.logical_path))
        if row is None:
            return None
        type_id = 0xAA if asset.logical_path.lower().endswith('.bk2') else 0xD2
        if (asset.section != 'stripped' or asset.flags != (w.MANIFEST_FLAG_H | w.MANIFEST_FLAG_F
                if type_id == 0xAA else w.MANIFEST_FLAG_H)
                or asset.hash_b64 != row['u44_0_0_hash'] or asset.cdn_size != row['expected_bytes']
                or row['u44_0_0_type'] != f'{type_id:X}'):
            raise w.ExportError(f'U44.0.1 source no longer matches U44.0.0 manifest: {asset.logical_path}')
        if type_id == 0xD2 and (asset.namespace, asset.logical_path, asset.hash_b64, asset.cdn_size) not in honly.KNOWN_TARGETS:
            raise w.ExportError('Unrecognized U44.0.0 H-only resource')
        path = w._safe_output_path(self.content, asset.namespace, asset.logical_path,
                                   type_id, asset.hash_b64)
        if (row.get('expected_relative_path') != path.relative_to(self.root).as_posix()
                or path.is_symlink() or not path.is_file()
                or not path.resolve().is_relative_to(self.content.resolve())):
            raise w.ExportError(f'U44.0.1 source path changed/escaped: {asset.logical_path}')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest().lower() != row['actual_sha256'].lower():
            raise w.ExportError(f'U44.0.1 source SHA-256 changed: {asset.logical_path}')
        manifest_row = {'expected_cdn_size_bytes': asset.cdn_size, 'expected_hash_base64': asset.hash_b64}
        if type_id == 0xAA:
            checked = videos.validate_cdn_payload(raw, manifest_row, oodle)
        else:
            checked = honly.validate_h_only_payload(raw, manifest_row, type_id, oodle)
        if checked['sha256'].lower() != row['actual_sha256'].lower():
            raise w.ExportError('U44.0.1 source SHA-256 validation disagreement')
        return raw, type_id
