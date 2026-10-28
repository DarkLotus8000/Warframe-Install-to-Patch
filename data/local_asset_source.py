"""Read-only discovery of explicitly supplied manifest-addressed local assets."""
from pathlib import Path
import os
import re
import stat

import warframe_install_to_patch as w

def _linked(path: Path) -> bool:
    info = path.lstat()
    return path.is_symlink() or bool(getattr(info, 'st_file_attributes', 0) &
        getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))

class LocalAssetSource:
    """Filenames locate candidates; the recovery pipeline validates their bytes."""

    def __init__(self, root: Path):
        if _linked(root):
            raise w.ExportError('Local asset root must not be a link')
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise w.ExportError('Local asset source must be a directory')
        self.entries = {}
        count = 0
        def fail(exc):
            raise exc
        for directory, dirs, files in os.walk(self.root, followlinks=False, onerror=fail):
            for name in dirs + files:
                path = Path(directory) / name
                count += 1
                if count > 100_000:
                    raise w.ExportError('Local asset source exceeds 100,000 entries')
                if _linked(path):
                    raise w.ExportError(f'Linked local asset source entry: {path}')
            for name in files:
                match = re.fullmatch(r'(.+)!([0-9A-Fa-f]{1,4})_([A-Za-z0-9+\-]{22})', name)
                if match:
                    stem, type_hex, digest = match.groups()
                    self.entries.setdefault((stem.casefold(), digest), []).append(
                        (int(type_hex, 16), Path(directory) / name))

    def candidates(self, row: dict) -> list[tuple[int, Path]]:
        return self.entries.get((Path(row['logical_path']).name.casefold(),
            row['expected_hash_base64']), [])

    def read(self, path: Path, expected_bytes: int) -> bytes:
        if not path.resolve(strict=True).is_relative_to(self.root):
            raise w.ExportError('Local asset escaped the source directory')
        for part in (path, *path.parents):
            if _linked(part):
                raise w.ExportError('Local asset path became a link')
            if part == self.root:
                break
        if not path.is_file():
            raise w.ExportError('Local asset must be an ordinary file')
        with path.open('rb') as handle:
            before = os.fstat(handle.fileno())
            if before.st_size != expected_bytes:
                raise w.ExportError('Local asset size differs from manifest')
            raw = handle.read(expected_bytes + 1)
            after = os.fstat(handle.fileno())
        if len(raw) != expected_bytes or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise w.ExportError('Local asset changed while reading')
        return raw
