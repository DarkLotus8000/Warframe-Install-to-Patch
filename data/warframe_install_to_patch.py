#!/usr/bin/env python3
from __future__ import annotations

from common import StrictArgumentParser, VERSION, error as print_error, warning as print_warning

import argparse
import base64
import ctypes
import hashlib
import json
import os
import re
import shutil
import struct
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

OODLE_DLL_NAME = "oo2core_9.dll"
OODLE_X64_SHA256 = "19452ae1abae65e1305d3818354d4fae7b1200294322f0d9c6d5ddeb7bd9f978"
OODLE_X64_SIZE = 582656
SHCC_PREAMBLE = b"SHCC\x1F\x00\x00\x00"
H_CACHE_SENTINEL_HASH = "---------------------w"
SUPPORTED_MANIFEST_VERSION = 14
MANIFEST_INFO_SIZE_MASK = 0x1FFFFFFF
MANIFEST_FLAG_H = 0x20000000
MANIFEST_FLAG_B = 0x40000000
MANIFEST_FLAG_F = 0x80000000
MANIFEST_FLAGS_MASK = MANIFEST_FLAG_H | MANIFEST_FLAG_B | MANIFEST_FLAG_F
TOC_MAGIC = 0x1867C64E
TOC_VERSIONS = {16, 20}
TOC_ENTRY = struct.Struct("<qqiiii64s")
MANIFEST_SECTION_NAMES = ("service", "packed", "stripped")

H_CACHE_B_CACHE_RE = re.compile(
    r"^/B\.Cache\.(?P<kind>Windows|Dx11(?!_)|Dx12(?!_))"
    r"(?P<suffix>_[A-Za-z0-9]+)?\.bin$"
)

try:
    import google_crc32c as _google_crc32c  # type: ignore
except (ImportError, OSError):
    _google_crc32c = None

class ExportError(RuntimeError):
    pass

class SourceCoverageError(ExportError):
    pass

def _missing_required_manifest_families(records, available_paths, requested):
    """Validate a declared installed configuration, never silently omit its families."""
    requested = tuple(requested)
    if not requested:
        return ()
    if len(requested) != len(set(requested)):
        raise ExportError('Duplicate --required-manifest-family argument')
    listed = {record.logical_path for record in records}
    for path in requested:
        if not H_CACHE_B_CACHE_RE.fullmatch(path) or path not in listed:
            raise ExportError(f'Required manifest family is not listed in target H.Cache: {path}')
    present = set(available_paths)
    return tuple(path for path in requested if path not in present)

class CdnSizeMismatchError(ExportError):
    pass

@dataclass(frozen=True, slots=True)
class CacheEntry:
    kind: str
    package: str
    namespace: str
    cache_path: Path
    logical_path: str
    offset: int
    compressed_len: int
    length: int

@dataclass(frozen=True, slots=True)
class HCacheRecord:
    logical_path: str
    target_hash: bytes
    info: int

@dataclass(frozen=True, slots=True)
class HCacheIndex:
    version: int
    records: tuple[HCacheRecord, ...]

@dataclass(frozen=True, slots=True)
class ManifestAsset:
    namespace: str
    section: str
    logical_path: str
    manifest_hash: bytes
    info: int

    @property
    def hash_b64(self) -> str:
        return b64m_encode(self.manifest_hash)

    @property
    def cdn_size(self) -> int:
        return self.info & MANIFEST_INFO_SIZE_MASK

    @property
    def flags(self) -> int:
        return self.info & MANIFEST_FLAGS_MASK

@dataclass(frozen=True, slots=True)
class TypeEvidence:
    type_id: int
    strength: str

# U44 DX11 .hlsl asset requests from the live Warframe client were compared
# with the exact matching H hashes in the installed cache and the emitted CDN
# filenames. The same content hash was requested as !27_ for H-header type
# 0x20 (ShaderPermutationDx11) and !2A_ for type 0x23 (ShaderDx11).
# These are *CDN filename IDs*, not alternate encodings of the H header.
# Restrict the correction to observed DX11 shader path families and pairs.
_DX11_SHADER_CDN_TYPES = {0x20: 0x27, 0x23: 0x2A}
_DX11_SHADER_PREFIXES = ("/ee/shaders/", "/lotus/shaders/")

def _observed_cdn_filename_type(asset: ManifestAsset, parsed_type: int | None) -> tuple[int | None, str | None]:
    lower_path = asset.logical_path.casefold()
    if (asset.namespace == "9" and lower_path.endswith(".hlsl")
            and lower_path.startswith(_DX11_SHADER_PREFIXES)
            and parsed_type in _DX11_SHADER_CDN_TYPES):
        return _DX11_SHADER_CDN_TYPES[parsed_type], "dx11-shader-cdn-map"
    return parsed_type, None

def resolve_common_header_type(
    asset: ManifestAsset,
    parsed_type: int | None,
    evidence: dict[tuple[str, str, str], TypeEvidence] | None = None,
    *,
    installed_type: TypeEvidence | None = None,
) -> tuple[int, str | None]:
    """Resolve the CDN filename type, which may differ from the H-header type.

    Two U44 DX11 shader header-to-CDN pairs are supported by exact-hash client
    requests. For verified U44.0.0, an independent native/Packages parent ID
    may also be supplied. All conflicting evidence fails closed.
    """
    key = (asset.namespace, asset.logical_path, asset.hash_b64)
    supplied = (evidence or {}).get(key)
    filename_type, mapping_source = _observed_cdn_filename_type(asset, parsed_type)
    reported = [("installed-cache CDN mapping" if mapping_source else "installed cache", filename_type),
        ("user evidence", supplied.type_id if supplied else None),
        ("installed native parent", installed_type.type_id if installed_type else None)]
    types = {value for _source, value in reported if value is not None}
    if len(types) > 1:
        desc = ", ".join(f"{source}=0x{value:X}" for source, value in reported if value is not None)
        raise ExportError(f"Conflicting CommonHeader types for {asset.namespace}{asset.logical_path}: {desc}")
    if filename_type is not None:
        return filename_type, mapping_source
    if installed_type is not None:
        return installed_type.type_id, installed_type.strength
    if supplied is not None:
        return supplied.type_id, supplied.strength
    raise ExportError(f"Could not recover CommonHeader type for {asset.namespace}{asset.logical_path}; "
        "the installed H entry has no recognized type, and no hash-matched evidence is available")

def load_type_evidence(
    path: Path,
    *,
    allow_cross_version: bool = False,
) -> dict[tuple[str, str, str], TypeEvidence]:
    """Read filename type hints without reading or changing reference patch directories.

    An exact filename hash is stronger than a cross-version path match, but
    neither replaces validation of the target H hash and reconstructed CDN size.
    """
    try:
        with path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ExportError(f"Cannot load type evidence {path}: {exc}") from exc
    if not isinstance(report, dict) or not isinstance(report.get("objects"), list):
        raise ExportError("Type-evidence report must contain an objects array")
    chosen: dict[tuple[str, str, str], TypeEvidence] = {}
    for item in report["objects"]:
        if not isinstance(item, dict):
            raise ExportError("Invalid type-evidence object")
        namespace = item.get("namespace")
        logical_path = item.get("logical_path")
        digest = item.get("manifest_hash_base64")
        status = item.get("status")
        if not isinstance(namespace, str) or not re.fullmatch(r"(?:0(?:_[a-z]{2,3})?|9|A)", namespace):
            raise ExportError("Invalid type-evidence namespace")
        if not isinstance(logical_path, str):
            raise ExportError("Invalid type-evidence logical path")
        _validate_logical_path(logical_path)
        if not isinstance(digest, str) or not re.fullmatch(r"[A-Za-z0-9+_-]{22}", digest):
            raise ExportError(f"Invalid type-evidence hash for {namespace}{logical_path}")
        key = (namespace, logical_path, digest)
        if key in chosen:
            raise ExportError(f"Duplicate type-evidence entry: {namespace}{logical_path}")
        if status in {"conflicting-type-evidence", "no-reference-found"}:
            continue
        if status not in {"exact-hash-type-evidence", "cross-version-hint-only"}:
            raise ExportError(f"Unknown type-evidence status for {namespace}{logical_path}")
        ids = item.get("observed_type_ids")
        refs = item.get("references")
        if not isinstance(ids, list) or len(ids) != 1 or not isinstance(ids[0], str):
            raise ExportError(f"Ambiguous type evidence: {namespace}{logical_path}")
        if not re.fullmatch(r"[0-9A-Fa-f]{1,4}", ids[0]):
            raise ExportError(f"Invalid type ID: {namespace}{logical_path}")
        type_id = int(ids[0], 16)
        if not isinstance(refs, list) or not refs:
            raise ExportError(f"No references for {namespace}{logical_path}")
        confirmed_exact = False
        reference_patches = set()
        for ref in refs:
            if not isinstance(ref, dict) or not isinstance(ref.get("type_id"), str):
                raise ExportError(f"Invalid reference for {namespace}{logical_path}")
            try:
                ref_type = int(ref["type_id"], 16)
            except ValueError as exc:
                raise ExportError(f"Invalid reference type for {namespace}{logical_path}") from exc
            if ref_type != type_id or not 0 <= ref_type <= 0xFFFF:
                raise ExportError(f"Conflicting reference types for {namespace}{logical_path}")
            ref_hash = ref.get("reference_hash_base64")
            ref_exact = ref.get("exact_target_hash")
            patch = ref.get("reference_patch")
            if not isinstance(ref_hash, str) or not isinstance(ref_exact, bool) or not isinstance(patch, str) or not patch:
                raise ExportError(f"Invalid reference fields for {namespace}{logical_path}")
            if ref_exact != (ref_hash == digest):
                raise ExportError(f"Inconsistent reference hash for {namespace}{logical_path}")
            confirmed_exact |= ref_exact
            reference_patches.add(patch.casefold())
        if (status == "exact-hash-type-evidence") != confirmed_exact:
            raise ExportError(f"Type-evidence classification mismatch for {namespace}{logical_path}")
        if confirmed_exact:
            chosen[key] = TypeEvidence(type_id, "exact-hash")
        elif allow_cross_version and len(reference_patches) >= 2:
            chosen[key] = TypeEvidence(type_id, "cross-version")
    return chosen

class OodleCompressOptions(ctypes.Structure):
    """64-bit OodleLZ_CompressOptions ABI. Only used in optional diagnostics.

    The defaults are copied from the pinned Windows Oodle runtime, rather
    than constructing an incomplete native struct from scratch.
    """
    _fields_ = [
        ("unused_was_verbosity", ctypes.c_uint32),
        ("minMatchLen", ctypes.c_int32),
        ("seekChunkReset", ctypes.c_int32),
        ("seekChunkLen", ctypes.c_int32),
        ("profile", ctypes.c_int32),
        ("dictionarySize", ctypes.c_int32),
        ("spaceSpeedTradeoffBytes", ctypes.c_int32),
        ("unused_was_maxHuffmansPerChunk", ctypes.c_int32),
        ("sendQuantumCRCs", ctypes.c_int32),
        ("maxLocalDictionarySize", ctypes.c_int32),
        ("makeLongRangeMatcher", ctypes.c_int32),
        ("matchTableSizeLog2", ctypes.c_int32),
        ("jobify", ctypes.c_int32),
        ("jobifyUserPtr", ctypes.c_void_p),
        ("farMatchMinLen", ctypes.c_int32),
        ("farMatchOffsetLog2", ctypes.c_int32),
        ("reserved", ctypes.c_uint32 * 4),
    ]

class Oodle:
    def __init__(self, script_dir: Path):
        self.script_dir = script_dir
        self._library = None

    def _dll_path(self) -> Path:
        return self.script_dir / OODLE_DLL_NAME

    def _load(self):
        if self._library is not None:
            return self._library
        path = self._dll_path()
        if not path.is_file():
            raise ExportError(
                f"Missing {OODLE_DLL_NAME}. Extract the complete archive including data/oo2core_9.dll; see README.md."
            )
        try:
            size = path.stat().st_size
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise ExportError(f"Could not verify {path}: {exc}") from exc
        if size != OODLE_X64_SIZE or digest.lower() != OODLE_X64_SHA256:
            raise ExportError(
                f"{OODLE_DLL_NAME} does not match the pinned x64 runtime expected by this tool."
            )
        try:
            library = ctypes.CDLL(str(path))
            function = library.OodleLZ_Decompress
            function.argtypes = [
                ctypes.c_void_p, ctypes.c_size_t,
                ctypes.c_void_p, ctypes.c_size_t,
                ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
                ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p,
                ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
            ]
            function.restype = ctypes.c_longlong
        except (OSError, AttributeError) as exc:
            raise ExportError(f"Could not load {path}: {exc}") from exc
        self._library = library
        return library

    def decompress(self, compressed: bytes, expected_size: int) -> bytes:
        library = self._load()
        source = ctypes.create_string_buffer(compressed, len(compressed))
        destination = ctypes.create_string_buffer(expected_size)
        result = int(
            library.OodleLZ_Decompress(
                ctypes.cast(source, ctypes.c_void_p), len(compressed),
                ctypes.cast(destination, ctypes.c_void_p), expected_size,
                0, 0, 0, None, 0, None, None, None, 0, 3,
            )
        )
        if result != expected_size:
            raise ExportError(
                f"Oodle decompression returned {result} bytes; expected {expected_size}."
            )
        return destination.raw[:expected_size]

    def identify_compressed_stream(self, compressed: bytes) -> tuple[int, bool]:
        """Read the codec from an existing Oodle stream without decompressing.

        Uses OodleLZ_GetFirstChunkCompressor, not a guess based on a 0x8C
        prefix or whichever compressor happens to give a similar byte count.
        Diagnostic only: metadata does not reveal encoder level/options.
        """
        if len(compressed) < 8:
            raise ExportError("Oodle stream is too short to classify")
        library = self._load()
        try:
            identify = library.OodleLZ_GetFirstChunkCompressor
            identify.argtypes = [ctypes.c_void_p, ctypes.c_ssize_t,
                ctypes.POINTER(ctypes.c_int)]
            identify.restype = ctypes.c_int
        except AttributeError as exc:
            raise ExportError("Bundled Oodle DLL lacks stream identification") from exc
        source = ctypes.create_string_buffer(compressed, len(compressed))
        independent = ctypes.c_int(0)
        codec = int(identify(ctypes.cast(source, ctypes.c_void_p),
            len(compressed), ctypes.byref(independent)))
        if codec not in (3, 8, 9, 11, 12, 13):
            raise ExportError(f"Oodle returned unsupported stream codec: {codec}")
        return codec, bool(independent.value)

    def compress(
        self, raw: bytes, compressor: int, level: int, *,
        space_speed_tradeoff: int | None = None,
        send_quantum_crcs: bool | None = None,
    ) -> bytes:
        """Encode a standalone Oodle stream with the bundled, pinned runtime.

        Used by the verified Leviathan-4 CDN wrapper and optional diagnostics.
        The caller must verify decoded-byte equality and exact manifest length.
        """
        if not raw:
            raise ExportError("Cannot compress an empty outer CDN object")
        library = self._load()
        try:
            bound = library.OodleLZ_GetCompressedBufferSizeNeeded
            bound.argtypes = [ctypes.c_int, ctypes.c_ssize_t]
            bound.restype = ctypes.c_ssize_t
            encode = library.OodleLZ_Compress
            encode.argtypes = [
                ctypes.c_int, ctypes.c_void_p, ctypes.c_ssize_t,
                ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                ctypes.c_ssize_t,
            ]
            encode.restype = ctypes.c_ssize_t
        except AttributeError as exc:
            raise ExportError("Bundled Oodle DLL lacks the required compression exports") from exc
        capacity = int(bound(compressor, len(raw)))
        if capacity < len(raw) or capacity > len(raw) + max(4096, len(raw) // 4):
            raise ExportError(f"Invalid Oodle output buffer requirement: {capacity}")
        options_ptr = None
        options = None
        if space_speed_tradeoff is not None or send_quantum_crcs is not None:
            if space_speed_tradeoff is not None and not 16 <= space_speed_tradeoff <= 2048:
                raise ExportError("Invalid experimental Oodle space-speed tradeoff")
            try:
                get_defaults = library.OodleLZ_CompressOptions_GetDefault
                get_defaults.argtypes = [ctypes.c_int, ctypes.c_int]
                get_defaults.restype = ctypes.POINTER(OodleCompressOptions)
                validate = library.OodleLZ_CompressOptions_Validate
                validate.argtypes = [ctypes.POINTER(OodleCompressOptions)]
                validate.restype = None
            except AttributeError as exc:
                raise ExportError("Pinned Oodle DLL lacks compression-options functions") from exc
            native_defaults = get_defaults(compressor, level)
            if not native_defaults:
                raise ExportError("Oodle returned a NULL default compression-options pointer")
            options = OodleCompressOptions.from_buffer_copy(native_defaults.contents)
            if space_speed_tradeoff is not None:
                options.spaceSpeedTradeoffBytes = space_speed_tradeoff
            if send_quantum_crcs is not None:
                options.sendQuantumCRCs = int(send_quantum_crcs)
            validate(ctypes.byref(options))
            options_ptr = ctypes.byref(options)
        source = ctypes.create_string_buffer(raw, len(raw))
        output = ctypes.create_string_buffer(capacity)
        size = int(encode(
            compressor, ctypes.cast(source, ctypes.c_void_p), len(raw),
            ctypes.cast(output, ctypes.c_void_p), level,
            options_ptr, None, None, None, 0,
        ))
        if size <= 0 or size > capacity:
            raise ExportError(f"Oodle compression failed (returned {size})")
        return output.raw[:size]

def b64m_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=").replace("/", "-")

def _decode_toc_name(raw: bytes) -> str:
    raw = raw.split(b"\0", 1)[0]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")

def _cache_namespace_from_package(package: str) -> str:
    lower = package.casefold()
    if lower.endswith("dx11"):
        return "9"
    if lower.endswith("dx12"):
        return "A"
    language = re.search(r"(_[a-z]{2,3})$", lower)
    if language is not None:
        return "0" + language.group(1)
    return "0"

def iter_toc_entries(toc_path: Path, kind: str, package: str, *, deleted_only: bool = False):
    """Read live TOC records, or inspect deleted records for read-only recovery diagnostics.

    Deleted records are never exposed to the ordinary cache index. A deleted
    record may point to overwritten data and must be verified independently.
    """
    try:
        data = toc_path.read_bytes()
    except OSError as exc:
        raise ExportError(f"Could not read {toc_path}: {exc}") from exc
    if len(data) < 8 or (len(data) - 8) % TOC_ENTRY.size != 0:
        raise ExportError(f"Unexpected TOC size: {toc_path}")
    magic, version = struct.unpack_from("<II", data, 0)
    if magic != TOC_MAGIC or version not in TOC_VERSIONS:
        raise ExportError(
            f"Unsupported TOC header in {toc_path.name}: magic=0x{magic:08X}, version={version}"
        )
    directories = [""]
    cache_path = toc_path.with_suffix(".cache")
    package = sys.intern(package)
    namespace = sys.intern(_cache_namespace_from_package(package))
    offset = 8
    while offset < len(data):
        cache_offset, timestamp, compressed_len, length, _reserved, parent_idx, raw_name = TOC_ENTRY.unpack_from(data, offset)
        offset += TOC_ENTRY.size
        name = _decode_toc_name(raw_name)
        if not name:
            continue
        if parent_idx < 0 or parent_idx >= len(directories):
            raise ExportError(f"Invalid parent directory index in {toc_path.name}")
        parent = directories[parent_idx]
        logical_path = sys.intern(f"{parent}/{name}" if parent else f"/{name}")
        if cache_offset == -1:
            directories.append(logical_path)
            continue
        deleted = timestamp == 0
        if deleted != deleted_only:
            continue
        if cache_offset < 0 or compressed_len < 0 or length < 0:
            if deleted:
                continue  # Tombstones may have their byte locations cleared.
            raise ExportError(f"Invalid live TOC entry for {logical_path} in {toc_path.name}")
        if deleted and (compressed_len == 0 or length == 0):
            continue  # A zero-length tombstone has no recoverable payload.
        yield CacheEntry(
            kind=kind,
            package=package,
            namespace=namespace,
            cache_path=cache_path,
            logical_path=logical_path,
            offset=cache_offset,
            compressed_len=compressed_len,
            length=length,
        )

def find_cache_windows_dir(root: Path) -> Path:
    if root.name.casefold() == "cache.windows" and root.is_dir():
        return root
    direct = root / "Cache.Windows"
    if direct.is_dir():
        return direct
    raise ExportError(f"Could not find Cache.Windows below: {root}")

def scan_cache(cache_dir: Path, kinds: str = "HBF") -> dict[tuple[str, str], dict[str, list[CacheEntry]]]:
    index: dict[tuple[str, str], dict[str, list[CacheEntry]]] = defaultdict(lambda: defaultdict(list))
    toc_count = 0
    entry_count = 0
    for kind in kinds:
        try:
            toc_paths = sorted(cache_dir.glob(f"{kind}.*.toc"), key=lambda p: p.name.casefold())
        except OSError as exc:
            raise ExportError(f"Could not enumerate {cache_dir}: {exc}") from exc
        for toc_path in toc_paths:
            package = toc_path.name[2:-4]
            if not package:
                continue
            toc_count += 1
            for entry in iter_toc_entries(toc_path, kind, package):
                index[(entry.namespace, entry.logical_path)][kind].append(entry)
                entry_count += 1
    print(f"[Cache] {cache_dir} | {toc_count} TOCs | {entry_count:,} live entries")
    return index

def read_cache_entry_raw(entry: CacheEntry) -> bytes:
    if not entry.cache_path.is_file():
        raise ExportError(f"Missing cache file: {entry.cache_path}")
    try:
        with entry.cache_path.open("rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            if entry.offset > size or entry.compressed_len > size - entry.offset:
                raise ExportError(
                    f"Cache entry exceeds file bounds: {entry.cache_path.name} {entry.logical_path}"
                )
            handle.seek(entry.offset)
            data = handle.read(entry.compressed_len)
    except OSError as exc:
        raise ExportError(f"Could not read {entry.cache_path}: {exc}") from exc
    if len(data) != entry.compressed_len:
        raise ExportError(f"Short read from {entry.cache_path.name}")
    return data

def _warframe_block_lens(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 8 > len(data):
        return 0, 0
    info = data[offset:offset + 8]
    if info[0] != 0x80 or (info[7] & 0x0F) != 0x01:
        return 0, 0
    num1 = int.from_bytes(info[:4], "big")
    num2 = int.from_bytes(info[4:], "big")
    return (num1 >> 2) & 0xFFFFFF, (num2 >> 5) & 0xFFFFFF

def decompress_cache_entry(entry: CacheEntry, oodle: Oodle) -> bytes:
    raw = read_cache_entry_raw(entry)
    if entry.compressed_len == entry.length:
        return raw
    output = bytearray()
    pos = 0
    while len(output) < entry.length:
        compressed_len, decompressed_len = _warframe_block_lens(raw, pos)
        if compressed_len == 0 and decompressed_len == 0:
            # Some Cache.Windows entries use one unframed compressed blob. The
            # repair tool already treats that as one block for decoding. It is
            # useful for reading target metadata/CommonHeaders, but it is not
            # automatically considered an exact SHCC type-2 payload by the
            # reconstruction path.
            compressed_len = entry.compressed_len
            decompressed_len = entry.length
            block_start = 0
            block_end = len(raw)
            pos = len(raw)
        else:
            block_start = pos + 8
            block_end = block_start + compressed_len
            if block_end > len(raw):
                raise ExportError(f"Truncated cache block for {entry.logical_path}")
            pos = block_end
        block = raw[block_start:block_end]
        if compressed_len == decompressed_len:
            decoded = block
        elif block and block[0] == 0x8C:
            decoded = oodle.decompress(block, decompressed_len)
        else:
            raise ExportError(
                f"Unsupported Cache.Windows compression for {entry.logical_path}"
            )
        output.extend(decoded)
    if len(output) != entry.length or pos != len(raw):
        raise ExportError(
            f"Cache entry length mismatch for {entry.logical_path}: got {len(output)}, expected {entry.length}"
        )
    return bytes(output)

def parse_common_header(data: bytes) -> tuple[bytes, int]:
    if len(data) < 24:
        raise ExportError("CommonHeader is too short")
    digest = data[:16]
    # Certain service binaries use a compact 0x14-byte header:
    # digest[16] + header-size(0x14) + CDN type + variant(1).
    # This exact layout is present in the U44 Dependancies.bin,
    # Packages.bin and Languages.bin headers. It is NOT inferred
    # from arbitrary bytes or from neighboring patch versions.
    if len(data) >= 28:
        header_size, compact_type, variant = struct.unpack_from("<III", data, 16)
        if header_size == 0x14 and 0 < compact_type <= 0xFFFF and variant == 1:
            return digest, compact_type
    # Some resources have 16 opaque bytes after the digest, followed by two
    # zero u32s and the CDN type at offset 40. An initial interpretation of
    # U44 OriginSolarMapRedux incorrectly treated the u32 at offset 44 as a
    # path length. Its actual observed bytes are:
    # +0x28 type=3; +0x2C auxiliary=25; +0x30 path length=33;
    # +0x34 absolute /Lotus/... path
    # Preserve the older single-length variant, but also accept the observed
    # auxiliary-u32 + length-u32 structure. Neither form is accepted unless
    # the claimed path is wholly in bounds and printable, with /Lotus/ prefix.
    if len(data) >= 55 and data[32:40] == b"\0" * 8:
        alt_type = struct.unpack_from("<I", data, 40)[0]
        if 0 < alt_type <= 0xFFFF:
            candidates = [(44, 48)]  # single path length at offset 44
            if len(data) >= 52:
                auxiliary, _ = struct.unpack_from("<II", data, 44)
                if 0 < auxiliary <= 200:
                    candidates.insert(0, (48, 52))  # auxiliary then length
            for length_offset, path_offset in candidates:
                name_len = struct.unpack_from("<I", data, length_offset)[0]
                name_end = path_offset + name_len
                if not (7 <= name_len <= 200 and name_end <= len(data)):
                    continue
                path = data[path_offset:name_end]
                if (path.startswith(b"/Lotus/") and b"\0" not in path
                        and all(0x20 <= ch < 0x7F for ch in path)):
                    return digest, alt_type
    offset = 16
    source_count = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    if source_count > 3000:
        raise ExportError(f"Unreasonable CommonHeader source path count: {source_count}")
    for _ in range(source_count):
        if offset + 4 > len(data):
            raise ExportError("Truncated CommonHeader source path length")
        path_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        if path_len > 200 or offset + path_len > len(data):
            raise ExportError("Invalid CommonHeader source path")
        offset += path_len
    if offset + 4 > len(data):
        raise ExportError("Truncated CommonHeader attribute length")
    attr_len = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    if offset + attr_len > len(data):
        raise ExportError("Truncated CommonHeader attributes")
    offset += attr_len
    if attr_len:
        if offset >= len(data):
            raise ExportError("Truncated CommonHeader attribute terminator")
        offset += 1
    if offset + 4 > len(data):
        raise ExportError("Truncated CommonHeader type")
    type_id = struct.unpack_from("<I", data, offset)[0] & 0xFFFF
    return digest, type_id

def parse_h_cache_header(header: bytes) -> HCacheIndex:
    if len(header) < 20:
        raise ExportError("H.Cache header is too short")
    version = struct.unpack_from("<I", header, 16)[0]
    offset = 20
    records: list[HCacheRecord] = []
    seen: set[str] = set()
    while offset < len(header):
        if offset + 4 > len(header):
            raise ExportError("Truncated H.Cache group count")
        count = struct.unpack_from("<I", header, offset)[0]
        offset += 4
        if count > 5_000_000:
            raise ExportError(f"Unreasonable H.Cache group count: {count}")
        for _ in range(count):
            if offset + 4 > len(header):
                raise ExportError("Truncated H.Cache path length")
            path_len = struct.unpack_from("<I", header, offset)[0]
            offset += 4
            if path_len <= 0 or offset + path_len + 20 > len(header):
                raise ExportError("Truncated H.Cache record")
            raw_path = header[offset:offset + path_len]
            offset += path_len
            target_hash = header[offset:offset + 16]
            offset += 16
            info = struct.unpack_from("<I", header, offset)[0]
            offset += 4
            try:
                path = raw_path.decode("utf-8")
            except UnicodeDecodeError:
                path = raw_path.decode("latin-1")
            if path in seen:
                raise ExportError(f"Duplicate H.Cache path: {path}")
            seen.add(path)
            records.append(HCacheRecord(path, target_hash, info))
    return HCacheIndex(version, tuple(records))

def parse_manifest_header(header: bytes, namespace: str) -> list[ManifestAsset]:
    if len(header) < 20:
        raise ExportError("Cache manifest header is too short")
    version = struct.unpack_from("<I", header, 16)[0]
    if version != SUPPORTED_MANIFEST_VERSION:
        raise ExportError(
            f"Unsupported cache-manifest version {version}; expected {SUPPORTED_MANIFEST_VERSION}"
        )
    offset = 20
    assets: list[ManifestAsset] = []
    for section in MANIFEST_SECTION_NAMES:
        if offset + 4 > len(header):
            raise ExportError(f"Truncated manifest {section} count")
        count = struct.unpack_from("<I", header, offset)[0]
        offset += 4
        if count > 5_000_000:
            raise ExportError(f"Unreasonable manifest {section} count: {count}")
        for _ in range(count):
            if offset + 4 > len(header):
                raise ExportError("Truncated manifest path length")
            path_len = struct.unpack_from("<I", header, offset)[0]
            offset += 4
            if path_len <= 0 or offset + path_len + 20 > len(header):
                raise ExportError("Truncated manifest entry")
            raw_path = header[offset:offset + path_len]
            offset += path_len
            digest = header[offset:offset + 16]
            offset += 16
            info = struct.unpack_from("<I", header, offset)[0]
            offset += 4
            try:
                path = raw_path.decode("utf-8")
            except UnicodeDecodeError:
                path = raw_path.decode("latin-1")
            assets.append(ManifestAsset(namespace, section, path, digest, info))
    if offset != len(header):
        raise ExportError(f"Unexpected {len(header) - offset} trailing manifest bytes")
    return assets

def _crc32c_table() -> tuple[int, ...]:
    polynomial = 0x82F63B78
    table = []
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = (crc >> 1) ^ (polynomial if crc & 1 else 0)
        table.append(crc)
    return tuple(table)

_CRC32C_TABLE = _crc32c_table()

def _crc32c_python(data: bytes) -> int:
    """Portable CRC32C fallback when the native extension is unavailable."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return (~crc) & 0xFFFFFFFF

def crc32c(data: bytes) -> int:
    if _google_crc32c is not None and getattr(_google_crc32c, "implementation", None) == "c":
        return int(_google_crc32c.value(data))
    return _crc32c_python(data)

def _validate_oodle_chunk_payload(raw: bytes, expected_decompressed: int) -> bool:
    pos = 0
    total = 0
    while pos < len(raw):
        if pos + 8 > len(raw):
            return False
        info = raw[pos:pos + 8]
        if info[0] != 0x80 or (info[7] & 0x0F) != 0x01:
            return False
        compressed_len, decompressed_len = _warframe_block_lens(raw, pos)
        pos += 8
        if compressed_len <= 0 or decompressed_len <= 0 or pos + compressed_len > len(raw):
            return False
        block = raw[pos:pos + compressed_len]
        pos += compressed_len
        if not block or (compressed_len != decompressed_len and block[0] != 0x8C):
            return False
        # A framed stream may mix Oodle-compressed blocks with blocks stored
        # verbatim. The same distinction is used by decompress_cache_entry().
        total += decompressed_len
    return pos == len(raw) and total == expected_decompressed

def _encode_exact_chunk(entry: CacheEntry) -> tuple[bytes, bool]:
    raw = read_cache_entry_raw(entry)
    if entry.compressed_len == entry.length:
        return struct.pack("<BII", 0, entry.length, len(raw)) + raw, True
    if _validate_oodle_chunk_payload(raw, entry.length):
        return struct.pack("<BII", 2, entry.length, len(raw)) + raw, True
    return b"", False

def _empty_chunk() -> bytes:
    return struct.pack("<BII", 0, 0, 0)

def build_shcc(
    h_entry: CacheEntry,
    b_entry: CacheEntry | None,
    f_entry: CacheEntry | None,
) -> bytes:
    chunks = []
    for entry in (h_entry, b_entry, f_entry):
        if entry is None:
            chunks.append(_empty_chunk())
            continue
        encoded, piece_exact = _encode_exact_chunk(entry)
        if not piece_exact:
            raise ExportError(
                f"Could not preserve the exact SHCC chunk payload for {entry.logical_path} "
                f"from {entry.cache_path.name}"
            )
        chunks.append(encoded)
    prefix = SHCC_PREAMBLE + b"".join(chunks) + b"\x52"
    return prefix + struct.pack("<I", crc32c(prefix))

def verify_h_cache_metadata_object(payload: bytes, expected_header: bytes, oodle: Oodle) -> str:
    """Verify CDN framing plus the *entire decoded* pristine H.Cache.bin header.

    H.Cache.bin has the sentinel filename, so its CDN name does not authenticate
    its contents. Recompressed originals may differ from build_shcc bytes.
    """
    if not 40 <= len(payload) <= 1024 * 1024:
        raise ExportError('H.Cache CDN object has an unsafe size')
    if int.from_bytes(payload[-4:], 'little') != crc32c(payload[:-4]):
        raise ExportError('H.Cache CDN CRC32C mismatch')
    if payload.startswith(SHCC_PREAMBLE):
        if payload[-5] != 0x52:
            raise ExportError('H.Cache direct SHCC footer mismatch')
        plain = payload[:-5]
    else:
        if payload[-5:-4] != CDN_OUTER_FOOTER_MARKER or len(payload) < 14:
            raise ExportError('H.Cache CDN wrapper is unrecognized')
        plain_size = int.from_bytes(payload[-9:-5], 'little')
        if not len(SHCC_PREAMBLE) + 27 <= plain_size <= 1024 * 1024:
            raise ExportError('H.Cache outer decoded size is unsafe')
        plain = oodle.decompress(payload[:-9], plain_size)
    if not plain.startswith(SHCC_PREAMBLE):
        raise ExportError('H.Cache decoded payload is not SHCC')
    offset = len(SHCC_PREAMBLE)
    header = None
    for kind in 'HBF':
        if offset + 9 > len(plain):
            raise ExportError(f'Truncated H.Cache {kind} chunk')
        codec, unpacked, stored = struct.unpack_from('<BII', plain, offset)
        offset += 9
        if stored > len(plain) - offset or (kind == 'H' and unpacked > 1024 * 1024):
            raise ExportError(f'Unsafe H.Cache {kind} chunk size')
        chunk = plain[offset:offset + stored]
        offset += stored
        if kind != 'H':
            # Archived H.Cache.bin uses 0xFFFFFFFF for some empty B/F chunk sizes.
            if codec != 0 or stored or unpacked not in (0, 0xFFFFFFFF):
                raise ExportError('H.Cache B/F slots must be empty')
        elif codec == 0 and unpacked == stored:
            header = chunk
        elif codec == 2 and _validate_oodle_chunk_payload(chunk, unpacked):
            from recover_missing_cdn import _unpack_framed_payload
            header = _unpack_framed_payload(chunk, unpacked, oodle)
        else:
            raise ExportError('Unsupported H.Cache H chunk codec or framing')
    if offset != len(plain):
        raise ExportError('H.Cache SHCC trailing bytes')
    if header != expected_header:
        raise ExportError('H.Cache decoded H bytes differ from pristine target')
    return hashlib.sha256(payload).hexdigest()

def _dedupe_entries(entries: list[CacheEntry]) -> list[CacheEntry]:
    seen = set()
    result = []
    for entry in entries:
        key = (entry.cache_path, entry.offset, entry.compressed_len, entry.length)
        if key not in seen:
            seen.add(key)
            result.append(entry)
    return result

def _entries_for(index, namespace: str, logical_path: str, kind: str) -> list[CacheEntry]:
    return _dedupe_entries(index.get((namespace, logical_path), {}).get(kind, []))

def _select_h_by_hash(
    index,
    namespace: str,
    logical_path: str,
    digest: bytes,
    oodle: Oodle,
    *,
    required_piece_kinds: str = "",
) -> tuple[CacheEntry, bytes, int | None]:
    matches = []
    errors = []
    entries = _entries_for(index, namespace, logical_path, "H")
    if not entries:
        raise SourceCoverageError(
            f"Target H cache does not contain {namespace}{logical_path}"
        )
    for entry in entries:
        try:
            header = decompress_cache_entry(entry, oodle)
        except ExportError as exc:
            errors.append(str(exc))
            continue
        if len(header) >= 16 and header[:16] == digest:
            type_id = None
            try:
                _hash, type_id = parse_common_header(header)
            except ExportError:
                pass
            matches.append((entry, header, type_id))
    if not matches:
        if errors:
            raise ExportError(
                f"Could not safely inspect target H cache for {namespace}{logical_path}: {errors[0]}"
            )
        raise SourceCoverageError(
            f"Target H cache does not contain {namespace}{logical_path} with hash {b64m_encode(digest)}"
        )
    if required_piece_kinds:
        complete = []
        for match in matches:
            entry = match[0]
            if all(
                _piece_in_package(index, namespace, logical_path, kind, entry.package) is not None
                for kind in required_piece_kinds
            ):
                complete.append(match)
        if not complete:
            kinds = "/".join(required_piece_kinds)
            raise SourceCoverageError(
                f"Target H cache contains the matching H entry for {namespace}{logical_path}, "
                f"but no matching package contains all required {kinds} pieces"
            )
        matches = complete
    matches.sort(key=lambda item: item[0].package.casefold())
    packages = {entry.package for entry, _header, _type in matches}
    if len(packages) > 1:
        signatures = set()
        for entry, header, type_id in matches:
            piece_signature = []
            for kind in required_piece_kinds:
                piece = _piece_in_package(index, namespace, logical_path, kind, entry.package)
                assert piece is not None
                piece_signature.append(
                    (
                        kind,
                        piece.length,
                        piece.compressed_len,
                        hashlib.sha256(read_cache_entry_raw(piece)).digest(),
                    )
                )
            signatures.add(
                (
                    entry.length,
                    entry.compressed_len,
                    hashlib.sha256(read_cache_entry_raw(entry)).digest(),
                    header[:16],
                    type_id,
                    tuple(piece_signature),
                )
            )
        if len(signatures) != 1:
            raise ExportError(
                f"Ambiguous target H cache entries for {namespace}{logical_path}: "
                + ", ".join(sorted(packages))
            )
    return matches[0]

def _select_h_cache(index, oodle: Oodle) -> tuple[CacheEntry, bytes]:
    logical_path = "/H.Cache.bin"
    candidates = _entries_for(index, "0", logical_path, "H")
    valid = []
    for entry in candidates:
        try:
            header = decompress_cache_entry(entry, oodle)
            if len(header) < 20:
                continue
            calculated = hashlib.md5(
                SHCC_PREAMBLE + header[16:],
                usedforsecurity=False,
            ).digest()
            if header[:16] != calculated:
                continue
            parse_h_cache_header(header)
            valid.append((entry, header))
        except ExportError:
            continue
    if not valid:
        raise ExportError(f"Could not find a valid installed {logical_path} H entry")
    if len({(e.package, h[:16]) for e, h in valid}) > 1:
        raise ExportError(f"Multiple different valid installed {logical_path} entries were found")
    return valid[0]

def _piece_in_package(index, namespace: str, logical_path: str, kind: str, package: str) -> CacheEntry | None:
    candidates = [e for e in _entries_for(index, namespace, logical_path, kind) if e.package == package]
    if not candidates:
        return None
    signatures = {(e.cache_path, e.offset, e.compressed_len, e.length) for e in candidates}
    if len(signatures) > 1:
        raise ExportError(f"Multiple live {kind} entries for {namespace}{logical_path} in package {package}")
    return candidates[0]

def _manifest_namespace(logical_path: str) -> str:
    match = H_CACHE_B_CACHE_RE.fullmatch(logical_path)
    if match is None:
        raise ExportError(f"Unsupported B.Cache family in H.Cache: {logical_path}")
    kind = match.group("kind")
    suffix = match.group("suffix") or ""
    if kind == "Windows":
        return "0" + suffix
    if suffix:
        raise ExportError(f"Unexpected suffix on {kind} manifest: {logical_path}")
    return "9" if kind == "Dx11" else "A"

def _validate_manifest_namespace(namespace: str) -> str:
    """Accept only namespace identifiers produced by installed B.Cache manifests."""
    if not isinstance(namespace, str) or not re.fullmatch(r'0(?:_[A-Za-z0-9]+)?|9|A', namespace):
        raise ExportError(f"Invalid manifest namespace: {namespace!r}")
    return namespace

def _validate_logical_path(logical_path: str) -> tuple[str, ...]:
    if not logical_path.startswith("/") or "\\" in logical_path or "\x00" in logical_path:
        raise ExportError(f"Unsafe logical path: {logical_path}")
    parts = tuple(logical_path[1:].split("/"))
    if not parts or any(not part or part in {".", ".."} or ":" in part for part in parts):
        raise ExportError(f"Unsafe logical path: {logical_path}")
    return parts

def _safe_output_path(content_root: Path, namespace: str, logical_path: str, type_id: int, digest: str) -> Path:
    parts = _validate_logical_path(logical_path)
    filename = parts[-1] + f"!{type_id:X}_{digest}"
    return content_root / namespace / Path(*parts[:-1], filename)

def atomic_write(path: Path, data: bytes) -> None:
    if os.name == "nt":
        _validate_windows_export_path(path, atomic=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass

class CdnReferenceResolver:
    """Read-only, opt-in recovery of identically named CDN objects from patches.

    The filename embeds the target CommonHeader hash (not a whole-file hash).
    Matching target namespace/path/type/hash/size is required; matching copies
    in separate reference directories must also be byte-identical.
    """

    _SUFFIX = re.compile(r"^!(?P<type>[0-9A-Fa-f]{1,8})_(?P<hash>[A-Za-z0-9+\-]{22})$")

    def __init__(self, patch_dirs: list[Path]):
        if not patch_dirs:
            raise ExportError("Specify at least one CDN reference patch")
        self.patch_roots: list[Path] = []
        self.content_roots: list[Path] = []
        for patch in patch_dirs:
            resolved = patch.resolve(strict=True)
            if not resolved.is_dir():
                raise ExportError(f"CDN reference is not a directory: {patch}")
            if (resolved / "OpenWF" / "Content" / "0").is_dir():
                content = resolved / "OpenWF" / "Content"
            elif resolved.name == "Content" and (resolved / "0").is_dir():
                content = resolved
            else:
                raise ExportError(f"Not an OpenWF reference patch: {patch}")
            content = content.resolve(strict=True)
            if content in self.content_roots:
                raise ExportError(f"Duplicate CDN reference directory: {patch}")
            self.patch_roots.append(resolved)
            self.content_roots.append(content)

    def validate_output(self, output_root: Path) -> None:
        output = output_root.resolve()
        for patch, content in zip(self.patch_roots, self.content_roots):
            if (output == patch or output.is_relative_to(patch)
                    or patch.is_relative_to(output)
                    or output == content or output.is_relative_to(content)):
                raise ExportError(f"Output and reference patch must be separate: {patch}")

    def resolve(
        self, namespace: str, logical_path: str, digest: str,
        type_id: int, expected_size: int,
    ) -> tuple[bytes, int] | None:
        parts = _validate_logical_path(logical_path)
        if not re.fullmatch(r"(?:0(?:_[a-z]{2,3})?|9|A)", namespace):
            raise ExportError(f"Invalid CDN reference namespace: {namespace}")
        if not re.fullmatch(r"[A-Za-z0-9+\-]{22}", digest):
            raise ExportError(f"Invalid CDN reference hash: {logical_path}")
        if not isinstance(type_id, int) or not 0 <= type_id <= 0xFFFF:
            raise ExportError(f"Invalid CDN reference type: {logical_path}")
        if not isinstance(expected_size, int) or expected_size <= 0:
            raise ExportError(f"Invalid CDN reference size: {logical_path}")
        candidate_data: list[bytes] = []
        for content in self.content_roots:
            directory = content / namespace / Path(*parts[:-1])
            if not directory.exists():
                continue
            if directory.is_symlink() or not directory.is_dir() or not directory.resolve().is_relative_to(content):
                raise ExportError(f"Unsafe CDN reference directory: {directory}")
            prefix = parts[-1] + "!"
            for path in directory.iterdir():
                if not path.name.startswith(prefix):
                    continue
                match = self._SUFFIX.fullmatch(path.name[len(parts[-1]):])
                if match is None or match.group("hash") != digest or int(match.group("type"), 16) != type_id:
                    continue
                if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(content):
                    raise ExportError(f"Unsafe CDN reference file: {path}")
                if path.stat().st_size != expected_size:
                    raise ExportError(f"CDN reference size mismatch for {namespace}{logical_path}: {path}")
                try:
                    data = path.read_bytes()
                except OSError as exc:
                    raise ExportError(f"Could not read CDN reference {path}: {exc}") from exc
                if len(data) != expected_size:
                    raise ExportError(f"CDN reference size changed during read: {path}")
                if data.startswith(SHCC_PREAMBLE):
                    if len(data) < 13 or data[-5] != 0x52 or int.from_bytes(data[-4:], "little") != crc32c(data[:-4]):
                        raise ExportError(f"CDN reference SHCC CRC32C mismatch: {path}")
                candidate_data.append(data)
        if not candidate_data:
            return None
        first = candidate_data[0]
        if any(other != first for other in candidate_data[1:]):
            raise ExportError(f"Conflicting reference CDN bytes for {namespace}{logical_path}")
        return first, len(candidate_data)

def _build_h_only_metadata_object(
    index,
    logical_path: str,
    digest: bytes,
    oodle: Oodle,
) -> tuple[bytes, bytes, str]:
    h_entry, header, _type_id = _select_h_by_hash(
        index,
        "0",
        logical_path,
        digest,
        oodle,
    )
    return build_shcc(h_entry, None, None), header, h_entry.package

def _required_piece_kinds(flags: int) -> str:
    return (
        ("B" if flags & MANIFEST_FLAG_B else "")
        + ("F" if flags & MANIFEST_FLAG_F else "")
    )

def _select_object_pieces(
    index,
    namespace: str,
    logical_path: str,
    digest: bytes,
    flags: int,
    oodle: Oodle,
) -> tuple[CacheEntry, CacheEntry | None, CacheEntry | None, bytes, int | None]:
    if not (flags & MANIFEST_FLAG_H):
        raise ExportError(
            f"Manifest entry has no H participation; unsupported for install reconstruction: "
            f"{namespace}{logical_path}"
        )
    required_piece_kinds = _required_piece_kinds(flags)
    h_entry, header, type_id = _select_h_by_hash(
        index,
        namespace,
        logical_path,
        digest,
        oodle,
        required_piece_kinds=required_piece_kinds,
    )
    b_entry = None
    f_entry = None
    if flags & MANIFEST_FLAG_B:
        b_entry = _piece_in_package(index, namespace, logical_path, "B", h_entry.package)
        if b_entry is None:
            raise SourceCoverageError(
                f"Target install is missing required B piece for {namespace}{logical_path} "
                f"in {h_entry.package}"
            )
    if flags & MANIFEST_FLAG_F:
        f_entry = _piece_in_package(index, namespace, logical_path, "F", h_entry.package)
        if f_entry is None:
            raise SourceCoverageError(
                f"Target install is missing required F piece for {namespace}{logical_path} "
                f"in {h_entry.package}"
            )
    return h_entry, b_entry, f_entry, header, type_id

# Candidate profiles are intentionally small and deterministic. The local
# The U44 reference files establish a specific whole-object CDN format:
# Leviathan-13, compression level 4, of SHCC *without* the synthetic 0x52
# CRC32C trailer, followed by the little-endian uncompressed length, marker
# 0x43, and little-endian CRC32C of all prior CDN bytes. Four independently
# captured objects agreed with this structure and byte-identical Oodle prefix.
# The format is attempted only when direct SHCC size mismatches the manifest.
OODLE_OUTER_PROFILE = (13, 4)
# Profiles retained for read-only diagnostics.
# The production exporter uses ONLY OODLE_OUTER_PROFILE.
OODLE_OUTER_PROFILES = tuple(
    (codec, level) for codec in (8, 9, 13, 11) for level in (4, 3, 5, 2, 6, 1)
)
CDN_OUTER_FOOTER_MARKER = b"\x43"

def build_outer_cdn_footer(compressed_prefix: bytes, decoded_length: int) -> bytes:
    """Build the verified 9-byte outer CDN footer, including its own CRC32C."""
    if not compressed_prefix or decoded_length <= 0 or decoded_length > 0xFFFFFFFF:
        raise ExportError("Invalid outer CDN prefix or decoded length")
    without_crc = (compressed_prefix + struct.pack("<I", decoded_length)
        + CDN_OUTER_FOOTER_MARKER)
    return without_crc[-5:] + struct.pack("<I", crc32c(without_crc))

def try_encode_outer_oodle(
    direct_shcc: bytes, expected_cdn_size: int, oodle: Oodle,
) -> tuple[bytes, tuple[int, int]] | None:
    """Rebuild U44 outer CDN bytes from caches, with no reference patch inputs.

    The direct SHCC object has a locally constructed 5-byte 0x52/CRC32C
    trailer; CDN outer streams instead compress the preceding SHCC bytes.
    Both the Oodle round-trip and the final manifest length are mandatory.
    The first Oodle block can be stored raw (0xCC) instead of compressed
    (0x8C); validate the codec through Oodle rather than its first byte.
    A different format, DLL result, or CDN length is never silently accepted.
    """
    if not direct_shcc.startswith(SHCC_PREAMBLE):
        raise ExportError("Outer-Oodle source is not a direct SHCC object")
    if (len(direct_shcc) < len(SHCC_PREAMBLE) + 5
            or direct_shcc[-5] != 0x52
            or int.from_bytes(direct_shcc[-4:], "little") != crc32c(direct_shcc[:-4])):
        raise ExportError("Outer-Oodle source has invalid SHCC CRC32C")
    if expected_cdn_size <= 9 or expected_cdn_size >= len(direct_shcc):
        return None
    plain = direct_shcc[:-5]
    codec, level = OODLE_OUTER_PROFILE
    prefix = oodle.compress(plain, codec, level)
    if len(prefix) + 9 != expected_cdn_size:
        return None
    actual_codec, independent = oodle.identify_compressed_stream(prefix)
    if (actual_codec, independent) != (codec, True):
        return None
    try:
        decoded = oodle.decompress(prefix, len(plain))
    except ExportError:
        return None
    if decoded != plain:
        return None
    candidate = prefix + build_outer_cdn_footer(prefix, len(plain))
    if len(candidate) != expected_cdn_size:
        return None
    # Guard against changes to the CRC/footer construction.
    if int.from_bytes(candidate[-4:], "little") != crc32c(candidate[:-4]):
        return None
    return candidate, (codec, level)

def _build_exact_direct_object(
    index,
    namespace: str,
    logical_path: str,
    digest: bytes,
    flags: int,
    expected_size: int,
    oodle: Oodle,
    *,
    try_oodle_outer: bool = True,
) -> tuple[bytes, bytes, int | None, str]:
    h_entry, b_entry, f_entry, header, type_id = _select_object_pieces(
        index, namespace, logical_path, digest, flags, oodle
    )
    obj = build_shcc(h_entry, b_entry, f_entry)
    if len(obj) != expected_size:
        if try_oodle_outer:
            encoded = try_encode_outer_oodle(obj, expected_size, oodle)
            if encoded is not None:
                candidate, (codec, level) = encoded
                print(f"[Outer Oodle] {namespace}{logical_path} | "
                      f"codec {codec}, level {level}, {len(obj):,} -> {len(candidate):,} B")
                return candidate, header, type_id, h_entry.package
        raise CdnSizeMismatchError(
            f"Reconstructed CDN size mismatch for {namespace}{logical_path}: "
            f"manifest {expected_size:,} B, direct SHCC {len(obj):,} B. "
            "This likely uses an outer whole-object wrapper or another unverified representation."
        )
    return obj, header, type_id, h_entry.package

def _build_object_for_asset(
    asset: ManifestAsset,
    target_index,
    oodle: Oodle,
    type_evidence: dict[tuple[str, str, str], TypeEvidence] | None = None,
    cdn_references: CdnReferenceResolver | None = None,
    try_oodle_outer: bool = True,
    installed_resolver=None,
) -> tuple[bytes, int, str, str | None]:
    try:
        obj, _header, type_id, package = _build_exact_direct_object(
            target_index, asset.namespace, asset.logical_path,
            asset.manifest_hash, asset.flags, asset.cdn_size, oodle,
            try_oodle_outer=try_oodle_outer,
        )
    except CdnSizeMismatchError:
        if cdn_references is None:
            raise
        _, _, _, _header, type_id = _select_object_pieces(
            target_index, asset.namespace, asset.logical_path,
            asset.manifest_hash, asset.flags, oodle,
        )
        from installed_type_resolver import evidence_for_asset
        type_id, _source = resolve_common_header_type(
            asset, type_id, type_evidence,
            installed_type=evidence_for_asset(installed_resolver, asset, type_id),
        )
        result = cdn_references.resolve(
            asset.namespace, asset.logical_path, asset.hash_b64, type_id, asset.cdn_size,
        )
        if result is None:
            raise ExportError(f"No matching CDN reference for {asset.namespace}{asset.logical_path}")
        obj, copies = result
        print(f"[CDN reference] {asset.namespace}{asset.logical_path} | "
              f"matched {copies} copy/copies by namespace, type, hash and size")
        return obj, type_id, "reference", "cdn-reference"
    from installed_type_resolver import evidence_for_asset
    type_id, type_source = resolve_common_header_type(
        asset, type_id, type_evidence,
        installed_type=evidence_for_asset(installed_resolver, asset, type_id),
    )
    return obj, type_id, package, type_source

def _base_matches(base_index, asset: ManifestAsset, oodle: Oodle) -> tuple[bool, bool]:
    had_read_error = False
    for entry in _entries_for(base_index, asset.namespace, asset.logical_path, "H"):
        try:
            header = decompress_cache_entry(entry, oodle)
        except ExportError:
            had_read_error = True
            continue
        if len(header) >= 16 and header[:16] == asset.manifest_hash:
            return True, had_read_error
    return False, had_read_error

def _duplicate_target_packages_not_updated(target_index, base_index, asset: ManifestAsset, oodle: Oodle) -> list[str]:
    """Detect target-identical H entries that remain stale in a second cache package.

    A path can be present under multiple Cache.Windows packages. Finding one
    matching base H (e.g. Misc) does not mean a second target package
    (e.g. AnimRetarget) already holds the target bytes. Return the target
    packages that would remain outdated if the CDN object were omitted.

    This is a *patch candidate* signal, not a guarantee the downstream patch
    applicator writes the object to each package. Its applied caches must be
    compared independently after installation.
    """
    targets = _entries_for(target_index, asset.namespace, asset.logical_path, "H")
    if len(targets) < 2:
        return []
    matching_target_packages = set()
    required = _required_piece_kinds(asset.flags)
    for entry in targets:
        header = decompress_cache_entry(entry, oodle)
        if (len(header) >= 16 and header[:16] == asset.manifest_hash
                and all(_piece_in_package(target_index, asset.namespace, asset.logical_path,
                kind, entry.package) is not None for kind in required)):
            matching_target_packages.add(entry.package)
    if len(matching_target_packages) < 2:
        return []
    missing = []
    for package in sorted(matching_target_packages, key=str.casefold):
        base_entries = [e for e in _entries_for(base_index, asset.namespace, asset.logical_path, "H")
            if e.package == package]
        if not base_entries:
            missing.append(package)
            continue
        hashes = set()
        for entry in base_entries:
            header = decompress_cache_entry(entry, oodle)
            if len(header) < 16:
                raise ExportError(f"Short base H header for {asset.namespace}{asset.logical_path} in {package}")
            hashes.add(header[:16])
        if hashes != {asset.manifest_hash}:
            missing.append(package)
            continue
        # A matching H is insufficient when this target package requires B/F.
        for kind in required:
            piece = _piece_in_package(base_index, asset.namespace, asset.logical_path, kind, package)
            if piece is None:
                missing.append(package)
                break
            # A missing/truncated file must not count as a complete base asset.
            read_cache_entry_raw(piece)
    return missing

def _base_has_complete_inherited_asset(base_index, asset: ManifestAsset, oodle: Oodle) -> bool:
    """Check an asset absent from the target against the unmodified Steam base.

    An H hash alone is insufficient: required B/F pieces must exist in the
    same base package and be readable. A missing/mismatched H or piece is a
    coverage gap; corrupt or ambiguous base data is an export error, not proof
    of inheritance. This does not claim byte-identical CDN reconstruction.
    """
    required = _required_piece_kinds(asset.flags)
    try:
        entry, header, _type = _select_h_by_hash(
            base_index, asset.namespace, asset.logical_path, asset.manifest_hash,
            oodle, required_piece_kinds=required,
        )
    except SourceCoverageError:
        return False
    if header[:16] != asset.manifest_hash:
        raise ExportError(f"Base H hash changed unexpectedly for {asset.namespace}{asset.logical_path}")
    for kind in required:
        piece = _piece_in_package(base_index, asset.namespace, asset.logical_path, kind, entry.package)
        if piece is None:
            raise ExportError(f"Base {kind} disappeared during inheritance check: {asset.namespace}{asset.logical_path}")
        decompress_cache_entry(piece, oodle)
    return True

def _dedupe_manifest_assets(assets: list[ManifestAsset]) -> tuple[list[ManifestAsset], int]:
    by_path: dict[tuple[str, str], ManifestAsset] = {}
    by_windows_path: dict[tuple[str, str], ManifestAsset] = {}
    duplicates = 0
    for asset in assets:
        _validate_logical_path(asset.logical_path)
        key = (asset.namespace, asset.logical_path)
        windows_key = (asset.namespace.casefold(), asset.logical_path.casefold())
        collision = by_windows_path.get(windows_key)
        if collision is not None and (
            collision.namespace != asset.namespace or collision.logical_path != asset.logical_path
        ):
            raise ExportError(
                f"Case-insensitive output path collision: "
                f"{collision.namespace}{collision.logical_path} vs {asset.namespace}{asset.logical_path}"
            )
        by_windows_path.setdefault(windows_key, asset)
        previous = by_path.get(key)
        if previous is None:
            by_path[key] = asset
            continue
        duplicates += 1
        if previous.manifest_hash != asset.manifest_hash or previous.info != asset.info:
            raise ExportError(
                f"Same target path has conflicting manifest definitions: "
                f"{asset.namespace}{asset.logical_path}"
            )
    return list(by_path.values()), duplicates

def _validate_source_and_output_paths(
    target_root: Path,
    base_root: Path,
    target_cache: Path,
    base_cache: Path,
    output_root: Path,
    *,
    dry_run: bool,
) -> None:
    if target_cache.resolve() == base_cache.resolve():
        raise ExportError("Target install and original base resolve to the same Cache.Windows directory")
    if dry_run:
        return
    output = output_root.resolve()
    for label, source in (("target", target_root), ("base", base_root), ("target cache", target_cache), ("base cache", base_cache)):
        source = source.resolve()
        if output == source or output.is_relative_to(source) or source.is_relative_to(output):
            raise ExportError(
                f"Output directory must be separate; it must not contain or be contained by the {label}: {output_root}"
            )
    _validate_output_directory(output_root)

def _validate_output_directory(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if not path.is_dir():
        raise ExportError(f"Output path exists but is not a directory: {path}")
    if next(path.iterdir(), None) is not None:
        raise ExportError(f"Output directory is not empty: {path}")

def _find_target_exe(target_root: Path) -> Path:
    candidates = [target_root / "Warframe.x64.exe"]
    if target_root.name.casefold() == "cache.windows":
        candidates.append(target_root.parent / "Warframe.x64.exe")
    exe = next((candidate for candidate in candidates if candidate.is_file()), None)
    if exe is None:
        raise ExportError(
            f"Could not find target Warframe.x64.exe at or next to: {target_root}"
        )
    return exe

def _copy_target_exe(target_exe: Path, output_root: Path) -> None:
    shutil.copy2(target_exe, output_root / "Warframe.x64.exe")

# Traditional Windows MAX_PATH includes the terminating NUL character.
# Leave room for the random temporary filename used by atomic_write.
_WINDOWS_MAX_PATH_UNITS = 259
_WINDOWS_MAX_DIRECTORY_UNITS = 247
_ATOMIC_TEMP_EXTRA_UNITS = 13  # "." + 8 random chars + ".tmp"
_DISK_SAFETY_MARGIN_BYTES = 64 * 1024 * 1024

def _windows_path_units(path: Path) -> int:
    """Count UTF-16 code units (Windows MAX_PATH), not Python characters."""
    return len(str(path).encode("utf-16-le")) // 2

def _validate_windows_export_path(path: Path, *, atomic: bool = False) -> None:
    """Conservatively reject paths requiring Windows long-path opt-in.

    The exporter uses ordinary file APIs and must not assume long paths were
    enabled on a specific Windows machine. This also checks mkstemp suffixes.
    """
    final = path.resolve(strict=False)
    total = _windows_path_units(final)
    if total > _WINDOWS_MAX_PATH_UNITS:
        raise ExportError(f"Windows MAX_PATH exceeded ({total} > 259 UTF-16 units): {final}")
    if atomic and total + _ATOMIC_TEMP_EXTRA_UNITS > _WINDOWS_MAX_PATH_UNITS:
        raise ExportError(
            f"Windows MAX_PATH exceeded by temporary output filename "
            f"({total} + {_ATOMIC_TEMP_EXTRA_UNITS} > 259 UTF-16 units): {final}"
        )
    if _windows_path_units(final.parent) > _WINDOWS_MAX_DIRECTORY_UNITS:
        raise ExportError(f"Windows directory path too long for safe creation: {final.parent}")
    for part in final.parts:
        if len(part.encode("utf-16-le")) // 2 > 255:
            raise ExportError(f"Windows path component exceeds 255 UTF-16 units: {part}")

def _output_volume_free_bytes(output_root: Path) -> int:
    """Check the destination filesystem, even if the output doesn't exist."""
    parent = output_root.resolve(strict=False)
    while not parent.exists():
        if parent == parent.parent:
            raise ExportError(f"Cannot identify output filesystem: {output_root}")
        parent = parent.parent
    if not parent.is_dir():
        raise ExportError(f"Output filesystem ancestor is not a directory: {parent}")
    try:
        return shutil.disk_usage(parent).free
    except OSError as exc:
        raise ExportError(f"Cannot check free disk space on {parent}: {exc}") from exc

def _preflight_export_capacity(
    output_root: Path,
    target_exe: Path,
    metadata_objects: list[tuple[str, bytes]],
    export_assets: list[ManifestAsset],
    planned_asset_bytes: int,
    *,
    check_windows_paths: bool | None = None,
) -> None:
    """Fail before creating any output when space/Windows paths are unsafe."""
    if check_windows_paths is None:
        check_windows_paths = os.name == "nt"
    root = output_root.resolve(strict=False)
    if check_windows_paths:
        content = root / "OpenWF" / "Content"
        destinations: list[tuple[Path, bool]] = [
            (root / ".install-to-patch.in-progress", False),
            (root / ".install-to-patch.failed", False),
            (root / "Warframe.x64.exe", False),
            (content / "0" / "UNMANAGED", True),
        ]
        destinations.extend((content / "0" / name, True) for name, _ in metadata_objects)
        # The type isn't known until each asset is encoded. Eight hexadecimal
        # digits are a conservative filename-length upper bound (32-bit type).
        destinations.extend(
            (_safe_output_path(content, a.namespace, a.logical_path, 0xFFFFFFFF, a.hash_b64), True)
            for a in export_assets
        )
        for destination, atomic in destinations:
            _validate_windows_export_path(destination, atomic=atomic)
        print(f"[Path] Validated {len(destinations):,} output paths against Windows MAX_PATH (including temporary files)")
    try:
        exe_bytes = target_exe.stat().st_size
    except OSError as exc:
        raise ExportError(f"Cannot determine target executable size: {exc}") from exc
    # Metadata is written in addition to CDN assets; include everything and
    # retain a fixed headroom for allocation overhead, other writes and races.
    estimated = planned_asset_bytes + sum(len(data) for _name, data in metadata_objects) + exe_bytes
    margin = max(_DISK_SAFETY_MARGIN_BYTES, (estimated + 49) // 50)  # >=2% or 64 MiB
    required = estimated + margin
    available = _output_volume_free_bytes(root)
    print(f"[Disk] Estimated output {estimated / 1024**2:,.1f} MiB "
          f"+ margin {margin / 1024**2:,.1f} MiB "
          f"| available {available / 1024**2:,.1f} MiB")
    if available < required:
        raise ExportError(
            f"Insufficient free disk space for patch output: "
            f"need {required:,} bytes including safety margin, available {available:,} bytes "
            f"on destination filesystem ({root})"
        )

def _create_output(path: Path) -> tuple[Path, Path]:
    _validate_output_directory(path)
    path.mkdir(parents=True, exist_ok=True)
    _validate_output_directory(path)
    marker = path / ".install-to-patch.in-progress"
    marker.write_text("Patch export in progress; do not use this output yet.\n", encoding="utf-8")
    return path, marker

def export_patch(
    target_root: Path,
    base_root: Path,
    output_root: Path,
    *,
    manifest_type: int,
    dry_run: bool,
    require_complete: bool,
    required_manifest_families: tuple[str, ...] = (),
    type_evidence_path: Path | None = None,
    allow_cross_version_types: bool = False,
    cdn_reference_paths: list[Path] | None = None,
    try_oodle_outer: bool = True,
    recovered_cdn_dir: Path | None = None,
    recovered_h_only_dir: Path | None = None,
    u4401_patch: Path | None = None,
    u4401_report: Path | None = None,
    static_type_recovery: bool = True,
    require_static_types: bool = False,
    failure_collector: list[dict] | None = None,
    published_output_root: Path | None = None,
) -> int:
    if u4401_report is not None and u4401_patch is None:
        raise ExportError("--u4401-report requires --u4401-patch")
    if require_static_types and not static_type_recovery:
        raise ExportError("--require-static-types conflicts with --no-static-type-recovery")
    if allow_cross_version_types and type_evidence_path is None:
        raise ExportError("--allow-cross-version-types requires --type-evidence")
    evidence = (
        load_type_evidence(type_evidence_path, allow_cross_version=allow_cross_version_types)
        if type_evidence_path is not None else {}
    )
    cdn_references = CdnReferenceResolver(cdn_reference_paths) if cdn_reference_paths else None
    if cdn_references is not None and not dry_run:
        cdn_references.validate_output(output_root)
    recovery_source = None
    if recovered_cdn_dir is not None:
        # This loader performs no HTTP requests, and requires a complete
        # downloader report. Each selected asset is rechecked against the
        # current manifest before output is created.
        from recovery_imports import RecoveredCdnCollection
        recovery_source = RecoveredCdnCollection(recovered_cdn_dir)
    h_only_source = None
    if recovered_h_only_dir is not None:
        from recovery_imports import RecoveredHOnlyCollection
        h_only_source = RecoveredHOnlyCollection(recovered_h_only_dir)
    u4401_source = None
    if u4401_patch is not None:
        from recovery_imports import ExactSourceCollection
        u4401_source = ExactSourceCollection(u4401_patch, u4401_report)
    if u4401_source is not None:
        overlap = u4401_source.rows.keys() & ((recovery_source.rows.keys() if recovery_source else set()) | (h_only_source.rows.keys() if h_only_source else set()))
        if overlap:
            raise ExportError("Source patch overlaps an explicitly supplied recovery folder")
    if recovery_source is not None and h_only_source is not None:
        overlap = recovery_source.rows.keys() & h_only_source.rows.keys()
        if overlap:
            raise ExportError('Same CDN asset appears in both recovery folders')
    target_root = target_root.resolve()
    base_root = base_root.resolve()
    target_cache = find_cache_windows_dir(target_root)
    base_cache = find_cache_windows_dir(base_root)
    _validate_source_and_output_paths(
        target_root,
        base_root,
        target_cache,
        base_cache,
        output_root,
        dry_run=dry_run,
    )
    if published_output_root is not None and not dry_run:
        # The final folder name can be longer than the short staging folder.
        # Validate both now, before writing any file.
        _validate_source_and_output_paths(
            target_root, base_root, target_cache, base_cache,
            published_output_root, dry_run=False,
        )
    if recovery_source is not None and not dry_run:
        output_resolved = output_root.resolve()
        if (output_resolved == recovery_source.root or
            output_resolved.is_relative_to(recovery_source.root) or
            recovery_source.root.is_relative_to(output_resolved)):
            raise ExportError('New patch output must not overlap the recovered CDN source')
    if h_only_source is not None and not dry_run:
        output_resolved = output_root.resolve()
        if (output_resolved == h_only_source.root or
            output_resolved.is_relative_to(h_only_source.root) or
            h_only_source.root.is_relative_to(output_resolved)):
            raise ExportError('New patch output must not overlap the recovered H-only source')
    if u4401_source is not None:
        for protected in (target_root, base_root, output_root.resolve()):
            if u4401_source.root == protected or u4401_source.root.is_relative_to(protected) or protected.is_relative_to(u4401_source.root):
                raise ExportError("Source patch and target/base/output directories must not overlap")
    target_exe = _find_target_exe(target_root)
    script_dir = Path(__file__).resolve().parent
    oodle = Oodle(script_dir)

    print(f"Warframe Install-to-Patch {VERSION}")
    print(f"Target install : {target_root}")
    print(f"Original base  : {base_root}")
    print(f"Output         : {output_root}")
    print(f"Manifest type  : 0x{manifest_type:X}")
    if recovery_source is not None:
        print(f"Recovered CDN  : {recovery_source.root} ({len(recovery_source.rows):,} report assets; offline)")
    if h_only_source is not None:
        print(f"Recovered H-only: {h_only_source.root} ({len(h_only_source.rows):,} report assets; offline)")
    if u4401_source is not None:
        print(f"Exact source patch: {u4401_source.root} ({len(u4401_source.rows)} validated identity candidates; offline)")
    print(f"Type recovery  : {'native/Packages enabled' if static_type_recovery else 'cache evidence only'}")
    if cdn_references is not None:
        print(f"CDN references : {len(cdn_references.patch_roots)} read-only patch(es)")
    if try_oodle_outer:
        print("Outer Oodle    : Leviathan-13 level 4 + verified 9-byte CRC32C footer (automatic)")
    if type_evidence_path is not None:
        strength_counts = Counter(ref.strength for ref in evidence.values())
        print(
            f"Type evidence  : {len(evidence)} eligible "
            f"({strength_counts['exact-hash']} exact-hash, "
            f"{strength_counts['cross-version']} cross-version)"
        )
        if allow_cross_version_types:
            print_warning("Cross-version type hints are not exact-hash confirmations.")
    print()

    target_index = scan_cache(target_cache, "HBF")
    base_index = scan_cache(base_cache, "HBF")
    if not base_index:
        raise ExportError(
            f"Original base Cache.Windows contains no usable live H entries: {base_cache}"
        )

    print("\n[Metadata] Recovering installed H.Cache.bin...")
    h_entry, h_header = _select_h_cache(target_index, oodle)
    h_obj = build_shcc(h_entry, None, None)
    h_index = parse_h_cache_header(h_header)
    b_records = [r for r in h_index.records if r.logical_path.startswith("/B.Cache.") and r.logical_path.endswith(".bin")]
    if not b_records:
        raise ExportError("Installed H.Cache.bin contains no B.Cache manifest records")
    print(f"[Metadata] H.Cache v{h_index.version} | {len(b_records)} B.Cache families")

    available_manifests = []
    missing_manifest_families = []
    manifest_assets_raw: list[ManifestAsset] = []
    metadata_objects: list[tuple[str, bytes]] = []
    h_name = f"H.Cache.bin!{manifest_type:X}_{H_CACHE_SENTINEL_HASH}"
    metadata_objects.append((h_name, h_obj))

    for record in b_records:
        match = H_CACHE_B_CACHE_RE.fullmatch(record.logical_path)
        if match is None:
            raise ExportError(f"Unsupported B.Cache family listed by H.Cache: {record.logical_path}")
        namespace = _manifest_namespace(record.logical_path)
        try:
            obj, header, _package = _build_h_only_metadata_object(
                target_index, record.logical_path, record.target_hash, oodle)
            assets = parse_manifest_header(header, namespace)
        except SourceCoverageError as exc:
            missing_manifest_families.append((record.logical_path, str(exc)))
            if not required_manifest_families:
                print(f"[Metadata] Missing source family: {record.logical_path} | {exc}")
            continue
        actual_hash = header[:16]
        if actual_hash != record.target_hash:
            raise ExportError(f"B.Cache hash mismatch after recovery: {record.logical_path}")
        filename = record.logical_path.lstrip("/") + f"!{manifest_type:X}_{b64m_encode(record.target_hash)}"
        metadata_objects.append((filename, obj))
        available_manifests.append(record.logical_path)
        manifest_assets_raw.extend(assets)
        counts = Counter(a.section for a in assets)
        print(
            f"[Metadata] {record.logical_path} (installed target) | "
            + " | ".join(f"{s}: {counts.get(s, 0):,}" for s in MANIFEST_SECTION_NAMES)
        )

    if not available_manifests:
        raise ExportError("No installed B.Cache manifests could be reconstructed")
    if missing_manifest_families and required_manifest_families:
        print(f'[Metadata] {len(missing_manifest_families)} additional manifest families not installed '
              '(out of selected scope; details in audit report)')
    missing_required = _missing_required_manifest_families(
        b_records, available_manifests, required_manifest_families)
    if missing_required:
        raise ExportError('Required installed-configuration manifests unavailable: '
            + ', '.join(missing_required))
    if required_manifest_families:
        print(f'[Manifest scope] {len(required_manifest_families)} explicitly required families '
              'verified; unavailable other configurations remain out of scope')

    manifest_assets, duplicates = _dedupe_manifest_assets(manifest_assets_raw)
    print(
        f"\n[Inventory] {len(manifest_assets):,} unique target objects from "
        f"{len(available_manifests)}/{len(b_records)} available manifest families "
        f"| duplicates ignored: {duplicates:,}"
    )

    changed: list[ManifestAsset] = []
    recovered_imports: list[ManifestAsset] = []
    recovered_h_imports: list[ManifestAsset] = []
    u4401_imports: list[ManifestAsset] = []
    unchanged = 0
    unknown_base = 0
    source_missing = 0
    inherited_from_base = 0
    base_inheritance_errors = 0
    proactive_fontcache = 0
    proactive_duplicate_packages = 0
    for i, asset in enumerate(manifest_assets, 1):
        if not (asset.flags & MANIFEST_FLAG_H):
            raise ExportError(
                f"Manifest entry has no H participation; unsupported for install reconstruction: "
                f"{asset.namespace}{asset.logical_path}"
            )
        # Source presence is checked before base classification so a language/DX family
        # that is represented by a manifest but not installed is reported as source coverage.
        required_piece_kinds = _required_piece_kinds(asset.flags)
        try:
            _select_h_by_hash(
                target_index,
                asset.namespace,
                asset.logical_path,
                asset.manifest_hash,
                oodle,
                required_piece_kinds=required_piece_kinds,
            )
            source_present = True
        except SourceCoverageError:
            source_present = False
        if not source_present:
            try:
                if _base_has_complete_inherited_asset(base_index, asset, oodle):
                    # A matching Steam base object should never be needlessly
                    # overwritten by a historical CDN download.
                    if ((recovery_source is not None and (asset.namespace, asset.logical_path) in recovery_source.rows) or
                        (h_only_source is not None and (asset.namespace, asset.logical_path) in h_only_source.rows) or
                        (u4401_source is not None and (asset.namespace, asset.logical_path) in u4401_source.rows)):
                        raise ExportError(f'Recovered CDN asset unexpectedly already inherited from base: {asset.namespace}{asset.logical_path}')
                    inherited_from_base += 1
                else:
                    if recovery_source is not None and (asset.namespace, asset.logical_path) in recovery_source.rows:
                        recovery_source.validate_asset(asset, oodle)
                        recovered_imports.append(asset)
                    elif h_only_source is not None and (asset.namespace, asset.logical_path) in h_only_source.rows:
                        h_only_source.validate_asset(asset, oodle)
                        recovered_h_imports.append(asset)
                    elif u4401_source is not None and (asset.namespace, asset.logical_path) in u4401_source.rows:
                        u4401_source.validate_asset(asset, oodle)
                        u4401_imports.append(asset)
                    else:
                        source_missing += 1
            except ExportError as exc:
                # Incomplete/corrupt base data is never silently called inherited.
                # Invalid recovery evidence is a hard error, not a source gap.
                if ((recovery_source is not None and (asset.namespace, asset.logical_path) in recovery_source.rows) or
                    (h_only_source is not None and (asset.namespace, asset.logical_path) in h_only_source.rows) or
                    (u4401_source is not None and (asset.namespace, asset.logical_path) in u4401_source.rows)):
                    raise
                source_missing += 1
                base_inheritance_errors += 1
                print(f"[Base inheritance error] {asset.namespace}{asset.logical_path} | {exc}")
            continue
        same, had_error = _base_matches(base_index, asset, oodle)
        is_fontcache = "/Temp/FontCache/" in asset.logical_path
        stale_duplicate_packages = []
        if same:
            try:
                stale_duplicate_packages = _duplicate_target_packages_not_updated(
                    target_index, base_index, asset, oodle
                )
            except ExportError as exc:
                print(f"[Duplicate package uncertainty] {asset.namespace}{asset.logical_path} | {exc}")
                had_error = True
        if had_error:
            unknown_base += 1
        elif same and not is_fontcache and not stale_duplicate_packages:
            unchanged += 1
        elif same and (is_fontcache or stale_duplicate_packages):
            changed.append(asset)
            if is_fontcache:
                proactive_fontcache += 1
            if stale_duplicate_packages:
                proactive_duplicate_packages += 1
                print(f"[Duplicate package refresh] {asset.namespace}{asset.logical_path} | "
                      f"base outdated in: {', '.join(stale_duplicate_packages)}")
        else:
            changed.append(asset)
        if i % 25000 == 0:
            print(
                f"[Compare] {i:,}/{len(manifest_assets):,} | changed/new {len(changed):,} | "
                f"unchanged {unchanged:,} | inherited {inherited_from_base:,} | unresolved {source_missing:,}"
            )

    if recovery_source is not None:
        used = {(a.namespace, a.logical_path) for a in recovered_imports}
        unused = recovery_source.rows.keys() - used
        if unused:
            sample = sorted(unused)[0]
            raise ExportError(f'Recovered CDN report contains {len(unused)} assets not eligible for target manifest import (first: {sample})')
    if h_only_source is not None:
        used = {(a.namespace, a.logical_path) for a in recovered_h_imports}
        unused = h_only_source.rows.keys() - used
        if unused:
            sample = sorted(unused)[0]
            raise ExportError(f'H-only recovery report has {len(unused)} assets not eligible for target manifest (first: {sample})')
    if u4401_source is not None:
        unused_u4401 = u4401_source.rows.keys() - {(a.namespace, a.logical_path) for a in u4401_imports}
        if unused_u4401:
            raise ExportError(f"{len(unused_u4401)} source-patch objects are not valid target/base source gaps")
    planned_bytes = (sum(a.cdn_size for a in changed) + sum(a.cdn_size for a in recovered_imports)
        + sum(a.cdn_size for a in recovered_h_imports) + sum(a.cdn_size for a in u4401_imports))
    print(
        f"[Compare] changed/new + proactive: {len(changed):,} | unchanged: {unchanged:,} | "
        f"inherited-from-base: {inherited_from_base:,} | source-unresolved: {source_missing:,} | "
        f"base-inheritance-errors: {base_inheritance_errors:,} | unknown-base: {unknown_base:,} | "
        f"FontCache proactive: {proactive_fontcache:,} | duplicate-package refresh: {proactive_duplicate_packages:,} | recovered-CDN: {len(recovered_imports):,} | "
        f"recovered-H-only: {len(recovered_h_imports):,} | source-patch exact: {len(u4401_imports):,}"
    )
    print(f"[Plan] {len(changed) + len(recovered_imports) + len(recovered_h_imports) + len(u4401_imports):,} CDN objects | {planned_bytes / (1024**2):,.1f} MiB")
    installed_resolver = None
    if static_type_recovery and (not dry_run or require_static_types):
        from installed_type_resolver import prepare
        installed_resolver = prepare(target_exe, target_index, oodle, required=require_static_types)
    if dry_run:
        print("[Dry run] No output was written.")
        partial_source = bool(source_missing or missing_manifest_families)
        if unknown_base or base_inheritance_errors:
            return 2
        if require_complete and partial_source:
            return 2
        return 0

    _preflight_export_capacity(
        output_root, target_exe, metadata_objects,
        changed + recovered_imports + recovered_h_imports + u4401_imports,
        planned_bytes,
    )
    if published_output_root is not None:
        _preflight_export_capacity(
            published_output_root, target_exe, metadata_objects,
            changed + recovered_imports + recovered_h_imports + u4401_imports,
            planned_bytes,
        )
    output_root, progress_marker = _create_output(output_root)
    content_root = output_root / "OpenWF" / "Content"
    metadata_dir = content_root / "0"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    _copy_target_exe(target_exe, output_root)

    for filename, data in metadata_objects:
        atomic_write(metadata_dir / filename, data)
    atomic_write(metadata_dir / "UNMANAGED", b"")
    print(
        f"[Output] Metadata: H.Cache.bin + {len(available_manifests)} B.Cache manifests + UNMANAGED"
    )

    reconstructed = 0
    failures: list[tuple[ManifestAsset, str]] = []
    section_counts: Counter[str] = Counter()
    evidence_used: Counter[str] = Counter()
    references_used = 0
    outer_encoded = 0
    for i, asset in enumerate(changed, 1):
        try:
            obj, type_id, _package, type_source = _build_object_for_asset(
                asset, target_index, oodle, evidence, cdn_references,
                try_oodle_outer=try_oodle_outer,
                installed_resolver=installed_resolver,
            )
            path = _safe_output_path(content_root, asset.namespace, asset.logical_path, type_id, asset.hash_b64)
            atomic_write(path, obj)
            reconstructed += 1
            section_counts[asset.section] += 1
            if type_source == "cdn-reference":
                references_used += 1
            else:
                if not obj.startswith(SHCC_PREAMBLE):
                    outer_encoded += 1
            if type_source is not None and type_source != "cdn-reference":
                evidence_used[type_source] += 1
                if type_source != "dx11-shader-cdn-map" or evidence_used[type_source] <= 5:
                    print(f"[Type] {asset.namespace}{asset.logical_path} | 0x{type_id:X} ({type_source})")
        except ExportError as exc:
            failures.append((asset, str(exc)))
            print_error(f"Export failed for {asset.namespace}{asset.logical_path} | {exc}")
            if failure_collector is not None:
                failure_collector.append({"namespace": asset.namespace, "path": asset.logical_path, "manifest_hash": asset.hash_b64, "error": str(exc)})
        if i % 1000 == 0 or i == len(changed):
            print(
                f"[Export] {i:,}/{len(changed):,} | written {reconstructed:,} | failed {len(failures):,}"
            )

    imported = 0
    for asset in recovered_imports:
        try:
            # Recheck immediately before copying to detect altered source files
            # between planning and output; never silently trust the report.
            data = recovery_source.validate_asset(asset, oodle)
            path = _safe_output_path(content_root, asset.namespace, asset.logical_path, 0xAA, asset.hash_b64)
            atomic_write(path, data)
            imported += 1
        except (OSError, ExportError) as exc:
            failures.append((asset, f'Recovered CDN import failed: {exc}'))
            print_error(f'Recovered CDN import failed for {asset.namespace}{asset.logical_path} | {exc}')
            if failure_collector is not None:
                failure_collector.append({"namespace": asset.namespace, "path": asset.logical_path, "manifest_hash": asset.hash_b64, "error": f'Recovered CDN import failed: {exc}'})
    if recovered_imports:
        print(f'[Recovered CDN] {imported:,}/{len(recovered_imports):,} copied from verified local source; no GET')

    imported_h_only = 0
    for asset in recovered_h_imports:
        try:
            data, type_id = h_only_source.validate_asset(asset, oodle)
            path = _safe_output_path(content_root, asset.namespace, asset.logical_path, type_id, asset.hash_b64)
            atomic_write(path, data)
            imported_h_only += 1
        except (OSError, ExportError) as exc:
            failures.append((asset, f'H-only CDN import failed: {exc}'))
            print_error(f'H-only CDN import failed for {asset.namespace}{asset.logical_path} | {exc}')
            if failure_collector is not None:
                failure_collector.append({"namespace": asset.namespace, "path": asset.logical_path, "manifest_hash": asset.hash_b64, "error": f'H-only CDN import failed: {exc}'})
    if recovered_h_imports:
        print(f'[Recovered H-only] {imported_h_only:,}/{len(recovered_h_imports):,} copied; no GET')

    imported_u4401 = 0
    for asset in u4401_imports:
        try:
            data, type_id = u4401_source.validate_asset(asset, oodle)
            path = _safe_output_path(content_root, asset.namespace, asset.logical_path, type_id, asset.hash_b64)
            atomic_write(path, data)
            imported_u4401 += 1
        except (OSError, ExportError) as exc:
            failures.append((asset, f'Source-patch exact import failed: {exc}'))
            print_error(f'Source-patch exact import failed for {asset.namespace}{asset.logical_path} | {exc}')
            if failure_collector is not None:
                failure_collector.append({"namespace": asset.namespace, "path": asset.logical_path, "manifest_hash": asset.hash_b64, "error": f'Source-patch exact import failed: {exc}'})
    if u4401_imports:
        print(f'[Source-patch exact] {imported_u4401:,}/{len(u4401_imports):,} copied; no GET')

    partial_source = bool(source_missing or missing_manifest_families)
    hard_failure = bool(failures or unknown_base or base_inheritance_errors or source_missing)
    export_failed = bool(hard_failure or (require_complete and partial_source))
    if export_failed:
        # A genuinely failed export must remain recognizable on disk. The
        # temporary marker is also retained if an unexpected exception or
        # process interruption stops execution before this point.
        progress_marker.replace(output_root / ".install-to-patch.failed")
    else:
        # Absent optional language/DX manifests are normal for an installed
        # configuration; they do not make a verified scoped export incomplete.
        progress_marker.unlink()

    print("\nSummary")
    print("-------")
    print(f"B.Cache families     : {len(available_manifests)}/{len(b_records)} available")
    if required_manifest_families:
        print(f"Required scope       : {len(required_manifest_families)} selected families verified")
    if missing_manifest_families:
        print("Other configurations: Not installed (normal for selected language/DX scope)")
    print(f"Manifest objects     : {len(manifest_assets):,}")
    print(f"Patch candidates     : {len(changed):,}")
    print(f"Objects written      : {reconstructed + imported + imported_h_only + imported_u4401:,}")
    print(f"Recovered CDN imports: {imported:,}")
    print(f"Recovered H-only     : {imported_h_only:,}")
    print(f"Source-patch exact imports: {imported_u4401:,}")
    print(f"Direct cache objects : {reconstructed - references_used - outer_encoded:,}")
    print(f"Outer Oodle objects  : {outer_encoded:,}")
    print(f"CDN reference copies : {references_used:,}")
    print(f"Unchanged base       : {unchanged:,}")
    print(f"Duplicate pkg refresh : {proactive_duplicate_packages:,}")
    print(f"Inherited from base  : {inherited_from_base:,}")
    print(f"Unresolved source    : {source_missing:,}")
    print(f"Base inherit errors  : {base_inheritance_errors:,}")
    print(f"Unknown base assets  : {unknown_base:,}")
    print(f"Reconstruction fail  : {len(failures):,}")
    if type_evidence_path is not None:
        print(
            f"External type hints : {evidence_used['exact-hash'] + evidence_used['cross-version']:,} "
            f"(exact {evidence_used['exact-hash']}, cross-version {evidence_used['cross-version']})"
        )
    print(f"Installed native IDs : {evidence_used['installed-native-parent']:,} dynamically resolved")
    print(f"DX11 shader CDN map  : {evidence_used['dx11-shader-cdn-map']:,} corrected filename types")
    print(
        "Sections             : "
        + " | ".join(f"{s} {section_counts.get(s, 0):,}" for s in MANIFEST_SECTION_NAMES)
    )
    print(f"Output               : {output_root}")

    if missing_manifest_families and not required_manifest_families:
        print("\nSource installation is missing these manifest families:")
        for path, reason in missing_manifest_families[:20]:
            print(f"  {path}: {reason}")
        if len(missing_manifest_families) > 20:
            print(f"  ... {len(missing_manifest_families) - 20} more")

    if failure_collector is not None:
        for kind, count in (("unknown-base", unknown_base), ("base-inheritance", base_inheritance_errors),
                ("missing-source", source_missing)):
            if count:
                failure_collector.append({"issue": kind, "count": count})
    if failures:
        print("\nPatch export FAILED: some objects could not be reconstructed exactly.")
        return 2
    if unknown_base or base_inheritance_errors:
        print("\nPatch export FAILED: some base cache entries could not be classified safely.")
        return 2
    if source_missing:
        print(f"\n[Error] {source_missing:,} assets in the selected manifest scope have no complete "
              "target/base cache source. Local-only reconstruction cannot invent missing data. "
              "The failed output must not be used.")
        return 2
    if require_complete and partial_source:
        print("\nPatch export FAILED: --require-complete requires every H.Cache-listed family.")
        return 2
    if missing_manifest_families:
        print("\nPatch export completed successfully for the installed configuration. "
              "Other language/DX configurations were not installed and are not included.")
    else:
        print("\nPatch export completed successfully.")
    return 0

def _parse_manifest_type(value: str) -> int:
    text = value.strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    try:
        parsed = int(text, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("manifest type must be hexadecimal, for example E or 0xE") from exc
    if not 0 <= parsed <= 0xFFFF:
        raise argparse.ArgumentTypeError("manifest type is out of range")
    return parsed

def main(argv: list[str] | None = None) -> int:
    parser = StrictArgumentParser(
        description=(
            "Reconstruct an OpenWF/NCT-style Warframe update patch from an installed target "
            "Cache.Windows tree and the original unupdated Steam base."
        )
    )
    parser.add_argument("target", type=Path, help="target/user Warframe install or Cache.Windows")
    parser.add_argument("base", type=Path, help="original unupdated Steam base or Cache.Windows")
    parser.add_argument("-o", "--output", type=Path, help="output directory; may exist if empty")
    parser.add_argument(
        "--manifest-type", type=_parse_manifest_type, default=0xE, metavar="HEX",
        help="H.Cache/B.Cache CDN type id (default: E, validated for U44)",
    )
    parser.add_argument("--dry-run", action="store_true", help="scan, parse and compare without writing output")
    parser.add_argument(
        "--recovered-cdn", type=Path, metavar="DIR",
        help="offline read-only recovered CDN directory (report + OpenWF/Content); revalidate every selected asset and include in a NEW patch output; never downloads",
    )
    parser.add_argument(
        "--recovered-h-only", type=Path, metavar="DIR",
        help="offline read-only directory of validated H-only CDN recovery objects",
    )
    parser.add_argument("--u4401-report", type=Path, metavar="JSON",
        help="explicit freshly generated exact source-patch comparison report (clean-run mode)")
    parser.add_argument("--u4401-patch", type=Path, metavar="DIR",
        help="read-only exact-identity source patch; uses the project-local verified comparison report; no downloads")
    parser.add_argument(
        "--try-oodle-outer", dest="try_oodle_outer", action="store_true", default=True,
        help="backward-compatible alias; standalone verified outer-CDN encoding is enabled by default",
    )
    parser.add_argument(
        "--no-outer-oodle", dest="try_oodle_outer", action="store_false",
        help="disable automatic Leviathan-4 outer-CDN reconstruction",
    )
    parser.add_argument(
        "--cdn-reference", type=Path, action="append", metavar="PATCH",
        help="read-only OpenWF patch to recover exact-hash/type/size CDN objects when direct reconstruction differs in size; may repeat",
    )
    parser.add_argument(
        "--no-static-type-recovery", dest="static_type_recovery", action="store_false", default=True,
        help="disable installed U44.0.0 EXE + Packages.bin static type derivation (for control comparisons)",
    )
    parser.add_argument(
        "--require-static-types", action="store_true",
        help="require verified installed native/Packages type recovery; fail closed if unavailable",
    )
    parser.add_argument(
        "--type-evidence", type=Path, metavar="JSON",
        help="reference-type-evidence.json; use only exact-hash type matches by default",
    )
    parser.add_argument(
        "--allow-cross-version-types", action="store_true",
        help="also allow unambiguous same-path type hints from two different reference patches",
    )
    parser.add_argument(
        "--required-manifest-family", action="append", default=[], metavar="/B.Cache.NAME.bin",
        help="require this exact H.Cache-listed manifest in the installed target; repeat to define an audited installed configuration",
    )
    parser.add_argument(
        "--require-complete", action="store_true",
        help="return incomplete if any H.Cache-listed language/DX family is absent from the installed target, or any manifest asset lacks source coverage",
    )
    parser.add_argument(
        "--audit-first", action="store_true",
        help="run full read-only manifest/base/H/B/F preflight before exporting; refuse export if audit has hard findings (extra scan)",
    )
    parser.add_argument(
        "--audit-report", type=Path, default=Path(__file__).resolve().parent / f'offline-patch-audit-preexport-v{VERSION}.json',
        help=f"JSON report path for --audit-first (default: ./offline-patch-audit-v{VERSION}.json)",
    )
    parser.add_argument(
        "--audit-deep-pieces", action="store_true",
        help="with --audit-first, also decompress every required reference/base B/F piece (slow)",
    )
    parser.add_argument('--keep-failed-output', action='store_true',
        help='keep failed temporary patch with .install-to-patch.failed for debugging (default: safely delete it)')
    parser.add_argument('--diagnostics-dir', type=Path, default=Path(__file__).resolve().parent,
        help='directory for timestamped export logs and result JSON (default: beside scripts)')
    parser.add_argument('--post-audit-report', type=Path,
        default=Path(__file__).resolve().parent / f'offline-patch-audit-postexport-v{VERSION}.json',
        help='deep post-export audit JSON path (default: beside scripts)')
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args(argv)

    if not args.target.exists() or not args.target.is_dir():
        parser.error(f"target path is not a directory: {args.target}")
    if not args.base.exists() or not args.base.is_dir():
        parser.error(f"base path is not a directory: {args.base}")

    output = args.output
    if output is None:
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output = Path.cwd() / f"{stamp}_update-patch-from-install"

    export_kwargs = dict(
        manifest_type=args.manifest_type,
        require_complete=args.require_complete,
        required_manifest_families=tuple(args.required_manifest_family),
        type_evidence_path=args.type_evidence,
        allow_cross_version_types=args.allow_cross_version_types,
        cdn_reference_paths=args.cdn_reference,
        try_oodle_outer=args.try_oodle_outer,
        recovered_cdn_dir=args.recovered_cdn,
        recovered_h_only_dir=args.recovered_h_only,
        u4401_patch=args.u4401_patch,
        u4401_report=args.u4401_report,
        static_type_recovery=args.static_type_recovery,
        require_static_types=args.require_static_types,
    )

    def preflight() -> bool:
        if not args.audit_first:
            return True
        from offline_patch_audit import audit
        print('[Preflight] Read-only manifest and cache audit before export')
        check = audit(target=args.target, base=args.base,
            recovered_cdn=args.recovered_cdn,
            recovered_h_only=args.recovered_h_only,
            u4401_patch=args.u4401_patch,
            u4401_report=args.u4401_report,
            deep_pieces=args.audit_deep_pieces,
            manifest_type=args.manifest_type,
            type_evidence_path=args.type_evidence,
            allow_cross_version_types=args.allow_cross_version_types,
            static_type_recovery=args.static_type_recovery,
            require_static_types=args.require_static_types,
            require_complete=args.require_complete,
            required_manifest_families=tuple(args.required_manifest_family))
        report_path = args.audit_report.resolve()
        for root in (args.target, args.base, args.recovered_cdn, args.recovered_h_only,
                args.u4401_patch, output):
            if root is not None and (report_path == root.resolve() or report_path.is_relative_to(root.resolve())):
                raise ExportError('Preflight report must be outside installation, recovery, and output roots')
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(check, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        print(f'[Preflight] {check["counts"]["manifest_objects"]:,} target assets; '
              f'{check["counts"]["expected_export_files"]:,} planned CDN files; '
              f'{check["hard_issue_total"]:,} hard issues')
        print(f'[Preflight report] {report_path}')
        if check['hard_issue_total']:
            print('[Preflight] Export blocked. Fix the listed issues before writing a patch.')
            return False
        return True

    if args.dry_run:
        # Non-writing diagnostics retain their existing behavior; no staging.
        try:
            if not preflight():
                return 2
            return export_patch(args.target, args.base, output, dry_run=True, **export_kwargs)
        except KeyboardInterrupt:
            print('Interrupted.', file=sys.stderr)
            return 130
        except (ExportError, OSError) as exc:
            print_error(exc)
            return 2

    from export_transaction import execute
    from offline_patch_audit import audit

    def verify_staged_patch(stage: Path) -> dict:
        print('[Post-export] Deep offline verification of temporary patch (before publication)')
        return audit(target=args.target, base=args.base, patch=stage,
            recovered_cdn=args.recovered_cdn,
            recovered_h_only=args.recovered_h_only,
            u4401_patch=args.u4401_patch,
            u4401_report=args.u4401_report,
            deep_patch=True, manifest_type=args.manifest_type,
            type_evidence_path=args.type_evidence,
            allow_cross_version_types=args.allow_cross_version_types,
            static_type_recovery=args.static_type_recovery,
            require_static_types=args.require_static_types,
            require_complete=args.require_complete,
            required_manifest_families=tuple(args.required_manifest_family))

    try:
        return execute(
            final_output=output, diagnostics_dir=args.diagnostics_dir, version=VERSION,
            keep_failed_output=args.keep_failed_output,
            protected_sources=(args.target, args.base, args.recovered_cdn,
            args.recovered_h_only, args.u4401_patch,
            *(args.cdn_reference or [])),
            post_audit_report=args.post_audit_report,
            preflight_report=args.audit_report if args.audit_first else None,
            preflight=preflight,
            export=lambda stage, failures: export_patch(
                args.target, args.base, stage, dry_run=False,
                failure_collector=failures, published_output_root=output, **export_kwargs),
            verify=verify_staged_patch,
        )
    except (ExportError, OSError, RuntimeError) as exc:
        print_error(exc)
        return 2

if __name__ == "__main__":
    # Keep helper-module imports bound to the same class definitions and
    # exceptions when this file is executed directly as a script.
    sys.modules.setdefault("warframe_install_to_patch", sys.modules[__name__])
    raise SystemExit(main())
