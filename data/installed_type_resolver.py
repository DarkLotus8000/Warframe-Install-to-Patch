"""Verified installed-client native CDN type research and resolver.

Only build-locked U44.0.0 executable and Packages data contribute type evidence.
"""
from __future__ import annotations
from collections import defaultdict
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import warframe_install_to_patch as w

# ---- Static type / Packages inspection ----
KNOWN_EXE_HASHES = {
    "0464a0796cab2a2eef68804ca89d4ff1ba1ff1dc8eba401524fa7c45b9a36143": "original-U44.0.0",
    "5ac9833246c5e87659cf64fbf9306b6f7b10e06d050b94e5f879d69d85ca97dd": "verified-Sideloadify-U44.0.0",
}

EXPECTED_PACKAGES_HASH = "0oF6Th1ig3gXbWsatBvWdw"

ZSTD_DICTIONARY_MAGIC = b"\x37\xa4\x30\xec"

MAX_PACKAGES_LEN = 256 * 1024 * 1024

MAX_ENTITIES = 10_000_000

class ProbeError(Exception):
    pass

def u32(data: bytes, pos: int) -> int:
    if pos < 0 or pos + 4 > len(data):
        raise ProbeError(f"Truncated Packages.bin u32 at {pos}")
    return struct.unpack_from("<I", data, pos)[0]

def _v46_directory_candidate(data: bytes, pos: int) -> bool:
    """Match the validated Patch Repair v46 directory-block preflight."""
    if pos < 0 or pos + 9 > len(data):
        return False
    n = struct.unpack_from("<I", data, pos)[0]
    if not 1 <= n <= 4096:
        return False
    meta_at = pos + 4 + n
    if meta_at + 5 > len(data):
        return False
    name = data[pos + 4:meta_at]
    if not name.startswith(b"/") or any(c == 0 or c < 0x20 for c in name):
        return False
    # The byte at meta_at is opaque per-directory metadata.
    block_count = struct.unpack_from("<I", data, meta_at + 1)[0]
    return 1 <= block_count <= 5_000_000

def _parse_entity_table(data: bytes, pos: int, count: int, collect: bool) -> tuple[int, dict[str, str | None], int]:
    """Validate every entity; quarantine conflicting duplicate parent paths.

    None means at least two incompatible parents were seen for that path. The
    reference repairer's last-parent-wins policy is appropriate for its own
    workflows but must not be treated as conclusive evidence in this probe.
    """
    parents: dict[str, str | None] = {}
    seen = 0
    blocks = 0
    n = len(data)

    def get_string(offset: int, field: str, max_len: int = 65536) -> tuple[str, int]:
        length = u32(data, offset)
        offset += 4
        if length > max_len or offset + length > n:
            raise ProbeError(f"Invalid Packages.bin {field} size {length} at 0x{offset - 4:X}")
        raw = data[offset:offset + length]
        if b"\x00" in raw:
            raise ProbeError(f"Embedded NUL in Packages.bin {field} at 0x{offset:X}")
        # v46 uses byte strings. Other control bytes are not a rejection criterion.
        return raw.decode("latin-1"), offset + length

    while seen < count:
        directory, pos = get_string(pos, "directory", max_len=4096)
        if not directory.startswith("/"):
            raise ProbeError(f"Invalid Packages.bin directory at 0x{pos:X}")
        if pos + 5 > n:
            raise ProbeError("Truncated Packages.bin directory metadata")
        pos += 1  # Opaque directory metadata; both 0x00 and 0x01 are known.
        entries = u32(data, pos)
        pos += 4
        if not 1 <= entries <= count - seen:
            raise ProbeError(f"Invalid Packages.bin directory entity count {entries} at 0x{pos - 4:X}")
        blocks += 1
        for _ in range(entries):
            filename, pos = get_string(pos, "filename")
            if pos + 3 > n:
                raise ProbeError("Truncated Packages.bin entity metadata")
            pos += 3  # Opaque per-entity metadata, not a CDN type.
            parent, pos = get_string(pos, "parent")
            if collect:
                path = directory + filename
                resolved = parent if parent.startswith("/") else directory + parent if parent else ""
                if path not in parents:
                    parents[path] = resolved
                elif parents[path] != resolved:
                    # Once ambiguous, always ambiguous (including further records).
                    parents[path] = None
            seen += 1
    return pos, parents, blocks

def parse_packages_v46(data: bytes) -> tuple[dict[str, str | None], dict]:
    """Locate and validate a real v46 entity table using Patch Repair's layout.

    The locator is anchored on the embedded Zstd dictionary and verifies all
    entity entries; it never trusts offsets or infers types from false positives.
    """
    if len(data) < 8192 or len(data) > MAX_PACKAGES_LEN:
        raise ProbeError("Packages.bin length outside supported research bounds")
    hsize, version, flags = struct.unpack_from("<III", data, 16)
    if (hsize, version, flags) != (20, 46, 1):
        raise ProbeError(f"Unsupported Packages header: header={hsize}, version={version}, flags={flags}")
    anchor = 2048
    dictionary_candidates = 0
    table_candidates = 0
    errors: list[str] = []
    while (anchor := data.find(ZSTD_DICTIONARY_MAGIC, anchor)) != -1:
        if anchor >= 4:
            dictionary_length = u32(data, anchor - 4)
            count_at = anchor + dictionary_length
            if 4096 <= dictionary_length and count_at + 4 <= len(data):
                count = u32(data, count_at)
                if 1 <= count <= MAX_ENTITIES:
                    dictionary_candidates += 1
                    scan_start = count_at + 4
                    scan_end = min(len(data) - 9, scan_start + 8192)
                    for start in range(scan_start, scan_end + 1):
                        if not _v46_directory_candidate(data, start):
                            continue
                        table_candidates += 1
                        try:
                            end, _, blocks = _parse_entity_table(data, start, count, collect=False)
                            # Patch Repair accepts up to 4096 bytes of trailing metadata.
                            if len(data) - end > 4096:
                                raise ProbeError(f"Unexplained trailing bytes: {len(data) - end}")
                            end2, parents, blocks2 = _parse_entity_table(data, start, count, collect=True)
                            if end2 != end or blocks2 != blocks:
                                raise ProbeError("Entity table changed between validation passes")
                            conflicts = [path for path, parent in parents.items() if parent is None]
                            return parents, {
                                "version": version, "entities": count, "unique_paths": len(parents),
                                "ambiguous_parent_paths_count": len(conflicts),
                                "ambiguous_parent_paths_sample": conflicts[:20],
                                "duplicate_entity_records": count - len(parents),
                                "directory_blocks": blocks, "directory_table_offset": start,
                                "dictionary_offset": anchor, "dictionary_length": dictionary_length,
                                "trailing_bytes": len(data) - end,
                            }
                        except ProbeError as exc:
                            if len(errors) < 5:
                                errors.append(f"0x{start:X}: {exc}")
        anchor += 1
    detail = "; ".join(errors)
    raise ProbeError(
        "Packages.bin v46 dictionary/entity table not structurally verified "
        f"(dictionary candidates={dictionary_candidates}, table candidates={table_candidates})"
        + (f"; sample failures: {detail}" if detail else "")
    )

def select_h_entries(cache_dir: Path, names: set[str]) -> dict[str,list[w.CacheEntry]]:
    found: dict[str,list[w.CacheEntry]] = defaultdict(list)
    # Scan just H TOCs; avoid loading hundreds of thousands of entries into memory.
    for toc in sorted(cache_dir.glob('H.*.toc')):
        for entry in w.iter_toc_entries(toc, "H", toc.name[2:-4]):
            if entry.namespace == '0' and entry.logical_path in names:
                found[entry.logical_path].append(entry)
    return found

def load_verified_h(entries: list[w.CacheEntry], expected_b64: str, oodle: w.Oodle) -> tuple[bytes,w.CacheEntry]:
    matches: list[tuple[bytes,w.CacheEntry]] = []
    errors: list[str] = []
    for entry in entries:
        if not 16 <= entry.length <= MAX_PACKAGES_LEN:
            errors.append(f"Invalid H length in {entry.package}: {entry.length}")
            continue
        try:
            raw = w.decompress_cache_entry(entry, oodle)
            correct = w.b64m_encode(raw[:16]) == expected_b64
            # Installed H's digest covers the SHCC preamble followed by all H bytes after the digest.
            embedded_verified = (hashlib.md5(w.SHCC_PREAMBLE + raw[16:], usedforsecurity=False).digest() == raw[:16])
            if correct and embedded_verified:
                matches.append((raw,entry))
        except (w.ExportError, OSError, ValueError) as exc:
            errors.append(f"{entry.package}: {exc}")
    if not matches:
        raise ProbeError(f"No matching verified H entry for hash {expected_b64}; failures={errors[:3]}")
    # Identical H bytes are fine even when duplicate packages contain them.
    if len({hashlib.sha256(raw).digest() for raw, _ in matches}) != 1:
        raise ProbeError("Conflicting hash-matched H payloads")
    return matches[0]

def exe_native_types(exe: Path) -> tuple[dict[str,set[int]], dict]:
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    label = KNOWN_EXE_HASHES.get(digest)
    if not label:
        raise ProbeError(f"EXE SHA-256 {digest} is not a verified U44.0.0 build; refusing type extraction")
    with tempfile.TemporaryDirectory(prefix='wf-u44-types-') as temp:
        tempdir = Path(temp)
        # Run the scanner in a separate process, preserving its timeout and
        # crash boundary; write TSV files only to this private scratch space.
        try:
            cp = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                '--scan-native-types', str(exe), str(tempdir)],
                capture_output=True, text=True, timeout=240,
                env=os.environ.copy())
        except subprocess.TimeoutExpired as exc:
            raise ProbeError('Executable type extraction timed out') from exc
        if cp.returncode:
            raise ProbeError(f'EXE extraction failed using pefile; check optional dependencies. Tail: ' +
                (cp.stderr or cp.stdout)[-1200:])
        source = tempdir/'native_types.tsv'
        if not source.is_file():
            raise ProbeError('EXE extractor did not produce native_types.tsv')
        types: dict[str,set[int]] = defaultdict(set)
        rows = 0
        for line in source.read_text('utf-8').splitlines():
            parts = line.split('\t')
            if len(parts) < 2 or not re.fullmatch(r'[A-Fa-f0-9]+',parts[0]):
                continue
            if len(parts) > 2 and ('DX11' in parts[2] or 'DX12' in parts[2]):
                continue
            types[parts[1]].add(int(parts[0],16))
            rows += 1
        return types, {"exe_variant": label, "exe_sha256":digest, "native_rows":rows,
            "native_names":len(types), "extractor_output":cp.stdout[-1500:], "pe_backend":"pefile"}

def resolve_parent_type(child: str, parents: dict[str,str | None], native: dict[str,set[int]]) -> dict:
    chain: list[str] = []
    seen: set[str] = set()
    node = child
    status = 'end-of-parent-chain'
    while node and node not in seen and len(chain) < 128:
        seen.add(node)
        chain.append(node)
        if node in parents and parents[node] is None:
            status = 'ambiguous-packages-parent'
            break
        node = parents.get(node, '')
    else:
        if node:
            status = 'cycle-or-depth-limit'
    by_basename: dict[str,set[int]] = defaultdict(set)
    for name, ids in native.items():
        by_basename[name.rsplit('/',1)[-1]].update(ids)
    candidates = []
    for path in chain:
        direct = native.get(path)
        # Basename is only evidence if globally unambiguous.
        values = direct if direct else by_basename.get(path.rsplit('/',1)[-1])
        if values and len(values) == 1:
            candidates.append({"parent":path,"type":next(iter(values)),"match":"exact" if direct else "unique-basename"})
        elif values:
            candidates.append({"parent":path,"type":None,"match":"ambiguous-native-name"})
    types = {c['type'] for c in candidates if c['type'] is not None}
    ambiguous = any(c['match'] == 'ambiguous-native-name' for c in candidates)
    derived = next(iter(types)) if len(types) == 1 and not ambiguous and status == 'end-of-parent-chain' else None
    return {"parent_chain":chain,"chain_status":status,
            "native_matches":candidates, "derived_type_hex":f"0x{derived:X}" if derived is not None else None,
            "derivation_status":"unique-native-type" if derived is not None else
            ('ambiguous-packages-parent' if status == 'ambiguous-packages-parent' else
        'conflicting-native-types' if len(types)>1 else 'unresolved')}

# ---- Installed build-gated resolver ----
class InstalledTypeResolver:
    """Resolve absent CDN filename type IDs from native types and Packages parents."""

    def __init__(self, parents: dict[str, str | None], native: dict[str, set[int]]):
        # Reuse the strict Phase 7 conflict/cycle/basename rules. Cache each
        # distinct logical path because a CDN manifest can repeat it.
        self.parents = parents
        self.native = native
        self._cache: dict[str, w.TypeEvidence | None] = {}
        self.unresolved: dict[str, str] = {}

    def get(self, path: str) -> w.TypeEvidence | None:
        if path not in self._cache:
            # A coincidental native basename is not enough: the installed
            # Packages table must actually name the requested child resource.
            if path not in self.parents:
                self._cache[path] = None
                self.unresolved[path] = 'missing-packages-entity'
                return None
            result = resolve_parent_type(path, self.parents, self.native)
            value = result['derived_type_hex']
            if value is None:
                self._cache[path] = None
                self.unresolved[path] = result['derivation_status']
            else:
                self._cache[path] = w.TypeEvidence(int(value, 16), 'installed-native-parent')
        return self._cache[path]

def evidence_for_asset(
    resolver: InstalledTypeResolver | None,
    asset: w.ManifestAsset,
    header_type: int | None,
) -> w.TypeEvidence | None:
    """Share the exact same native-evidence eligibility rule with the auditor."""
    if resolver is None or asset.namespace != '0':
        return None
    key = (asset.namespace, asset.logical_path, asset.hash_b64)
    if header_type is not None and key not in w._BUILTIN_U44_TYPES:
        return None
    return resolver.get(asset.logical_path)

def prepare(target_exe: Path, target_index, oodle: w.Oodle, *, required: bool = False) -> InstalledTypeResolver | None:
    """Load U44 native mappings and matching installed Packages.bin once.

    In default compatibility mode a missing optional package or unsupported
    executable leaves the original exporter fallbacks available. Strict mode
    refuses these cases. Successfully recovered contradictory IDs always fail.
    """
    try:
        with target_exe.open('rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
    except OSError as exc:
        raise w.ExportError(f'Cannot read target EXE for static type recovery: {exc}') from exc
    if digest not in KNOWN_EXE_HASHES:
        if required:
            raise w.ExportError('Static type recovery requires a verified U44.0.0 EXE (unknown SHA-256)')
        print('[Static types] Unsupported EXE build; skipping U44-specific native/Packages recovery')
        return None
    missing = [mod for mod in ('pefile', 'capstone', 'numpy') if importlib.util.find_spec(mod) is None]
    if missing:
        message = f"Optional EXE analysis dependencies missing: {', '.join(missing)}; install dependencies from requirements.txt"
        if required:
            raise w.ExportError(message)
        print(f'[Static types] {message}; retaining hash-locked fallback behavior')
        return None
    try:
        native, details = exe_native_types(target_exe)
        entries = [
            e for e in w._entries_for(target_index, '0', '/Packages.bin', 'H')
            if e.package.casefold() == 'misc'
        ]
        if not entries:
            raise ProbeError('Verified /Packages.bin entry not found in installed H.Misc.toc')
        raw, _selected = load_verified_h(entries, EXPECTED_PACKAGES_HASH, oodle)
        parents, meta = parse_packages_v46(raw)
    except (ProbeError, w.ExportError, OSError, ValueError) as exc:
        if required:
            raise w.ExportError(f'Static type recovery failed: {exc}') from exc
        print(f'[Static types] Recovery unavailable ({exc}); retaining hash-locked fallback behavior')
        return None
    return InstalledTypeResolver(parents, native)

def preflight_pinned_types(resolver: InstalledTypeResolver, target_index, oodle: w.Oodle,
        manifest_assets: list[w.ManifestAsset], *, required: bool = False) -> int:
    """Cross-check the five hash-locked hints *before* creating output.

    All selected H bytes must match the manifest digest, not merely the path.
    Native mismatches are never hidden by the legacy fallback registry.
    """
    count = 0
    for asset in manifest_assets:
        key = (asset.namespace, asset.logical_path, asset.hash_b64)
        fallback = w._BUILTIN_U44_TYPES.get(key)
        if fallback is None:
            continue
        entries = w._entries_for(target_index, asset.namespace, asset.logical_path, 'H')
        try:
            load_verified_h(entries, asset.hash_b64, oodle)
        except ProbeError as exc:
            if required:
                raise w.ExportError(f'Static type preflight cannot verify {asset.logical_path}: {exc}') from exc
            print(f'[Static types] Cannot confirm installed H for {asset.logical_path}: {exc}')
            continue
        derived = resolver.get(asset.logical_path)
        if derived is None:
            if required:
                raise w.ExportError(f'Static type unresolved for {asset.logical_path}: '
                    f"{resolver.unresolved.get(asset.logical_path)}")
            print(f'[Static types] {asset.logical_path}: unresolved native/Packages chain; legacy fallback retained')
            continue
        if derived.type_id != fallback.type_id:
            raise w.ExportError(f'Static type disagrees with bundled U44 evidence for {asset.logical_path}: '
                f'installed 0x{derived.type_id:X}, bundled 0x{fallback.type_id:X}')
        count += 1
    if required and count != len(w._BUILTIN_U44_TYPES):
        raise w.ExportError(f'Static type preflight verified {count}/{len(w._BUILTIN_U44_TYPES)} pinned U44 resources')
    if count:
        print(f'[Static types] {count}/{len(w._BUILTIN_U44_TYPES)} pinned CDN types verified')
    return count

# ---- Isolated PE interpreter / native CDN type scanner ----
# Keep this specialized scanner private to the resolver module while
# retaining separate-process isolation and temporary TSV output files.
def _scan_executable_types(exe_path: Path, output_dir: Path) -> None:
    # Extract native cache type IDs from the verified Warframe.x64.exe.
    # Output: native_types.tsv. Extensionless assets inherit the native type
    # at the end of their Packages.bin parent chain.
    # Platform 0 = Windows content; 9 = DX11 shaders; A = DX12 shaders.
    # Called only through the private --scan-native-types subprocess.
    # Dependencies: pefile, capstone, numpy.

    # Native PE memory and instruction interpreter.
    import capstone, struct, re
    def open_pe(path: str):
        """Open the executable as a read-only memory-mapped PE image."""
        try:
            import pefile
        except ImportError as exc:
            raise RuntimeError("pefile is required; install requirements.txt") from exc
        pe = pefile.PE(str(path), fast_load=True)
        return pe, pe.get_memory_mapped_image()
    from capstone import x86
    pe, img = open_pe(str(exe_path))
    base = pe.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
    text = next(s for s in pe.sections if s.Name.startswith(b".text"))
    rdata = next(s for s in pe.sections if s.Name.startswith(b".rdata"))
    def q(a): return struct.unpack_from("<Q", img, a)[0]
    M64 = (1 << 64) - 1
    FULL = {}
    for r64, r32, r16, r8 in [("rax","eax","ax","al"),("rbx","ebx","bx","bl"),("rcx","ecx","cx","cl"),("rdx","edx","dx","dl"),
            ("rsi","esi","si","sil"),("rdi","edi","di","dil"),("rbp","ebp","bp","bpl"),("rsp","esp","sp","spl")] + \
            [(f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b") for i in range(8, 16)]:
        FULL[r64] = (r64, 64); FULL[r32] = (r64, 32); FULL[r16] = (r64, 16); FULL[r8] = (r64, 8)
    class Fail(Exception): pass
    def run(fn, dl, max_steps=400, globals_=None):
        """globals_: {rva: value} for runtime globals in .data that the function reads."""
        globals_ = globals_ or {}
        R = {k: 0 for k in set(v[0] for v in FULL.values())}
        R["rdx"] = dl; R["rsp"] = 0x10000; stack = {}
        ZF = CF = SF = OF = False
        pc = fn; ret_stack = [None]; steps = 0
        def rget(name):
            full, bits = FULL[name]; return R[full] & ((1 << bits) - 1)
        def rset(name, v):
            full, bits = FULL[name]; v &= (1 << bits) - 1
            if bits == 32: R[full] = v
            elif bits == 64: R[full] = v
            else: R[full] = (R[full] & ~((1 << bits) - 1) & M64) | v
        def addr(ins, o):
            m = o.mem
            if m.base == x86.X86_REG_RIP: return ("img", ins.address + ins.size + m.disp)
            a = m.disp
            if m.base: a += R[FULL[ins.reg_name(m.base)][0]]
            if m.index: a += R[FULL[ins.reg_name(m.index)][0]] * m.scale
            return ("stk", a & M64)
        def get(ins, o):
            if o.type == x86.X86_OP_IMM: return o.imm & ((1 << (o.size*8)) - 1)
            if o.type == x86.X86_OP_REG: return rget(ins.reg_name(o.reg))
            kind, a = addr(ins, o)
            if kind == "stk" and rdata.VirtualAddress <= a < rdata.VirtualAddress + rdata.Misc_VirtualSize:
                kind = "img"  # register holding a lea'd .rdata address, e.g. a per-platform lookup table
            if kind == "img" and a in globals_:
                return globals_[a] & ((1 << (o.size*8)) - 1)
            if kind == "img":
                if not (rdata.VirtualAddress <= a < rdata.VirtualAddress + rdata.Misc_VirtualSize): raise Fail(f"reads runtime global at {ins.address:#x}")
                return int.from_bytes(img[a:a+o.size], "little")
            if a < 0x8000 or a > 0x20000: raise Fail(f"reads object field at {ins.address:#x}")
            return stack.get(a, 0) & ((1 << (o.size*8)) - 1)
        def put(ins, o, v):
            if o.type == x86.X86_OP_REG: rset(ins.reg_name(o.reg), v); return
            kind, a = addr(ins, o)
            if kind != "stk" or a < 0x8000 or a > 0x20000: raise Fail("store outside stack")
            stack[a] = v & ((1 << (o.size*8)) - 1)
        def cond(cc):
            return {"e":ZF,"z":ZF,"ne":not ZF,"nz":not ZF,"b":CF,"c":CF,"ae":not CF,"nc":not CF,"be":CF or ZF,"a":not (CF or ZF),
                    "l":SF != OF,"ge":SF == OF,"le":ZF or SF != OF,"g":not ZF and SF == OF,"s":SF,"ns":not SF}[cc]
        while True:
            steps += 1
            if steps > max_steps: raise Fail("steps")
            ins = next(md.disasm(img[pc:pc+16], pc), None)
            if ins is None: raise Fail("decode")
            m, ops = ins.mnemonic, ins.operands; nxt = pc + ins.size
            if m == "ret":
                r = ret_stack.pop()
                if r is None: return R["rax"] & 0xFFFF
                R["rsp"] += 8; pc = r; continue
            if m == "call":
                if ops[0].type != x86.X86_OP_IMM: raise Fail("indirect call")
                R["rsp"] -= 8; ret_stack.append(nxt); pc = ops[0].imm; continue
            if m == "jmp":
                if ops[0].type != x86.X86_OP_IMM: raise Fail("indirect jmp")
                pc = ops[0].imm; continue
            if m.startswith("j"):
                pc = ops[0].imm if cond(m[1:]) else nxt; continue
            if m == "push": R["rsp"] -= 8; stack[R["rsp"]] = get(ins, ops[0]); pc = nxt; continue
            if m == "pop": put(ins, ops[0], stack.get(R["rsp"], 0)); R["rsp"] += 8; pc = nxt; continue
            if m in ("nop", "int3") and m == "nop": pc = nxt; continue
            if m in ("mov", "movzx"): put(ins, ops[0], get(ins, ops[1])); pc = nxt; continue
            if m == "movsx":
                v = get(ins, ops[1]); b = ops[1].size*8
                if v >> (b-1): v -= 1 << b
                put(ins, ops[0], v); pc = nxt; continue
            if m == "lea":
                kind, a = addr(ins, ops[1]); put(ins, ops[0], a); pc = nxt; continue
            if m.startswith("cmov"):
                if cond(m[4:]): put(ins, ops[0], get(ins, ops[1]))
                elif ops[0].size == 4: put(ins, ops[0], get(ins, ops[0]))
                pc = nxt; continue
            if m.startswith("set"):
                put(ins, ops[0], 1 if cond(m[3:]) else 0); pc = nxt; continue
            if m in ("add","sub","cmp","and","or","xor","test","inc","dec","shl","shr","imul","neg"):
                bits = ops[0].size*8; mask = (1 << bits) - 1
                a = get(ins, ops[0])
                b = get(ins, ops[1]) if len(ops) > 1 else (1 if m in ("inc","dec") else 0)
                if m in ("add","inc"): r = a + b
                elif m in ("sub","cmp","dec"): r = a - b
                elif m in ("and","test"): r = a & b
                elif m == "or": r = a | b
                elif m == "xor": r = a ^ b
                elif m == "shl": r = a << b
                elif m == "shr": r = a >> b
                elif m == "neg": r = -a
                elif m == "imul": r = a * (get(ins, ops[2]) if len(ops) > 2 else b)
                if m in ("sub","cmp"): CF = a < b
                elif m == "add": CF = r > mask
                else: CF = False
                r &= mask; ZF = r == 0; SF = bool(r >> (bits-1)); OF = False
                if m not in ("cmp","test"): put(ins, ops[0], r)
                pc = nxt; continue
            raise Fail(f"{ins.address:#x} {m} {ins.op_str}")

    # Native-type discovery using validated executable tables.
    import collections

    PLATFORM_WINDOWS = 0
    SHADER_PLATFORMS = { 0x9: "DX11 (Content/9)", 0xA: "DX12 (Content/A)" }

    def runtime_global_of(err):
        # rva of the .data global that an instruction named in a Fail message reads
        m = re.search(r"reads runtime global at (0x[0-9a-f]+)", err)
        if not m: return None
        a = int(m.group(1), 16)
        ins = next(md.disasm(img[a:a+16], a))
        for o in ins.operands:
            if o.type == x86.X86_OP_MEM and o.mem.base == x86.X86_REG_RIP:
                return ins.address + ins.size + o.mem.disp

    def run_with_globals(f, dl):
        # Runtime globals default to 0; for shaders that means "not the active API / no special mode", which is how the shipped cache is built.
        gl = {}
        for _ in range(8):
            try: return run(f, dl, globals_=gl)
            except Fail as e:
                g = runtime_global_of(str(e))
                if g is None or g in gl: raise
                gl[g] = 0
        raise Fail("too many globals")

    tx = img[text.VirtualAddress:text.VirtualAddress+text.Misc_VirtualSize]
    # ---- Native types ----
    # Each native type is registered by a static initializer:
    # lea rdx, "<Name>"; call MakeStr; lea rdx, "<Package>"; call MakeStr; ...; lea rcx, <factory>; ...; call Register
    # The factory constructs the object; the last vtable it stores is the type's own. Slot 22 is the extension list getter
    # (same as for the extension scan above, whose type getter is 12 slots later), so the type getter is slot 34.
    import bisect, numpy as np
    EXT_SLOT = 22
    TYPE_SLOT = EXT_SLOT + 12

    _pdata = next(s for s in pe.sections if s.Name.startswith(b".pdata"))
    _pd = img[_pdata.VirtualAddress:_pdata.VirtualAddress + _pdata.Misc_VirtualSize]
    _starts = sorted(struct.unpack_from("<I", _pd, i)[0] for i in range(0, len(_pd) - 11, 12) if struct.unpack_from("<I", _pd, i)[0])
    def fstart(a):
        return _starts[bisect.bisect_right(_starts, a) - 1]

    def section_of(t):
        for s in pe.sections:
            if s.VirtualAddress <= t < s.VirtualAddress + s.Misc_VirtualSize: return s.Name.rstrip(b"\0").decode()

    def string_at(t):
        b = img[t:t+128].split(b"\0")[0]
        return b.decode() if b and all(32 <= c < 127 for c in b) else None

    def rip_lea(ins):
        if ins.mnemonic == "lea" and ins.operands[1].type == x86.X86_OP_MEM and ins.operands[1].mem.base == x86.X86_REG_RIP:
            return ins.address + ins.size + ins.operands[1].mem.disp

    # direct call sites, grouped by target
    _tb = np.frombuffer(text.get_data(), dtype=np.uint8).astype(np.int64)
    _pos = np.where(_tb[:-5] == 0xE8)[0]
    _rel = _tb[_pos+1] | (_tb[_pos+2]<<8) | (_tb[_pos+3]<<16) | (_tb[_pos+4]<<24)
    _rel = np.where(_rel >= 1<<31, _rel - (1<<32), _rel)
    _call_site = text.VirtualAddress + _pos
    _call_tgt = _call_site + 5 + _rel

    def find_register():
        # Register = the second call after a "lea rdx, <package>" in the registration pattern; take the most common one.
        pkg = img.find(b"\0/EE/Types/GraphicsRes/\0") + 1
        votes = collections.Counter()
        for m in re.finditer(rb"\x48\x8d\x15(....)", tx, re.S):
            a = text.VirtualAddress + m.start()
            if a + 7 + struct.unpack("<i", m.group(1))[0] != pkg: continue
            calls = [i.operands[0].imm for i in md.disasm(img[a:a+0x60], a) if i.mnemonic == "call" and i.operands[0].type == x86.X86_OP_IMM]
            if len(calls) >= 2: votes[calls[1]] += 1
        return votes.most_common(1)[0][0]

    def vtable_of(factory, depth=0):
        last = None; pend = None; calls = []
        for n, ins in enumerate(md.disasm(img[factory:factory+800], factory)):
            t = rip_lea(ins)
            if t is not None:
                pend = (ins.reg_name(ins.operands[0].reg), t) if section_of(t) == ".rdata" else None
            elif ins.mnemonic == "mov" and pend and ins.operands[0].type == x86.X86_OP_MEM and ins.operands[0].mem.disp == 0 \
                    and ins.operands[0].mem.index == 0 and ins.operands[1].type == x86.X86_OP_REG and ins.reg_name(ins.operands[1].reg) == pend[0]:
                last = pend[1]
            if ins.mnemonic == "call" and ins.operands[0].type == x86.X86_OP_IMM: calls.append(ins.operands[0].imm)
            if ins.mnemonic == "jmp" and ins.operands[0].type == x86.X86_OP_IMM and last is None and depth < 2:
                return vtable_of(ins.operands[0].imm, depth + 1)
            if ins.mnemonic in ("ret", "int3") or n > 200: break
        if last is None and calls and depth < 2:
            return vtable_of(calls[0], depth + 1)
        return last

    register = find_register()
    native = []  # (type or None, path, note)
    for site in _call_site[_call_tgt == register].tolist():
        f = fstart(site); strs = []; texts = []
        for ins in md.disasm(img[f:site], f):
            t = rip_lea(ins)
            if t is None: continue
            sec = section_of(t)
            if sec == ".text": texts.append(t)
            elif sec == ".rdata" and string_at(t): strs.append(string_at(t))
        pkg = next((s for s in strs[1:] if s.startswith("/")), None)
        if not strs or not pkg or not texts: continue
        path = pkg + strs[0]
        vt = vtable_of(texts[-1])
        if vt is None:
            native.append((None, path, "ERR no vtable")); continue
        fn = q(vt + 8*TYPE_SLOT) - base
        try:
            native.append((run(fn, PLATFORM_WINDOWS), path, ""))
        except Fail as e:
            if runtime_global_of(str(e)) is None:
                native.append((None, path, "ERR " + str(e)))
            else:
                for dl, name in SHADER_PLATFORMS.items():
                    try: native.append((run_with_globals(fn, dl), path, name))
                    except Fail as e2: native.append((None, path, f"{name} ERR {e2}"))
    # Registered types that aren't cached resources (editor commands, components, ...) have some other method in the type
    # slot, which evaluates to 0 or not at all; leave those out.
    resolved = sorted((r for r in native if r[0]), key=lambda r: r[1])
    with open(str(output_dir / "native_types.tsv"), "w") as fh:
        for t, path, note in resolved:
            fh.write(f"{t:X}\t{path}\t{note}\n")
    print(len(native), "native types,", len(resolved), "with a cache type")

def _run_internal_scanner(argv: list[str]) -> int:
    if len(argv) != 3 or argv[0] != '--scan-native-types':
        raise SystemExit('Internal use only: --scan-native-types EXE OUTPUT_DIR')
    exe_path, output_dir = Path(argv[1]), Path(argv[2])
    if not exe_path.is_file() or not output_dir.is_dir():
        raise SystemExit('EXE or output directory unavailable for internal type scan')
    _scan_executable_types(exe_path, output_dir)
    return 0

if __name__ == '__main__':
    raise SystemExit(_run_internal_scanner(sys.argv[1:]))
