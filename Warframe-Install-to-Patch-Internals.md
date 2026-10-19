# Warframe Install-to-Patch — Internals

## Scope

v0.1 exports an **OpenWF-compatible U44.0.0 EN/DX11 patch** from an untouched
final installation and its original Steam base. It uses the four installed
`B.Cache.Windows` manifest families (base, `_en`, `_xx`, `Dx11`), not missing
language or DX12 variants. The normal reconstruction requires 100 exact
U44.0.0-identity objects obtainable from a U44.0.1 patch and three pinned
historical CDN objects. Other versions require their own recovery profile; the manifest parser alone
does not make the U44-specific recovery steps reusable without validation.

## Workflow

`install_to_patch.py`:

1. Validate the separate target, base, U44.0.1, workspace and output paths.
2. Fingerprint source TOCs, selected cache payloads and the executable.
3. Parse `H.Cache.bin`, installed manifests and source H/B/F cache entries.
4. Resolve native CDN types, base inheritance and missing source pieces.
5. Verify 100 exact-identity U44.0.1 objects and recover the three pinned CDN objects.
6. Export the selected objects and run pre-publication deep audits.
7. Optionally add every manifest-declared stripped asset (`-a`).
8. Recheck source fingerprints and publish the staged patch to a new directory.

The reference installations and U44.0.1 patch remain read-only. The exporter
never consumes old diagnostics, previous recovery directories or a previously
exported patch as evidence. Invalid inputs or unverifiable resources fail
without publishing a partial output.

## Verification

- Match manifest namespace, logical path, H hash, resolved CDN type, size and
  required H/B/F sections.
- Validate CRC32C, SHCC framing, decoded CommonHeader and section integrity.
  Supported outer Oodle streams may differ in compressor header bytes.
- Accept inherited content only when the original cache evidence matches.
- Verify all selected objects after staging. Missing or conflicting exact
  identities are errors; matching *paths* alone are never sufficient.
- `-f` additionally hashes every source cache payload at each fingerprint check.

The manifest's H hash authenticates the H CommonHeader, **not necessarily the
complete historical F payload**. CRC32C detects accidental corruption but is
not a historical cryptographic F hash. Original cache F matches provide
independent F-byte evidence when available.

## Original H.Cache.bin

An exact OpenWF supplemental filename is constructed from a unique target EXE
build label or explicit `-H LABEL`. Auto mode falls back to local reconstruction
when the file is unavailable. An explicit label requires the download. Invalid
or mismatching HTTP-200 objects are rejected. Downloads are bounded to 1 MiB
and redirects are refused.

An original `H.Cache.bin` may differ from the locally reconstructed CDN object
at the compression/wrapper level. Both are accepted only when the full decoded
H data matches the pristine target cache, with valid framing and CRC32C.
Replacement happens only in unpublished staging output. Existing patches with
a validated original file do not need regeneration.

## Stripped assets

`-a` or `add_stripped.py` works **only** on objects in the installed manifests'
`stripped` sections (528 entries for this U44.0.0 profile). The order of
recovery is original target/base cache, optional exact-identity source patch,
and explicitly enabled exact-ID CDN fallback. CDN downloads must match the
original manifest's identity, size and decoded sections. Newer different-H
objects are never substituted.

Standalone enrichment stages and verifies additions before copying them into
the patch. Exceptions and Ctrl+C roll back files created during that run;
forced termination or power loss may leave partial files, so back up the patch.
`-n` performs the same checks without publishing additions. An unresolved
dry-run exits with code 3. Integrated `-a` runs within the new patch's
unpublished transaction.

`add_stripped.py -A` performs a read-only audit of manifest-declared `.bk2`
F bytes. With `-s`, it compares same-path objects in update patches even if
H identities differ. Source-absent objects are reported as `not_present`, not
assumed unchanged. The audit never modifies or downloads asset objects.

## Reports and failure handling

Each public run writes a timestamped plain-text `.log` and JSON report in
`logs/`. The JSON records source checks, verification, recovery provenance,
CDN attempts and failure details. Intermediate report files use the v0.1
report format and are stored only in the isolated temporary workspace;
recovery imports revalidate their contents. Temporary files are discarded
after successful consolidation, or retained when requested for diagnosis.

CDN and original H.Cache downloads use bounded retries (default five) with
backoff for transient errors. Permanent 404/410 responses do not retry. Unrecognized verified CDN outer
formats are rejected. Downloaded bytes are not committed until validation
passes. Interactive status colors match NCT; logs remain ANSI-free.

## Modules

| Module | Responsibility |
| --- | --- |
| `data/warframe_install_to_patch.py` | Cache/manifest parsing, CDN object encoding, export engine |
| `data/rebuild_pristine_u4400.py`, `data/restore_u44_complete.py` | Clean source workflow and recovery staging |
| `data/inspect_*`, `data/compare_u4401_sources.py` | Installed-source inventory and exact-object comparison |
| `data/recover_*`, `data/recovery_imports.py` | Verified historical CDN and local source recovery |
| `data/installed_type_resolver.py` | Native PE/Packages-based CDN type resolution |
| `data/offline_patch_audit.py`, `data/stripped_archive.py` | Deep validation, stripped enrichment and video audit |
| `data/export_transaction.py`, `data/common.py` | Safe publication, source fingerprints, HTTP retry and logging |

The pinned x64 `data/oo2core_9.dll` is required and distributed with this
archive. It is third-party software; GPLv3 covers the project source, not
that binary. Check its redistribution rights before public release.
