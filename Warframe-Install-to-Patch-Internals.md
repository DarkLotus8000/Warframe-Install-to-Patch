# Warframe Install-to-Patch — Internals

## Scope

v0.1 exports an OpenWF-compatible patch from the intact installed manifests
and original Steam base. U44.0.0 EN/DX11 is the tested recovery case; the
installed B.Cache manifest families determine export scope. Recovery identities and counts are derived from the installed manifests.
Exact objects are reused from the supplied source patch when valid; otherwise
CDN candidates are resolved and validated. Native type analysis and the
installed-manifest scope still have U44-specific restrictions.

## Workflow

`install_to_patch.py`:

1. Validate the separate target, base, optional source patch, workspace and output paths.
2. Fingerprint source TOCs, selected cache payloads and the executable.
3. Parse `H.Cache.bin`, installed manifests and source H/B/F cache entries.
4. Resolve native CDN types, base inheritance and missing source pieces.
5. Verify exact source-patch identities and recover unresolved CDN objects.
6. Export the selected objects and run pre-publication deep audits.
7. Optionally add every manifest-declared stripped asset (`-a`).
8. Recheck source fingerprints and publish the staged patch to a new directory.

The reference installations and optional source patch remain read-only. The exporter
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

An exact OpenWF supplemental filename combines the date-only `buildLabel`
from EXE VERSIONINFO with the `/B.Cache.Windows.bin` hash in installed
`H.Cache.bin`, or uses an explicit `-H KEY`. Auto mode falls back to local reconstruction
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
`stripped` sections (the count comes from the installed manifest). The order of
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
| `data/rebuild_patch.py`, `data/source_inventory.py` | Clean source workflow and recovery staging |
| `data/inspect_*`, `data/compare_sources.py` | Installed-source inventory and exact-object comparison |
| `data/recover_manifest_sources.py`, `data/recovery_imports.py` | Verified historical CDN and local source recovery |
| `data/installed_type_resolver.py` | Native PE/Packages-based CDN type resolution |
| `data/offline_patch_audit.py`, `data/stripped_archive.py` | Deep validation, stripped enrichment and video audit |
| `data/export_transaction.py`, `data/common.py` | Safe publication, source fingerprints, HTTP retry and logging |

The required x64 `data/oo2core_9.dll` is bundled and SHA-256 pinned.
