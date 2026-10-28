# Warframe Install-to-Patch

Reconstruct an OpenWF-compatible Warframe update patch from an untouched final installation and its original Steam base. The recovery path discovers missing objects from installed manifests; U44.0.0 EN/DX11 is the tested profile.

## Requirements

- Windows 10 (64-bit) or newer
- Python 3.11+

```cmd
py -m pip install -r requirements.txt
```

## Usage

Reconstruct a patch using the final installation, original Steam base, and an optional recovery source patch:

```cmd
py install_to_patch.py -t "D:\Warframe\Final" -b "D:\Warframe\SteamBase" -u "D:\Patches\44.0.1" -P "D:\Patches"
```

Omit `-u` to attempt unresolved objects directly from the original CDN. Add `-a -c` to include all stripped assets with CDN fallback. The input installations and existing patches are not modified. Use a final installation that has not been launched through OpenWF.

Use separately saved local assets without any network access:

```cmd
py install_to_patch.py -t "D:\Warframe\Final" -b "D:\Warframe\SteamBase" --local-assets "D:\U44 Sample\AbilityVideos" --offline -P "D:\Patches" -k
```

The local folder is read-only and searched recursively for `name!TYPE_HASH` files. Filenames locate candidates; their manifest size, H hash/type, container structure and CRC must validate before a copy enters the isolated recovery workspace. Each accepted object records its original path and SHA-256. Extra sample files are ignored. Ambiguous, unreadable or invalid matching files are reported and never silently replaced through network fallback.

`--offline` disables CDN requests and the optional H.Cache lookup. Missing objects remain listed individually with their cache-source reason; an incomplete patch is never published. `-k` retains validated recovery copies as well as reports when some objects remain missing. Without `--offline`, local assets are tried before the existing CDN fallback. Validation establishes H identity and container integrity, not independent historical authentication of F bytes using a whole-object manifest digest.

Missing sources produce the status `incomplete-sources` and exit code **3**, with the recovery totals and missing-file list at the top level of the JSON report. Software/validation exceptions remain failures (exit code 2). Source fingerprinting prints progress for large files at five-second intervals, including bytes processed.

To recheck an explicitly retained workspace offline without rescanning unchanged installations or requiring the original loose-asset folder:

```cmd
py data\recover_manifest_sources.py --probe --offline --workspace "D:\WF-Rebuild\RUN_ID" --target "D:\Warframe\Final" --base "D:\Warframe\SteamBase"
```

This validates the current source snapshot and rechecks staged files using their recovery reports, SHA-256 and manifest identity. It retains provenance and makes no network requests. Public patch builds still create fresh workspaces. `--probe` writes a diagnostic report, not a patch.

Check an existing patch for missing stripped assets without changing it:

```cmd
py add_stripped.py -p "D:\Patches\44.0.0" -t "D:\Warframe\Final" -b "D:\Warframe\SteamBase" -s "D:\Patches\44.0.1" -c -n
```

Remove `-n` to add verified missing assets. Use `-A` instead for a read-only video audit; `-A -s SOURCE` compares videos with another patch.

Check whether unresolved CDN objects have surviving data in live or deleted cache TOC records (offline, read-only). Reuse the JSON from a completed export:

```cmd
py data\inspect_missing_source.py "D:\Warframe\Final" "D:\Warframe\SteamBase" --residual-run-report "logs\RUN_ID.json" -o "logs\offline-residual-probe.json"
```

This probe reports candidates only. It never imports uncertain video bytes or replaces the existing exact-identity recovery checks.

Additional read-only diagnostics accept reports with any supported object count (up to 512 for gap scanning):

```cmd
py data\probe_unindexed_cache.py residual.json missing-source.json gaps.json
py data\inspect_video_samples.py "D:\Samples" residual.json missing-source.json samples.json
```

The gap scanner searches H bytes and unindexed H/B/F regions. The sample checker compares cache/TOC files directly in the sample folder and recursively inspects `*.bk2!AA_HASH` assets, including videos outside AbilityVideos. Output reports must be new files outside the source folders. Neither diagnostic imports objects.

## Options

**`install_to_patch.py`**

- `-t, --target PATH` - Final installation (required)
- `-b, --base PATH` - Original Steam base (required)
- `-u, --source-patch PATH` - Optional exact-identity recovery source
- `--local-assets PATH` - Read-only folder of local asset candidates
- `--offline` - Disable network recovery and H.Cache lookup (incompatible with `-c` and `-H`)
- `-P, --output-parent PATH` - Parent directory for a new patch
- `-o, --output PATH` - Exact new output directory (alternative to `-P`)
- `-a, --all-stripped` - Include all stripped assets
- `-c, --stripped-cdn-fallback` - Enable CDN fallback with `-a`
- `-H, --h-cache-archive-key KEY` - Select an original H.Cache archive
- `-w, --work-parent PATH` - Temporary workspace parent
- `-l, --logs-dir PATH` - Log directory
- `-r, --cdn-retries N` - CDN download attempts
- `-T, --cdn-timeout SECONDS` - Download timeout
- `-f, --full-source-hash` - Hash all source cache payloads
- `-e, --keep-failed-output` - Retain failed staging output
- `-k, --keep-workspace` - Retain temporary recovery files

**`add_stripped.py`**

- `-p, --patch PATH` - Existing patch (required)
- `-t, --target PATH` - Final installation (required)
- `-b, --base PATH` - Original Steam base (required)
- `-s, --source-patch PATH` - Additional source patch (repeatable)
- `-c, --cdn-fallback` - Enable CDN fallback
- `-n, --dry-run` - Verify without changing the patch
- `-A, --audit-videos` - Read-only video audit
- `-r, --retries N` - CDN download attempts
- `-f, --full-source-hash` - Hash all source cache payloads
- `-l, --logs-dir PATH` - Log directory

Both commands support `-h, --help` and `-v, --version`. See [Internals](Warframe-Install-to-Patch-Internals.md) for technical details.
