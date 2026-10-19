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

Check an existing patch for missing stripped assets without changing it:

```cmd
py add_stripped.py -p "D:\Patches\44.0.0" -t "D:\Warframe\Final" -b "D:\Warframe\SteamBase" -s "D:\Patches\44.0.1" -c -n
```

Remove `-n` to add verified missing assets. Use `-A` instead for a read-only video audit; `-A -s SOURCE` compares videos with another patch.

## Options

**`install_to_patch.py`**

- `-t, --target PATH` - Final installation (required)
- `-b, --base PATH` - Original Steam base (required)
- `-u, --source-patch PATH` - Optional exact-identity recovery source
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
