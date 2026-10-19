"""Shared I/O helpers: terminal status, source fingerprints and verified CDN retries.

No importer side effects or source writes. The exporter dependency in
fetch_verified is deliberately lazy to prevent circular imports.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError

VERSION = "0.1"

class StrictArgumentParser(argparse.ArgumentParser):
    """Reject ambiguous abbreviations, stacked short flags, and duplicate options.

    Repeated options are allowed only for explicitly repeatable destinations.
    Short values must be separate tokens (``-p PATH``, not ``-pPATH``).
    """

    def __init__(self, *args, repeatable_destinations=(), **kwargs):
        kwargs['allow_abbrev'] = False
        super().__init__(*args, **kwargs)
        self.repeatable_destinations = frozenset(repeatable_destinations)

    def error(self, message):
        self.print_usage(sys.stderr)
        error(f'{self.prog}: {message}', file=sys.stderr)
        self.exit(2)

    def parse_known_args(self, args=None, namespace=None):
        args = list(sys.argv[1:] if args is None else args)
        seen = set()
        for token in args:
            if token == '--':
                break
            if token.startswith('--'):
                option = token.partition('=')[0]
            elif token.startswith('-') and len(token) > 1:
                option = token[:2]
                if option in self._option_string_actions and len(token) > 2:
                    self.error(f'Short options must be separate and take separate values: {token}')
            else:
                continue
            action = self._option_string_actions.get(option)
            if action is not None:
                if action.dest in seen and action.dest not in self.repeatable_destinations:
                    self.error(f'Option supplied more than once: {option}')
                seen.add(action.dest)
        return super().parse_known_args(args, namespace)

# ---- Console and plain-text logging ----
GREEN = '\x1b[32m'
YELLOW = '\x1b[33m'
RED = '\x1b[31m'
CYAN = '\x1b[36m'
RESET = '\x1b[0m'

_VT_MODE = 0x0004

_ANSI = re.compile(r'\x1b\[[0-9;]*m')

_vt_enabled: dict[int, bool] = {}

def strip_ansi(message: str) -> str:
    return _ANSI.sub('', message)

def _enabled(stream) -> bool:
    if os.environ.get('NO_COLOR') is not None or os.environ.get('TERM') == 'dumb':
        return False
    if not getattr(stream, 'isatty', lambda: False)():
        return False
    if os.name != 'nt':
        return True
    # The Win32 console handle belongs to the original stream even when output
    # is tee'd into a log. Cache by STDOUT/STDERR, never by a wrapper's id.
    handle_number = -12 if stream is sys.stderr else -11
    if handle_number not in _vt_enabled:
        try:
            handle = ctypes.windll.kernel32.GetStdHandle(handle_number)
            mode = ctypes.c_uint()
            supported = bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)))
            if supported and not (mode.value & _VT_MODE):
                supported = bool(ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | _VT_MODE))
        except (AttributeError, OSError, ValueError):
            supported = False
        _vt_enabled[handle_number] = supported
    return _vt_enabled[handle_number]

def color(value: object, ansi: str, stream=None) -> str:
    stream = sys.stdout if stream is None else stream
    label = str(value)
    return f'{ansi}{label}{RESET}' if _enabled(stream) else label

def status(code: int, stream=None) -> str:
    tone = GREEN if 200 <= code < 300 and code != 206 else (YELLOW if 300 <= code < 400 or code == 206 else RED)
    return color(str(code), tone, stream)

def label(name: str, stream=None) -> str:
    tone = RED if name.upper() in ('ERROR', 'FAILED') else (YELLOW if name.upper() in ('WARNING', 'RETRY') else GREEN if name.upper() in ('VERIFIED', 'COMPLETE', 'PUBLISHED') else CYAN)
    return color(f'[{name}]', tone, stream)

def error(message: object, *, file=None) -> None:
    stream = sys.stderr if file is None else file
    print(f'{color("ERROR:", RED, stream)} {strip_ansi(str(message))}', file=stream)

def warning(message: object, *, file=None) -> None:
    stream = sys.stdout if file is None else file
    print(f'{color("WARNING:", YELLOW, stream)} {strip_ansi(str(message))}', file=stream)

def http_line(method: str, code: int, logical_path: str, detail: str = '') -> None:
    method_label = color(f'[{method}]', CYAN)
    suffix = f' | {detail}' if detail else ''
    print(f'{method_label} HTTP {status(code)} | {logical_path}{suffix}')

class PlainLogTee:
    """Preserve TTY color on screen, but log plain text without ANSI escapes."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for i, stream in enumerate(self.streams):
            stream.write(data if i == 0 else strip_ansi(data))
        return len(data)

    def flush(self):
        for stream in self.streams:
            stream.flush()

    def __getattr__(self, name):
        return getattr(self.streams[0], name)

# ---- Source fingerprints ----

SELECTED = {'Font', 'ShaderDx11', 'ShaderPermutationDx11', 'Misc'}

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def snapshot(root: Path, *, all_cache: bool = False) -> dict:
    root = root.resolve(strict=True)
    cache = root if root.name.casefold() == 'cache.windows' else root / 'Cache.Windows'
    if not cache.is_dir() or cache.is_symlink():
        raise ValueError(f'Cannot find safe Cache.Windows: {cache}')
    records = {}
    for path in sorted(cache.rglob('*')):
        if not path.is_file():
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(cache):
            raise ValueError(f'Unsafe cache symlink: {path}')
        if path.suffix.lower() not in ('.toc', '.cache'):
            continue
        rel = path.relative_to(cache).as_posix()
        stat = path.stat()
        should_hash = (path.suffix.lower() == '.toc' or all_cache or
            any(f'.{package}.cache' in path.name for package in SELECTED))
        records[rel] = {'size': stat.st_size, 'mtime_ns': stat.st_mtime_ns,
            'sha256': sha256(path) if should_hash else None}
    if not records or not any(k.lower().endswith('.toc') for k in records):
        raise ValueError(f'No cache TOCs found: {cache}')
    return {'kind': 'warframe-cache-fingerprint', 'version': VERSION,
            'generated_utc': datetime.now(timezone.utc).isoformat(),
            'cache': str(cache), 'all_cache_hashed': bool(all_cache),
            'files': records}

def compare(before: dict, after: dict) -> dict:
    if before.get('kind') != 'warframe-cache-fingerprint' or after.get('kind') != 'warframe-cache-fingerprint':
        raise ValueError('Expected two compatible cache fingerprint reports')
    b, a = before['files'], after['files']
    changes = []
    stats = {'files_before': len(b), 'files_after': len(a),
        'added': 0, 'removed': 0, 'content_changed': 0,
        'stat_changed_unhashed': 0, 'timestamp_only': 0, 'unchanged': 0}
    for name in sorted(b.keys() | a.keys()):
        first, second = b.get(name), a.get(name)
        if first is None:
            state = 'added'
        elif second is None:
            state = 'removed'
        elif first['size'] != second['size']:
            state = 'content_changed'
        elif first['sha256'] is not None and second['sha256'] is not None:
            if first['sha256'] != second['sha256']:
                state = 'content_changed'
            elif first['mtime_ns'] != second['mtime_ns']:
                state = 'timestamp_only'
            else:
                state = 'unchanged'
        elif first['mtime_ns'] != second['mtime_ns']:
            state = 'stat_changed_unhashed'
        else:
            state = 'unchanged'
        stats[state] += 1
        if state != 'unchanged':
            changes.append({'file': name, 'status': state, 'before': first, 'after': second})
    return {'kind': 'warframe-cache-fingerprint-comparison', 'version': VERSION,
            'compared_utc': datetime.now(timezone.utc).isoformat(),
            'before_cache': before.get('cache'), 'after_cache': after.get('cache'),
            'counts': stats, 'changes': changes,
            'limitations': ('Cache contents not SHA-256 hashed on both sides cannot be proved unchanged by this comparison. '
        'This covers Cache.Windows only, not OpenWF-specific user data elsewhere.')}

def safe_json_write(path: Path, data: dict, sources: tuple[Path, ...]) -> None:
    dest = path.resolve(strict=False)
    for root in sources:
        resolved = root.resolve(strict=False)
        if dest == resolved or dest.is_relative_to(resolved):
            raise ValueError(f'Report cannot be written within an inspected directory: {dest}')
    if dest.exists():
        raise ValueError(f'Refusing to overwrite an existing snapshot or comparison: {dest}')
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    print(f'[Report] {dest}')

# ---- Verified CDN retries ----
RETRYABLE_HTTP = {408, 425, 429}

def fetch_verified(*, url: str, logical_path: str, expected_size: int,
        timeout: float, get_func, verify_func, retries: int = 5,
        attempts_log: list[dict] | None = None, before_attempt=None,
        sleeper=None):
    """Return (bytes, verifier_result); no failed payload is accepted.

    get_func(url, expected_size, timeout) must enforce Content-Length and the
    expected body length. verify_func(bytes) must reject bad contents. Network
    exceptions, size errors and transient integrity failures may retry, but
    known unsupported CDN envelopes and permanent HTTP 4xx fail immediately. Attempts are recorded even if the
    operation ultimately raises; the original final exception is preserved.
    """
    import warframe_install_to_patch as w
    if not 1 <= retries <= 20:
        raise ValueError('CDN retries must be between 1 and 20')
    if not 1 <= timeout <= 120 or expected_size <= 0:
        raise ValueError('Invalid CDN timeout or expected size')
    history = attempts_log if attempts_log is not None else []
    pause = sleeper if sleeper is not None else time.sleep
    for attempt in range(1, retries + 1):
        # Budget checks are deliberately outside the retry handler. When the
        # download allowance is exhausted, fail closed without further GETs.
        if before_attempt is not None:
            before_attempt(attempt, expected_size)
        print(f'{label("GET")} {logical_path} | attempt {attempt}/{retries} | expected {expected_size:,} bytes')
        phase = 'GET'
        failure = None
        try:
            data = get_func(url, expected_size, timeout)
            phase = 'verify'
            checks = verify_func(data)
            history.append({'attempt': attempt, 'status': 'verified', 'http_status': 200,
                'bytes': len(data)})
            http_line('GET', 200, logical_path, f'attempt {attempt}/{retries}; verified {len(data):,} bytes')
            return data, checks
        except HTTPError as exc:
            failure = exc
            code = exc.code
            retryable = code in RETRYABLE_HTTP or 500 <= code <= 599
            reason = f'HTTP {code}: {exc.reason}'
            http_line('GET', code, logical_path, f'attempt {attempt}/{retries}; request rejected: {exc.reason}')
            entry = {'attempt': attempt, 'status': 'http-failed', 'http_status': code,
                'retryable': retryable, 'reason': reason[:240]}
        except (URLError, TimeoutError, ConnectionError, OSError) as exc:
            failure = exc
            retryable = True
            reason = f'{type(exc).__name__}: {exc}'
            entry = {'attempt': attempt, 'status': 'network-failed', 'http_status': None,
                'retryable': True, 'reason': reason[:240]}
        except (w.ExportError, ValueError) as exc:
            failure = exc
            # The downloader enforces exact byte size and encoding and raises
            # the reconstruction ExportError on malformed/truncated payloads.
            # A verifier can likewise raise for CRC, H identity or CDN type.
            # All other programming errors propagate without a retry.
            retryable = getattr(exc, 'retryable', True)
            reason = f'{type(exc).__name__}: {exc}'
            entry = {'attempt': attempt, 'status': 'integrity-failed' if phase == 'verify' else 'response-invalid',
                'http_status': 200 if phase == 'verify' else None,
                'retryable': retryable, 'reason': reason[:600]}
        history.append(entry)
        if not retryable or attempt == retries:
            assert failure is not None
            raise failure.with_traceback(failure.__traceback__)
        delay = min(2 ** (attempt - 1), 8)
        print(f'{label("RETRY")} {logical_path} | attempt {attempt + 1}/{retries} '
              f'in {delay}s | {reason}')
        pause(delay)
    raise AssertionError('Unreachable CDN retry state')
