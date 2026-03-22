#!/usr/bin/env python3
"""
FO76 Signature Scanner -- Windows Edition

Reads the .text section from a running Fallout76.exe process on Windows using
the Win32 API (kernel32.dll via ctypes) and scans for known function signatures
using wildcard byte patterns.

This is the Windows-native counterpart to scanner.py (Linux). It uses:
  - kernel32.OpenProcess / ReadProcessMemory instead of /proc/PID/mem
  - tasklist.exe instead of pgrep
  - EnumProcessModulesEx / GetModuleFileNameExW for module base discovery
  - PE header parsing via ReadProcessMemory for section layout

Pattern format:
    bytes:  b"\x48\x83\x7C\x24\x40\x00"
    mask:   "xxxxxx"
    'x' = must match, '?' = wildcard (any byte)

Scan results are cached to scan_cache.json keyed by binary SHA-256.

Usage:
    python scanner_windows.py                  # scan running FO76 process
    python scanner_windows.py --pid 12345      # specify PID
    python scanner_windows.py --no-cache       # skip cache, force rescan
    python scanner_windows.py --test           # test mode: attach to explorer.exe

Requires: Python 3.8+, Windows, no external dependencies (stdlib + ctypes only)
"""

import argparse
import ctypes
import ctypes.wintypes as wintypes
import hashlib
import json
import logging
import os
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

IMAGE_BASE = 0x140000000
SCAN_CACHE_PATH = Path(__file__).parent / "scan_cache.json"
DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB

# --- Win32 constants --------------------------------------------------------

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
LIST_MODULES_ALL = 0x03

# --- Win32 API setup --------------------------------------------------------

kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

# ReadProcessMemory
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,    # hProcess
    ctypes.c_void_p,    # lpBaseAddress
    ctypes.c_void_p,    # lpBuffer
    ctypes.c_size_t,    # nSize
    ctypes.POINTER(ctypes.c_size_t),  # lpNumberOfBytesRead
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

# OpenProcess
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

# CloseHandle
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

# EnumProcessModulesEx
psapi.EnumProcessModulesEx.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.HMODULE),
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.DWORD,
]
psapi.EnumProcessModulesEx.restype = wintypes.BOOL

# GetModuleFileNameExW
psapi.GetModuleFileNameExW.argtypes = [
    wintypes.HANDLE,
    wintypes.HMODULE,
    wintypes.LPWSTR,
    wintypes.DWORD,
]
psapi.GetModuleFileNameExW.restype = wintypes.DWORD


# ---------------------------------------------------------------------------
# Patterns (shared with scanner.py -- kept in sync)
# ---------------------------------------------------------------------------

@dataclass
class ScanPattern:
    """A byte pattern with wildcard mask for signature scanning."""
    name: str
    pattern: bytes
    mask: str
    offset: int = 0

    def __post_init__(self):
        if len(self.pattern) != len(self.mask):
            raise ValueError(
                f"Pattern '{self.name}': pattern length ({len(self.pattern)}) "
                f"!= mask length ({len(self.mask)})"
            )
        for c in self.mask:
            if c not in ('x', '?'):
                raise ValueError(
                    f"Pattern '{self.name}': invalid mask char '{c}' (use 'x' or '?')"
                )


PATTERNS = [
    # -- Scaleform / Papyrus VM patterns ------------------------------------
    ScanPattern(
        name="VirtualMachine::FindBoundObject",
        pattern=b"\x48\x83\x7C\x24\x40\x00",
        mask="xxxxxx",
    ),
    ScanPattern(
        name="VirtualMachine::DispatchMethodCallImpl",
        pattern=b"\x8B\x05",
        mask="xx",
    ),
    ScanPattern(
        name="BSScaleformManager::LoadMovieDef",
        pattern=b"\x49\x3B\xF6",
        mask="xxx",
    ),
    ScanPattern(
        name="ObjectInterface::AttachMovie",
        pattern=b"\x4C\x24\x20",
        mask="xxx",
    ),
    ScanPattern(
        name="ObjectInterface::CreateEmptyMovieClip",
        pattern=b"\x4D\x8B\xF0",
        mask="xxx",
    ),
    ScanPattern(
        name="ObjectInterface::InvokeClosure",
        pattern=b"\x89\x54\x24",
        mask="xxx",
    ),

    # -- Player character functions -----------------------------------------
    ScanPattern(
        name="LocalPlayerCharacter::Update",
        pattern=b"\x48\x8b\xc4\xf3\x0f\x11\x48\x10\x55\x53\x56\x57\x41\x54\x41\x55",
        mask="xxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="BasePlayerCharacter::SetGodMode",
        pattern=b"\x4c\x8b\xdc\x49\x89\x5b\x18\x57\x48\x83\xec\x40\x80\xa1\xa8\x0d",
        mask="xxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="LocalPlayerCharacter::TeleportPlayer",
        pattern=(b"\x48\x8d\x3d\x00\x00\x00\x00\x0f\xba\xe0\x08\x72\x43"
                 b"\x48\x89\x74\x24\x38\x48\x8d"),
        mask="xxx????xxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="LocalPlayerCharacter::GetInventoryEncumbrance",
        pattern=(b"\x40\x55\x56\x57\x48\x83\xec\x30\x48\xc7\x44\x24\x20"
                 b"\xfe\xff\xff\xff\x48\x89\x5c\x24\x60\x49\x8b"),
        mask="xxxxxxxxxxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="BasePlayerCharacter::Update",
        pattern=b"\x48\x8b\xc4\x53\x56\x57\x41\x56\x41\x57\x48\x81\xec\xc0\x00\x00",
        mask="xxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="LocalPlayerCharacter::CenterOnCell",
        pattern=b"\x48\x8b\xc4\x57\x48\x81\xec\x80\x00\x00\x00\x48\xc7\x40\xb8\xfe",
        mask="xxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="LocalPlayerCharacter::PreNetUpdate",
        pattern=b"\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8d\x6c",
        mask="xxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="LocalPlayerCharacter::RequestNetworkAuthorityUpdate",
        pattern=(b"\x40\x53\x48\x83\xec\x40\x80\x3d\x00\x00\x00\x00"
                 b"\x00\x48\x8b\xd9"),
        mask="xxxxxxxx????xxxx",
    ),
    ScanPattern(
        name="LocalPlayerCharacter::ShouldWaitInLoadScreen",
        pattern=b"\x4c\x8b\xdc\x55\x56\x57\x41\x56\x41\x57\x48\x83\xec\x70\x49\xc7",
        mask="xxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="LocalPlayerCharacter::Reset3D",
        pattern=b"\x4c\x8b\xdc\x57\x41\x56\x41\x57\x48\x83\xec\x50\x49\xc7\x43\xe0",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # -- Actor functions ----------------------------------------------------
    ScanPattern(
        name="Actor::Update",
        pattern=(b"\x48\x8b\xc4\x55\x56\x57\x41\x54\x41\x55\x41\x56"
                 b"\x41\x57\x48\x8d\xa8\x08\xfd\xff"),
        mask="xxxxxxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="Actor::IsDead",
        pattern=(b"\x40\x57\x48\x83\xec\x30\x48\xc7\x44\x24\x20\xfe"
                 b"\xff\xff\xff\x48\x89\x5c\x24\x48\x48\x89\x74\x24"
                 b"\x50\x41\x0f\xb6"),
        mask="xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="Actor::GetCurrentTarget",
        pattern=(b"\x40\x57\x48\x83\xec\x30\x48\xc7\x44\x24\x20\xfe"
                 b"\xff\xff\xff\x48\x89\x5c\x24\x48\x48\x89\x74\x24"
                 b"\x58\x48\x8b\xfa"),
        mask="xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="Actor::SetCurrentTarget",
        pattern=(b"\x40\x53\x57\x48\x83\xec\x48\x48\xc7\x44\x24\x28"
                 b"\xfe\xff\xff\xff\x48\x8b\xda\x48"),
        mask="xxxxxxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="Actor::SetPosition",
        pattern=b"\x48\x8d\x15\x00\x00\x00\x00\x48\x8d\x4d\xa6\xe8\x21\x24\x79\xfd",
        mask="xxx????xxxxxxxxx",
    ),
    ScanPattern(
        name="Actor::SetHeading",
        pattern=(b"\x40\x57\x48\x83\xec\x50\x48\xc7\x44\x24\x20\xfe"
                 b"\xff\xff\xff\x48\x89\x5c\x24\x68"),
        mask="xxxxxxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="Actor::GetControllingActor",
        pattern=(b"\x40\x57\x48\x83\xec\x30\x48\xc7\x44\x24\x20\xfe"
                 b"\xff\xff\xff\x48\x89\x5c\x24\x40\x48\x89\x74\x24"
                 b"\x58\x48\x8b\xfa"),
        mask="xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="Actor::UpdateMagic",
        pattern=b"\x48\x8b\xc4\x55\x56\x57\x48\x81\xec\x80\x00\x00\x00\x48\xc7\x40",
        mask="xxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="Actor::UpdateMinimal",
        pattern=b"\x48\x8b\xc4\x55\x53\x56\x57\x41\x56\x48\x8d\xa8\x28\xff\xff\xff",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # -- TESDataHandler functions -------------------------------------------
    ScanPattern(
        name="TESDataHandler::LoadForm",
        pattern=b"\x40\x53\x55\x56\x57\x41\x56\x48\x83\xec\x30\x48\xc7\x44\x24\x20",
        mask="xxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="TESDataHandler::ConstructObject",
        pattern=b"\x44\x88\x44\x24\x18\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41",
        mask="xxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="TESDataHandler::UnloadCell",
        pattern=b"\x48\x85\xd2\x0f\x84\x37\x04\x00\x00\x55\x56\x57\x41\x56\x41\x57",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # -- ProcessLists functions ---------------------------------------------
    ScanPattern(
        name="ProcessLists::UpdateClient",
        pattern=b"\x40\x55\x53\x56\x57\x41\x54\x41\x56\x41\x57\x48\x8b\xec\x48\x81",
        mask="xxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="ProcessLists::UpdateMagicEffects",
        pattern=(b"\x48\x8b\xc4\x56\x57\x41\x56\x48\x81\xec\x80\x00"
                 b"\x00\x00\x48\xc7\x40\xa0\xfe\xff"),
        mask="xxxxxxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="ProcessLists::QueueActorTransformWithFootIKResults",
        pattern=b"\x40\x53\x55\x56\x57\x41\x54\x41\x56\x41\x57\x48\x83\xec\x50\x48",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # -- TESForm lookup functions -------------------------------------------
    ScanPattern(
        name="TESForm::GetFormByEditorID",
        pattern=b"\x40\x55\x56\x57\x41\x56\x41\x57\x48\x83\xec\x30\x48\xc7\x44\x24",
        mask="xxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="TESForm::GetFormByNumericID",
        pattern=b"\x89\x4c\x24\x08\x55\x56\x57\x41\x56\x41\x57\x48\x8b\xec\x48\x83",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # -- Inventory / ActorValue / ActiveEffect ------------------------------
    ScanPattern(
        name="BGSInventoryList::AddEquipmentChange",
        pattern=b"\x4c\x89\x4c\x24\x20\x44\x88\x44\x24\x18\x48\x89\x4c\x24\x08\x55",
        mask="xxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="ActorValuesSnapshotComponent::PostSerializeReadREFRJob",
        pattern=(b"\x40\x56\x57\x41\x56\x48\x83\xec\x30\x48\xc7\x44"
                 b"\x24\x20\xfe\xff\xff\xff\x48\x89\x5c\x24\x68\x4c"),
        mask="xxxxxxxxxxxxxxxxxxxxxxxx",
    ),
    ScanPattern(
        name="ActiveEffectManager::ForEachActiveEffect",
        pattern=(b"\x48\x89\x54\x24\x10\x53\x55\x56\x57\x41\x56\x48"
                 b"\x83\xec\x40\x48\xc7\x44\x24\x20"),
        mask="xxxxxxxxxxxxxxxxxxxx",
    ),
]


def _match_at(data: bytes, pos: int, pattern: bytes, mask: str) -> bool:
    """Check if pattern matches at position in data, respecting mask."""
    for i in range(len(pattern)):
        if mask[i] == 'x' and data[pos + i] != pattern[i]:
            return False
    return True


# ---------------------------------------------------------------------------
# Windows process memory reader (replaces /proc/PID/mem file object)
# ---------------------------------------------------------------------------

class ProcessMemoryReader:
    """
    File-like wrapper around ReadProcessMemory for compatibility with
    the scanner's mem_file interface (seek + read).
    """

    def __init__(self, handle):
        self._handle = handle
        self._pos = 0

    def seek(self, pos):
        self._pos = pos

    def read(self, size):
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            self._handle,
            ctypes.c_void_p(self._pos),
            buf,
            size,
            ctypes.byref(bytes_read),
        )
        if not ok:
            err = ctypes.get_last_error() if hasattr(ctypes, 'get_last_error') else kernel32.GetLastError()
            raise OSError(f"ReadProcessMemory failed at 0x{self._pos:X} (size={size}, error={err})")
        data = buf.raw[:bytes_read.value]
        self._pos += bytes_read.value
        return data

    def close(self):
        if self._handle:
            kernel32.CloseHandle(self._handle)
            self._handle = None


# ---------------------------------------------------------------------------
# Scan cache
# ---------------------------------------------------------------------------

def _hash_binary_header(mem_file, base_addr: int, nbytes: int = 4096) -> str:
    """Hash the first N bytes of the mapped image to fingerprint the build."""
    try:
        mem_file.seek(base_addr)
        header = mem_file.read(nbytes)
        return hashlib.sha256(header).hexdigest()
    except (OSError, ValueError):
        return ""


def _load_cache() -> dict:
    try:
        return json.loads(SCAN_CACHE_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict) -> None:
    SCAN_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCAN_CACHE_PATH.write_text(json.dumps(cache, indent=2))
    log.info("Scan cache saved to %s", SCAN_CACHE_PATH)


def load_cached_results(mem_file, base_addr: int) -> Optional[dict]:
    """Return cached scan results if the binary hasn't changed."""
    cache = _load_cache()
    binary_hash = _hash_binary_header(mem_file, base_addr)
    if not binary_hash:
        return None

    entry = cache.get(binary_hash)
    if entry is None:
        return None

    results = {name: int(addr_hex, 16) for name, addr_hex in entry.get("results", {}).items()}

    cached_base = int(entry.get("base_addr", "0"), 16)
    if cached_base != base_addr:
        delta = base_addr - cached_base
        results = {name: addr + delta for name, addr in results.items()}

    return results


def save_results_to_cache(mem_file, base_addr: int, results: dict) -> None:
    """Save scan results to disk, keyed by binary hash."""
    binary_hash = _hash_binary_header(mem_file, base_addr)
    if not binary_hash:
        return

    cache = _load_cache()
    cache[binary_hash] = {
        "base_addr": f"0x{base_addr:X}",
        "results": {name: f"0x{addr:X}" for name, addr in results.items()},
        "pattern_count": len(PATTERNS),
    }

    if len(cache) > 5:
        keys = list(cache.keys())
        for k in keys[:-5]:
            del cache[k]

    _save_cache(cache)


# ---------------------------------------------------------------------------
# PE section parser (via ReadProcessMemory)
# ---------------------------------------------------------------------------

def parse_pe_sections(mem_file, base_addr: int) -> dict:
    """Parse PE section headers from the process memory."""
    mem_file.seek(base_addr)
    dos = mem_file.read(0x40)
    if dos[:2] != b'MZ':
        raise RuntimeError(f"No MZ header at 0x{base_addr:X} (got {dos[:2]!r})")
    e_lfanew = struct.unpack_from('<I', dos, 0x3C)[0]

    mem_file.seek(base_addr + e_lfanew)
    pe_sig = mem_file.read(4)
    if pe_sig != b'PE\x00\x00':
        raise RuntimeError(f"Bad PE signature: {pe_sig!r}")

    coff = mem_file.read(20)
    num_sections = struct.unpack_from('<H', coff, 2)[0]
    opt_header_size = struct.unpack_from('<H', coff, 16)[0]

    mem_file.seek(base_addr + e_lfanew + 4 + 20 + opt_header_size)

    sections = {}
    for _ in range(num_sections):
        sec = mem_file.read(40)
        name = sec[:8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', sec, 8)[0]
        vaddr = struct.unpack_from('<I', sec, 12)[0]
        sections[name] = {
            'va': base_addr + vaddr,
            'vsize': vsize,
            'end': base_addr + vaddr + vsize,
        }
    return sections


# ---------------------------------------------------------------------------
# Process finder (Windows)
# ---------------------------------------------------------------------------

def find_process_pid(process_name: str = "Fallout76.exe") -> Optional[int]:
    """Find a process PID by name using tasklist."""
    try:
        result = subprocess.run(
            ['tasklist', '/FI', f'IMAGENAME eq {process_name}', '/FO', 'CSV', '/NH'],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if not line or 'INFO:' in line:
            continue
        # CSV format: "name","PID","Session","Session#","Mem Usage"
        parts = line.split('","')
        if len(parts) >= 2:
            try:
                pid = int(parts[1].strip('"'))
                return pid
            except (ValueError, IndexError):
                continue
    return None


def get_module_base(handle, process_name: str = "Fallout76.exe") -> Optional[int]:
    """
    Find the base address of the main executable module using
    EnumProcessModulesEx + GetModuleFileNameExW.
    """
    max_modules = 1024
    arr = (wintypes.HMODULE * max_modules)()
    needed = wintypes.DWORD(0)

    ok = psapi.EnumProcessModulesEx(
        handle, arr, ctypes.sizeof(arr), ctypes.byref(needed), LIST_MODULES_ALL
    )
    if not ok:
        return None

    count = min(needed.value // ctypes.sizeof(wintypes.HMODULE), max_modules)
    name_buf = ctypes.create_unicode_buffer(512)

    for i in range(count):
        psapi.GetModuleFileNameExW(handle, arr[i], name_buf, 512)
        mod_name = name_buf.value
        if mod_name.lower().endswith(process_name.lower()):
            # HMODULE is the base address
            return ctypes.cast(arr[i], ctypes.c_void_p).value

    # If we can't find by name, the first module is usually the main exe
    if count > 0:
        return ctypes.cast(arr[0], ctypes.c_void_p).value

    return None


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

def scan_memory(
    mem_file,
    base_addr: int,
    text_start: int,
    text_size: int,
    patterns: Optional[list] = None,
    use_cache: bool = True,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> dict:
    """
    Scan the .text section for all known function signatures.

    Returns:
        Dict mapping pattern name -> absolute virtual address.
        Only includes patterns that were found.
    """
    if patterns is None:
        patterns = PATTERNS

    if use_cache:
        cached = load_cached_results(mem_file, base_addr)
        if cached is not None:
            pattern_names = {p.name for p in patterns}
            if not (pattern_names - set(cached.keys())):
                log.info("All %d patterns satisfied from cache", len(cached))
                return cached

    results: dict = {}
    remaining = {p.name: p for p in patterns}

    log.info(
        "Scanning .text: base=0x%X, start=0x%X, size=%.1fMB, patterns=%d",
        base_addr, text_start, text_size / (1024 * 1024), len(remaining),
    )

    max_pattern_len = max(len(p.pattern) for p in patterns)
    overlap = max_pattern_len - 1

    offset = 0
    while offset < text_size and remaining:
        read_size = min(chunk_size + overlap, text_size - offset)
        try:
            mem_file.seek(text_start + offset)
            chunk = mem_file.read(read_size)
        except OSError as e:
            log.warning("Read error at offset 0x%X: %s", text_start + offset, e)
            offset += chunk_size
            continue

        if not chunk:
            break

        found_in_chunk = []
        for name, pat in remaining.items():
            plen = len(pat.pattern)
            scan_end = (
                min(len(chunk) - plen + 1, chunk_size)
                if offset + chunk_size < text_size
                else len(chunk) - plen + 1
            )
            for i in range(scan_end):
                if _match_at(chunk, i, pat.pattern, pat.mask):
                    addr = text_start + offset + i + pat.offset
                    results[name] = addr
                    found_in_chunk.append(name)
                    log.info(
                        "FOUND %s at 0x%X (RVA +0x%X)",
                        name, addr, addr - base_addr,
                    )
                    break

        for name in found_in_chunk:
            del remaining[name]

        offset += chunk_size

    log.info("Scan complete: %d/%d patterns found", len(results), len(patterns))
    for name in remaining:
        log.warning("NOT FOUND: %s", name)

    if use_cache:
        save_results_to_cache(mem_file, base_addr, results)

    return results


def format_scan_results(results: dict, base_addr: int) -> str:
    """Format scan results into a readable report."""
    lines = ["Address Scan Results:", f"  Image base: 0x{base_addr:X}", ""]
    for pat in PATTERNS:
        if pat.name in results:
            addr = results[pat.name]
            rva = addr - base_addr
            lines.append(f"  [OK] {pat.name}: 0x{addr:X} (RVA +0x{rva:X})")
        else:
            lines.append(f"  [--] {pat.name}: NOT FOUND")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Test mode: verify memory reading works against any process
# ---------------------------------------------------------------------------

def run_test_mode(process_name: str = "explorer.exe"):
    """
    Test mode: open a known process, read its PE headers, and list sections.
    This verifies the Win32 memory reading pipeline works without needing FO76.
    """
    print(f"=== TEST MODE: attaching to {process_name} ===")
    print()

    pid = find_process_pid(process_name)
    if not pid:
        print(f"ERROR: {process_name} not found. Try a different process name.")
        return False

    print(f"Found {process_name} PID: {pid}")

    access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        err = kernel32.GetLastError()
        print(f"ERROR: OpenProcess failed (error {err}). Try running as Administrator.")
        return False

    print(f"Process handle: 0x{handle:X}")

    # Find module base
    base = get_module_base(handle, process_name)
    if not base:
        print("WARNING: Could not find module base via EnumProcessModulesEx")
        kernel32.CloseHandle(handle)
        return False

    print(f"Module base: 0x{base:X}")

    # Create memory reader
    mem = ProcessMemoryReader(handle)

    # Try reading MZ header
    try:
        mem.seek(base)
        header = mem.read(2)
        if header == b'MZ':
            print("MZ header: OK")
        else:
            print(f"MZ header: unexpected bytes {header!r}")
            mem.close()
            return False
    except OSError as e:
        print(f"ERROR: ReadProcessMemory failed: {e}")
        mem.close()
        return False

    # Parse PE sections
    try:
        sections = parse_pe_sections(mem, base)
        print(f"\nPE Sections ({len(sections)}):")
        for name, info in sections.items():
            print(f"  {name:8s}  VA=0x{info['va']:X}  Size={info['vsize']:>10,} bytes")
    except Exception as e:
        print(f"ERROR parsing PE sections: {e}")
        mem.close()
        return False

    # Read a small sample from .text to prove scanning would work
    if '.text' in sections:
        text = sections['.text']
        try:
            mem.seek(text['va'])
            sample = mem.read(min(64, text['vsize']))
            print(f"\n.text first 64 bytes: {sample.hex()}")
            print("\nAll memory reading tests PASSED.")
        except OSError as e:
            print(f"ERROR reading .text: {e}")
            mem.close()
            return False
    else:
        print("\nNo .text section found (unusual but not fatal for test)")

    # Hash test
    binary_hash = _hash_binary_header(mem, base)
    if binary_hash:
        print(f"Binary hash (first 4KB): {binary_hash[:16]}...")

    mem.close()
    print()
    print("=== TEST PASSED: Win32 memory reading pipeline is working ===")
    return True


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Signature scanner for Fallout 76 on Windows"
    )
    parser.add_argument("--pid", type=int, help="Game PID (auto-detected if omitted)")
    parser.add_argument("--no-cache", action="store_true", help="Force rescan, ignore cache")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--test", nargs='?', const="explorer.exe", metavar="PROCESS",
                        help="Test mode: verify memory reading against a process (default: explorer.exe)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    # Test mode
    if args.test is not None:
        success = run_test_mode(args.test)
        sys.exit(0 if success else 1)

    # Normal FO76 scan mode
    pid = args.pid or find_process_pid("Fallout76.exe")
    if not pid:
        print("ERROR: Fallout 76 not running. Start the game first.")
        print("       (Use --test to verify memory reading against another process)")
        sys.exit(1)

    print(f"Fallout 76 PID: {pid}")

    access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        err = kernel32.GetLastError()
        print(f"ERROR: OpenProcess failed (error {err}). Try running as Administrator.")
        sys.exit(1)

    # Find the actual base address of Fallout76.exe in memory
    base_addr = get_module_base(handle, "Fallout76.exe")
    if not base_addr:
        log.warning("Could not determine module base, using default 0x%X", IMAGE_BASE)
        base_addr = IMAGE_BASE

    print(f"Image base: 0x{base_addr:X}")
    print()

    mem = ProcessMemoryReader(handle)

    try:
        sections = parse_pe_sections(mem, base_addr)
    except Exception as e:
        print(f"ERROR: Failed to parse PE headers: {e}")
        mem.close()
        sys.exit(1)

    if '.text' not in sections:
        print("ERROR: No .text section found in PE headers")
        mem.close()
        sys.exit(1)

    text = sections['.text']
    print(f".text:  0x{text['va']:X} - 0x{text['end']:X} ({text['vsize']/(1024*1024):.1f} MB)")
    print(f"Patterns: {len(PATTERNS)}")
    print()

    results = scan_memory(
        mem_file=mem,
        base_addr=base_addr,
        text_start=text['va'],
        text_size=text['vsize'],
        use_cache=not args.no_cache,
    )

    print()
    print(format_scan_results(results, base_addr))
    print()
    print(f"Found {len(results)}/{len(PATTERNS)} patterns.")

    mem.close()


if __name__ == "__main__":
    main()
