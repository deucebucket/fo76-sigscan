#!/usr/bin/env python3
"""
FO76 Signature Scanner

Reads the .text section directly from /proc/PID/mem and scans for known
function signatures using wildcard byte patterns. This finds function
addresses across game updates without hardcoded offsets.

Pattern format:
    bytes:  b"\x48\x83\x7C\x24\x40\x00"
    mask:   "xxxxxx"
    'x' = must match, '?' = wildcard (any byte)

Scan results are cached to scan_cache.json keyed by binary SHA-256.
The cache is invalidated automatically when the game binary changes.

Usage:
    python3 scanner.py                  # scan running FO76 process
    python3 scanner.py --pid 12345      # specify PID
    python3 scanner.py --no-cache       # skip cache, force rescan

Requires: Python 3.8+, Linux, game running under Proton/Wine
"""

import argparse
import hashlib
import json
import logging
import os
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional

log = logging.getLogger(__name__)

IMAGE_BASE = 0x140000000
SCAN_CACHE_PATH = Path(__file__).parent / "scan_cache.json"
DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB


@dataclass
class ScanPattern:
    """A byte pattern with wildcard mask for signature scanning."""
    name: str
    pattern: bytes
    mask: str
    offset: int = 0  # offset from match start to actual function entry

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


# ---------------------------------------------------------------------------
# Signature patterns from Creation Engine reverse engineering.
#
# Each pattern uses the first N bytes of the function prologue.  Bytes that
# encode RIP-relative displacements (which change between builds) are masked
# with '?' so the pattern still matches after patches.
#
# Categories:
#   - Scaleform / Papyrus VM patterns (6)
#   - Player character functions (10)
#   - Actor functions (9)
#   - TESDataHandler functions (3)
#   - ProcessLists functions (3)
#   - TESForm lookup functions (2)
#   - Inventory / ActorValue / ActiveEffect (3)
# ---------------------------------------------------------------------------

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

    # LocalPlayerCharacter::Update (dev RVA 0x2A2F0EF)
    ScanPattern(
        name="LocalPlayerCharacter::Update",
        pattern=b"\x48\x8b\xc4\xf3\x0f\x11\x48\x10\x55\x53\x56\x57\x41\x54\x41\x55",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # BasePlayerCharacter::SetGodMode (dev RVA 0x188F61C)
    ScanPattern(
        name="BasePlayerCharacter::SetGodMode",
        pattern=b"\x4c\x8b\xdc\x49\x89\x5b\x18\x57\x48\x83\xec\x40\x80\xa1\xa8\x0d",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # LocalPlayerCharacter::TeleportPlayer (dev RVA 0x2A2CE8D)
    # Bytes 3-6 are RIP-relative displacement (wildcarded)
    ScanPattern(
        name="LocalPlayerCharacter::TeleportPlayer",
        pattern=(b"\x48\x8d\x3d\x00\x00\x00\x00\x0f\xba\xe0\x08\x72\x43"
                 b"\x48\x89\x74\x24\x38\x48\x8d"),
        mask="xxx????xxxxxxxxxxxxx",
    ),

    # LocalPlayerCharacter::GetInventoryEncumbrance (dev RVA 0x2A2D66D)
    ScanPattern(
        name="LocalPlayerCharacter::GetInventoryEncumbrance",
        pattern=(b"\x40\x55\x56\x57\x48\x83\xec\x30\x48\xc7\x44\x24\x20"
                 b"\xfe\xff\xff\xff\x48\x89\x5c\x24\x60\x49\x8b"),
        mask="xxxxxxxxxxxxxxxxxxxxxxxx",
    ),

    # BasePlayerCharacter::Update (dev RVA 0x1887AD2)
    ScanPattern(
        name="BasePlayerCharacter::Update",
        pattern=b"\x48\x8b\xc4\x53\x56\x57\x41\x56\x41\x57\x48\x81\xec\xc0\x00\x00",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # LocalPlayerCharacter::CenterOnCell (dev RVA 0x2A2DBBA)
    ScanPattern(
        name="LocalPlayerCharacter::CenterOnCell",
        pattern=b"\x48\x8b\xc4\x57\x48\x81\xec\x80\x00\x00\x00\x48\xc7\x40\xb8\xfe",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # LocalPlayerCharacter::PreNetUpdate (dev RVA 0x1AFDD75)
    ScanPattern(
        name="LocalPlayerCharacter::PreNetUpdate",
        pattern=b"\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8d\x6c",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # LocalPlayerCharacter::RequestNetworkAuthorityUpdate (dev RVA 0x2A46D11)
    ScanPattern(
        name="LocalPlayerCharacter::RequestNetworkAuthorityUpdate",
        pattern=(b"\x40\x53\x48\x83\xec\x40\x80\x3d\x00\x00\x00\x00"
                 b"\x00\x48\x8b\xd9"),
        mask="xxxxxxxx????xxxx",
    ),

    # LocalPlayerCharacter::ShouldWaitInLoadScreen (dev RVA 0x2A53A52)
    ScanPattern(
        name="LocalPlayerCharacter::ShouldWaitInLoadScreen",
        pattern=b"\x4c\x8b\xdc\x55\x56\x57\x41\x56\x41\x57\x48\x83\xec\x70\x49\xc7",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # LocalPlayerCharacter::Reset3D (dev RVA 0x29085B6)
    ScanPattern(
        name="LocalPlayerCharacter::Reset3D",
        pattern=b"\x4c\x8b\xdc\x57\x41\x56\x41\x57\x48\x83\xec\x50\x49\xc7\x43\xe0",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # -- Actor functions ----------------------------------------------------

    # Actor::Update (dev RVA 0x28C8507)
    ScanPattern(
        name="Actor::Update",
        pattern=(b"\x48\x8b\xc4\x55\x56\x57\x41\x54\x41\x55\x41\x56"
                 b"\x41\x57\x48\x8d\xa8\x08\xfd\xff"),
        mask="xxxxxxxxxxxxxxxxxxxx",
    ),

    # Actor::IsDead (dev RVA 0x28D7A2D)
    ScanPattern(
        name="Actor::IsDead",
        pattern=(b"\x40\x57\x48\x83\xec\x30\x48\xc7\x44\x24\x20\xfe"
                 b"\xff\xff\xff\x48\x89\x5c\x24\x48\x48\x89\x74\x24"
                 b"\x50\x41\x0f\xb6"),
        mask="xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ),

    # Actor::GetCurrentTarget (dev RVA 0x28CF20A)
    ScanPattern(
        name="Actor::GetCurrentTarget",
        pattern=(b"\x40\x57\x48\x83\xec\x30\x48\xc7\x44\x24\x20\xfe"
                 b"\xff\xff\xff\x48\x89\x5c\x24\x48\x48\x89\x74\x24"
                 b"\x58\x48\x8b\xfa"),
        mask="xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ),

    # Actor::SetCurrentTarget (dev RVA 0x28CF3A1)
    ScanPattern(
        name="Actor::SetCurrentTarget",
        pattern=(b"\x40\x53\x57\x48\x83\xec\x48\x48\xc7\x44\x24\x28"
                 b"\xfe\xff\xff\xff\x48\x8b\xda\x48"),
        mask="xxxxxxxxxxxxxxxxxxxx",
    ),

    # Actor::SetPosition (dev RVA 0x289BBE8)
    ScanPattern(
        name="Actor::SetPosition",
        pattern=b"\x48\x8d\x15\x00\x00\x00\x00\x48\x8d\x4d\xa6\xe8\x21\x24\x79\xfd",
        mask="xxx????xxxxxxxxx",
    ),

    # Actor::SetHeading (dev RVA 0x28BB9E0)
    ScanPattern(
        name="Actor::SetHeading",
        pattern=(b"\x40\x57\x48\x83\xec\x50\x48\xc7\x44\x24\x20\xfe"
                 b"\xff\xff\xff\x48\x89\x5c\x24\x68"),
        mask="xxxxxxxxxxxxxxxxxxxx",
    ),

    # Actor::GetControllingActor (dev RVA 0x299448F)
    ScanPattern(
        name="Actor::GetControllingActor",
        pattern=(b"\x40\x57\x48\x83\xec\x30\x48\xc7\x44\x24\x20\xfe"
                 b"\xff\xff\xff\x48\x89\x5c\x24\x40\x48\x89\x74\x24"
                 b"\x58\x48\x8b\xfa"),
        mask="xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ),

    # Actor::UpdateMagic (dev RVA 0x2999839)
    ScanPattern(
        name="Actor::UpdateMagic",
        pattern=b"\x48\x8b\xc4\x55\x56\x57\x48\x81\xec\x80\x00\x00\x00\x48\xc7\x40",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # Actor::UpdateMinimal (dev RVA 0x28CA6F4)
    ScanPattern(
        name="Actor::UpdateMinimal",
        pattern=b"\x48\x8b\xc4\x55\x53\x56\x57\x41\x56\x48\x8d\xa8\x28\xff\xff\xff",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # -- TESDataHandler functions -------------------------------------------

    # TESDataHandler::LoadForm (dev RVA 0xCC265C)
    ScanPattern(
        name="TESDataHandler::LoadForm",
        pattern=b"\x40\x53\x55\x56\x57\x41\x56\x48\x83\xec\x30\x48\xc7\x44\x24\x20",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # TESDataHandler::ConstructObject (dev RVA 0xCD21FF)
    ScanPattern(
        name="TESDataHandler::ConstructObject",
        pattern=b"\x44\x88\x44\x24\x18\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # TESDataHandler::UnloadCell (dev RVA 0xCC90E5)
    ScanPattern(
        name="TESDataHandler::UnloadCell",
        pattern=b"\x48\x85\xd2\x0f\x84\x37\x04\x00\x00\x55\x56\x57\x41\x56\x41\x57",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # -- ProcessLists functions ---------------------------------------------

    # ProcessLists::UpdateClient (dev RVA 0x2A98484)
    ScanPattern(
        name="ProcessLists::UpdateClient",
        pattern=b"\x40\x55\x53\x56\x57\x41\x54\x41\x56\x41\x57\x48\x8b\xec\x48\x81",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # ProcessLists::UpdateMagicEffects (dev RVA 0x2AA1912)
    ScanPattern(
        name="ProcessLists::UpdateMagicEffects",
        pattern=(b"\x48\x8b\xc4\x56\x57\x41\x56\x48\x81\xec\x80\x00"
                 b"\x00\x00\x48\xc7\x40\xa0\xfe\xff"),
        mask="xxxxxxxxxxxxxxxxxxxx",
    ),

    # ProcessLists::QueueActorTransformWithFootIKResults (dev RVA 0x2AA04F0)
    ScanPattern(
        name="ProcessLists::QueueActorTransformWithFootIKResults",
        pattern=b"\x40\x53\x55\x56\x57\x41\x54\x41\x56\x41\x57\x48\x83\xec\x50\x48",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # -- TESForm lookup functions -------------------------------------------

    # TESForm::GetFormByEditorID (dev RVA 0xD154AF)
    ScanPattern(
        name="TESForm::GetFormByEditorID",
        pattern=b"\x40\x55\x56\x57\x41\x56\x41\x57\x48\x83\xec\x30\x48\xc7\x44\x24",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # TESForm::GetFormByNumericID (dev RVA 0xD15144)
    ScanPattern(
        name="TESForm::GetFormByNumericID",
        pattern=b"\x89\x4c\x24\x08\x55\x56\x57\x41\x56\x41\x57\x48\x8b\xec\x48\x83",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # -- Inventory / ActorValue / ActiveEffect ------------------------------

    # BGSInventoryList::AddEquipmentChange (dev RVA 0xDA1E62)
    ScanPattern(
        name="BGSInventoryList::AddEquipmentChange",
        pattern=b"\x4c\x89\x4c\x24\x20\x44\x88\x44\x24\x18\x48\x89\x4c\x24\x08\x55",
        mask="xxxxxxxxxxxxxxxx",
    ),

    # ActorValuesSnapshotComponent::PostSerializeReadREFRJob (dev RVA 0x260DF6B)
    ScanPattern(
        name="ActorValuesSnapshotComponent::PostSerializeReadREFRJob",
        pattern=(b"\x40\x56\x57\x41\x56\x48\x83\xec\x30\x48\xc7\x44"
                 b"\x24\x20\xfe\xff\xff\xff\x48\x89\x5c\x24\x68\x4c"),
        mask="xxxxxxxxxxxxxxxxxxxxxxxx",
    ),

    # ActiveEffectManager::ForEachActiveEffect (dev RVA 0x24CD85C)
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
# Scan cache
# ---------------------------------------------------------------------------

def _hash_binary_header(mem_file: BinaryIO, base_addr: int, nbytes: int = 4096) -> str:
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


def load_cached_results(mem_file: BinaryIO, base_addr: int) -> Optional[dict]:
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


def save_results_to_cache(mem_file: BinaryIO, base_addr: int, results: dict) -> None:
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
# PE section parser
# ---------------------------------------------------------------------------

def parse_pe_sections(mem_file: BinaryIO, base_addr: int) -> dict:
    """Parse PE section headers from the mapped image in process memory."""
    mem_file.seek(base_addr)
    dos = mem_file.read(0x40)
    e_lfanew = struct.unpack_from('<I', dos, 0x3C)[0]

    mem_file.seek(base_addr + e_lfanew)
    pe_sig = mem_file.read(4)
    assert pe_sig == b'PE\x00\x00', f"Bad PE signature: {pe_sig}"

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
# Process finder
# ---------------------------------------------------------------------------

def find_game_pid() -> Optional[int]:
    """Find the FO76 PID (largest RSS Fallout76 process)."""
    try:
        result = subprocess.run(
            ["pgrep", "-af", "Fallout76"],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    best_pid, best_rss = None, 0
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        try:
            pid = int(line.split()[0])
        except (ValueError, IndexError):
            continue
        try:
            with open(f"/proc/{pid}/status") as f:
                for sl in f:
                    if sl.startswith("VmRSS:"):
                        rss = int(sl.split()[1])
                        if rss > best_rss and rss > 1000000:
                            best_rss = rss
                            best_pid = pid
        except (OSError, ValueError):
            pass
    return best_pid


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

def scan_memory(
    mem_file: BinaryIO,
    base_addr: int,
    text_start: int,
    text_size: int,
    patterns: Optional[list] = None,
    use_cache: bool = True,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> dict:
    """
    Scan the .text section for all known function signatures.

    Args:
        mem_file: Open file handle to /proc/PID/mem (mode 'rb').
        base_addr: The mapped base address of the game image.
        text_start: Absolute start address of the .text section.
        text_size: Size of the .text section in bytes.
        patterns: List of ScanPattern objects. Defaults to PATTERNS.
        use_cache: Try loading from cache first and save after scan.
        chunk_size: Read chunk size in bytes. Default 16 MB.

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
        except (OSError, ValueError) as e:
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
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Signature scanner for Fallout 76 on Linux"
    )
    parser.add_argument("--pid", type=int, help="Game PID (auto-detected if omitted)")
    parser.add_argument("--no-cache", action="store_true", help="Force rescan, ignore cache")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    pid = args.pid or find_game_pid()
    if not pid:
        print("ERROR: Fallout 76 not running. Start the game first.")
        sys.exit(1)

    if not os.path.exists(f"/proc/{pid}/maps"):
        print(f"ERROR: PID {pid} not found in /proc.")
        sys.exit(1)

    print(f"Fallout 76 PID: {pid}")
    print(f"Image base: 0x{IMAGE_BASE:X}")
    print()

    mem = open(f"/proc/{pid}/mem", "rb")

    sections = parse_pe_sections(mem, IMAGE_BASE)
    text = sections['.text']
    print(f".text:  0x{text['va']:X} - 0x{text['end']:X} ({text['vsize']/(1024*1024):.1f} MB)")
    print(f"Patterns: {len(PATTERNS)}")
    print()

    results = scan_memory(
        mem_file=mem,
        base_addr=IMAGE_BASE,
        text_start=text['va'],
        text_size=text['vsize'],
        use_cache=not args.no_cache,
    )

    print()
    print(format_scan_results(results, IMAGE_BASE))
    print()
    print(f"Found {len(results)}/{len(PATTERNS)} patterns.")

    mem.close()


if __name__ == "__main__":
    main()
