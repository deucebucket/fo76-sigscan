#!/usr/bin/env python3
"""
FO76 g_player Pointer Finder

Scans the .text section for RIP-relative references to g_player, a static
pointer to PlayerCharacter* stored in .data. This finds the g_player global
variable address across game updates without hardcoded offsets.

Strategy:
  1. Parse PE section headers from /proc/PID/mem
  2. Scan .text for `mov reg, [rip+disp32]` and `lea reg, [rip+disp32]`
  3. Calculate target addresses in .data
  4. Group by target, rank by reference count
  5. For each candidate: read ptr, check for FormID 0x14 at +0x38
  6. Verify by reading position twice with movement check

Usage:
    python3 find_g_player.py              # auto-detect PID
    python3 find_g_player.py --pid 12345  # specify PID

IMPORTANT: Player must be MOVING in-game during the verification phase!

Known offsets for FO76 1.7.x:
  - FormID at +0x38 (confirmed)
  - Position (NiPoint3) at +0xD0 (approximate, may shift between builds)
"""

import argparse
import struct
import sys
import os
import json
import math
import time
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime

IMAGE_BASE = 0x140000000
POSITION_OFFSET = 0xD0   # NiPoint3 offset in PlayerCharacter
FORMID_OFFSET = 0x38      # FormID offset (confirmed for 1.7.23.39)

OUTPUT_DIR = Path(__file__).parent / "results"


def find_game_pid():
    """Find FO76 PID (largest RSS Fallout76 process)."""
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


def parse_pe_sections(mem, base_addr):
    """Read PE section headers from the image base."""
    mem.seek(base_addr)
    dos = mem.read(0x40)
    e_lfanew = struct.unpack_from('<I', dos, 0x3C)[0]

    mem.seek(base_addr + e_lfanew)
    pe_sig = mem.read(4)
    assert pe_sig == b'PE\x00\x00', f"Bad PE signature: {pe_sig}"

    coff = mem.read(20)
    num_sections = struct.unpack_from('<H', coff, 2)[0]
    opt_header_size = struct.unpack_from('<H', coff, 16)[0]

    mem.seek(base_addr + e_lfanew + 4 + 20 + opt_header_size)

    sections = {}
    for _ in range(num_sections):
        sec = mem.read(40)
        name = sec[:8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', sec, 8)[0]
        vaddr = struct.unpack_from('<I', sec, 12)[0]
        chars = struct.unpack_from('<I', sec, 36)[0]
        sections[name] = {
            'va': base_addr + vaddr,
            'vsize': vsize,
            'end': base_addr + vaddr + vsize,
            'chars': chars,
        }
    return sections


def parse_maps(pid):
    """Parse /proc/PID/maps and return executable regions in the FO76 image range."""
    text_regions = []

    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            addr_range = parts[0]
            perms = parts[1]
            start_s, end_s = addr_range.split('-')
            start = int(start_s, 16)
            end = int(end_s, 16)

            if start < IMAGE_BASE or start > 0x150000000:
                continue
            if 'x' in perms:
                text_regions.append((start, end))

    return text_regions


def scan_rip_relative_refs(mem, text_regions, data_start, data_end):
    """
    Scan .text for RIP-relative MOV/LEA instructions that reference .data addresses.
    Returns (target_counter, target_refs).
    """
    target_counter = Counter()
    target_refs = defaultdict(list)

    reg_names = {
        0x48: {0x05: 'rax', 0x0D: 'rcx', 0x15: 'rdx', 0x1D: 'rbx',
               0x35: 'rsi', 0x3D: 'rdi'},
        0x4C: {0x05: 'r8', 0x0D: 'r9', 0x15: 'r10', 0x1D: 'r11',
               0x25: 'r12', 0x2D: 'r13', 0x35: 'r14', 0x3D: 'r15'},
    }

    for region_start, region_end in text_regions:
        size = region_end - region_start
        try:
            mem.seek(region_start)
            data = mem.read(size)
        except (OSError, ValueError) as e:
            print(f"  Failed to read 0x{region_start:X}-0x{region_end:X}: {e}")
            continue

        for i in range(len(data) - 6):
            byte0 = data[i]
            if byte0 not in (0x48, 0x4C):
                continue

            byte1 = data[i + 1]
            if byte1 not in (0x8B, 0x8D):
                continue

            modrm = data[i + 2]
            if (modrm & 0xC7) != 0x05:
                continue

            disp = struct.unpack_from('<i', data, i + 3)[0]
            instr_addr = region_start + i
            next_instr = instr_addr + 7
            target = next_instr + disp

            if target < data_start or target >= data_end:
                continue

            reg_idx = modrm & 0x38 | 0x05
            reg = reg_names.get(byte0, {}).get(reg_idx, f'?{modrm:02X}')
            opname = 'mov' if byte1 == 0x8B else 'lea'

            target_counter[target] += 1
            if len(target_refs[target]) < 10:
                target_refs[target].append((instr_addr, reg, opname))

    return target_counter, target_refs


def read_ptr(mem, addr):
    """Read a 64-bit pointer at addr."""
    try:
        mem.seek(addr)
        return struct.unpack('<Q', mem.read(8))[0]
    except:
        return 0


def read_floats(mem, addr, count=3):
    """Read count floats at addr."""
    try:
        mem.seek(addr)
        return struct.unpack(f'<{count}f', mem.read(4 * count))
    except:
        return None


def read_uint32(mem, addr):
    """Read a uint32 at addr."""
    try:
        mem.seek(addr)
        return struct.unpack('<I', mem.read(4))[0]
    except:
        return None


def is_valid_heap_ptr(val):
    """Check if a value looks like a valid heap pointer."""
    return 0x100000000 < val < 0x7FFFFFFFFFFF


def check_candidate(mem, data_addr, rdata_start=None, rdata_end=None):
    """
    Check a .data address as a potential g_player pointer.

    g_player is a static pointer in .data that directly holds a PlayerCharacter*.
    PlayerCharacter has:
      - vtable pointer at +0x00 (in .rdata)
      - FormID 0x14 at +0x38
      - NiPoint3 position at +0xD0
    """
    ptr = read_ptr(mem, data_addr)
    if not is_valid_heap_ptr(ptr):
        return None

    result = {
        'data_addr': data_addr,
        'rva': data_addr - IMAGE_BASE,
        'ptr': ptr,
    }

    vtable = read_ptr(mem, ptr)
    result['vtable'] = vtable
    if rdata_start and rdata_end:
        result['vtable_in_rdata'] = rdata_start <= vtable < rdata_end

    formid = read_uint32(mem, ptr + FORMID_OFFSET)
    result['formid'] = formid
    result['is_player_form'] = (formid == 0x14)

    pos = read_floats(mem, ptr + POSITION_OFFSET)
    if pos:
        x, y, z = pos
        result['position'] = {'x': round(x, 4), 'y': round(y, 4), 'z': round(z, 4)}
        result['valid_position'] = (
            all(not (math.isnan(v) or math.isinf(v)) for v in [x, y, z])
            and all(abs(v) < 200000 for v in [x, y, z])
        )

    # Scan wider range of offsets for position-like data
    result['alt_positions'] = []
    try:
        mem.seek(ptr)
        obj_data = mem.read(0x500)
        for off in range(0, len(obj_data) - 12, 4):
            x, y, z = struct.unpack_from('<fff', obj_data, off)
            if any(math.isnan(v) or math.isinf(v) for v in [x, y, z]):
                continue
            if (all(abs(v) < 100000 for v in [x, y, z])
                    and sum(1 for v in [x, y, z] if abs(v) > 10) >= 2):
                result['alt_positions'].append({
                    'offset': off,
                    'x': round(x, 2), 'y': round(y, 2), 'z': round(z, 2)
                })
    except:
        pass

    return result


def verify_movement(mem, candidates, wait_time=3):
    """
    Read position from candidates twice with a delay.
    Returns candidates with movement data added.
    """
    readings = {}
    for c in candidates:
        ptr = c['ptr']
        pos = read_floats(mem, ptr + POSITION_OFFSET)
        if pos:
            readings[c['data_addr']] = {'pos': pos, 'offset': POSITION_OFFSET}

        for alt in c.get('alt_positions', []):
            off = alt['offset']
            pos = read_floats(mem, ptr + off)
            if pos:
                key = (c['data_addr'], off)
                readings[key] = {'pos': pos, 'offset': off, 'data_addr': c['data_addr']}

    print(f"  First read: {len(readings)} position readings")
    print(f"  Waiting {wait_time}s -- MOVE YOUR CHARACTER IN-GAME!")
    time.sleep(wait_time)

    results = []
    for c in candidates:
        ptr = c['ptr']

        for key_suffix in [POSITION_OFFSET] + [a['offset'] for a in c.get('alt_positions', [])]:
            if isinstance(key_suffix, int):
                key = c['data_addr'] if key_suffix == POSITION_OFFSET else (c['data_addr'], key_suffix)

            if key not in readings:
                continue

            r = readings[key]
            pos2 = read_floats(mem, ptr + r['offset'])
            if not pos2:
                continue

            x1, y1, z1 = r['pos']
            x2, y2, z2 = pos2
            dist = math.sqrt((x2 - x1)**2 + (y2 - y1)**2 + (z2 - z1)**2)

            if dist > 0.1:
                results.append({
                    'data_addr': c['data_addr'],
                    'rva': c['data_addr'] - IMAGE_BASE,
                    'ptr': c['ptr'],
                    'offset': r['offset'],
                    'pos1': {'x': round(x1, 2), 'y': round(y1, 2), 'z': round(z1, 2)},
                    'pos2': {'x': round(x2, 2), 'y': round(y2, 2), 'z': round(z2, 2)},
                    'movement': round(dist, 4),
                    'ref_count': c.get('ref_count', 0),
                    'formid': c.get('formid'),
                })

    results.sort(key=lambda x: x['movement'], reverse=True)
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Find g_player (PlayerCharacter*) pointer in FO76 process memory"
    )
    parser.add_argument("--pid", type=int, help="Game PID (auto-detected if omitted)")
    args = parser.parse_args()

    pid = args.pid or find_game_pid()
    if not pid:
        print("ERROR: FO76 not running! Start the game first.")
        sys.exit(1)

    if not os.path.exists(f"/proc/{pid}/maps"):
        print(f"ERROR: PID {pid} not found!")
        sys.exit(1)

    print("=" * 70)
    print("FO76 g_player POINTER FINDER")
    print("=" * 70)
    print(f"PID: {pid}")
    print(f"Image base: 0x{IMAGE_BASE:X}")
    print()

    mem = open(f"/proc/{pid}/mem", "rb")

    # Read PE sections
    sections = parse_pe_sections(mem, IMAGE_BASE)
    data_sec = sections['.data']
    rdata_sec = sections['.rdata']
    text_sec = sections['.text']

    print(f".text:  0x{text_sec['va']:X} - 0x{text_sec['end']:X} ({text_sec['vsize']/(1024*1024):.1f} MB)")
    print(f".rdata: 0x{rdata_sec['va']:X} - 0x{rdata_sec['end']:X} ({rdata_sec['vsize']/(1024*1024):.1f} MB)")
    print(f".data:  0x{data_sec['va']:X} - 0x{data_sec['end']:X} ({data_sec['vsize']/(1024*1024):.1f} MB)")
    print()

    text_regions = parse_maps(pid)
    text_total = sum(e - s for s, e in text_regions)
    print(f"Executable regions: {len(text_regions)} ({text_total/(1024*1024):.1f} MB)")

    # Phase 1: Scan for RIP-relative references
    print("\n" + "=" * 70)
    print("PHASE 1: Scanning .text for RIP-relative references to .data...")
    print("-" * 70)

    target_counter, target_refs = scan_rip_relative_refs(
        mem, text_regions, data_sec['va'], data_sec['end']
    )
    print(f"\nFound {len(target_counter)} unique .data targets referenced from .text")

    # Phase 2: Check top candidates for FormID 0x14
    print("\n" + "=" * 70)
    print("PHASE 2: Checking top .data targets for FormID 0x14...")
    print("-" * 70)

    top_targets = target_counter.most_common(500)
    player_candidates = []
    all_valid = []

    for addr, count in top_targets:
        result = check_candidate(mem, addr, rdata_sec['va'], rdata_sec['end'])
        if not result:
            continue
        result['ref_count'] = count

        if result.get('is_player_form'):
            player_candidates.append(result)
        if result.get('valid_position') or result.get('alt_positions'):
            all_valid.append(result)

    print(f"\nFormID=0x14 candidates: {len(player_candidates)}")
    for c in player_candidates:
        rva = c['rva']
        print(f"  RVA 0x{rva:X} ({c['ref_count']} refs) -> 0x{c['ptr']:X}")
        if c.get('position'):
            p = c['position']
            print(f"    pos@+0xD0: ({p['x']:.2f}, {p['y']:.2f}, {p['z']:.2f})")

    # Phase 3: Full .data scan for FormID 0x14
    print("\n" + "=" * 70)
    print("PHASE 3: Full .data scan for pointers to FormID 0x14 objects...")
    print("-" * 70)

    mem.seek(data_sec['va'])
    full_data = mem.read(data_sec['vsize'])

    for i in range(0, len(full_data) - 8, 8):
        ptr = struct.unpack_from('<Q', full_data, i)[0]
        if not is_valid_heap_ptr(ptr):
            continue

        formid = read_uint32(mem, ptr + FORMID_OFFSET)
        if formid != 0x14:
            continue

        data_addr = data_sec['va'] + i
        if any(c['data_addr'] == data_addr for c in player_candidates):
            continue

        result = check_candidate(mem, data_addr, rdata_sec['va'], rdata_sec['end'])
        if result:
            result['ref_count'] = target_counter.get(data_addr, 0)
            player_candidates.append(result)

    print(f"Total FormID=0x14 candidates after full scan: {len(player_candidates)}")
    for c in player_candidates:
        rva = c['rva']
        refs = c['ref_count']
        print(f"  RVA 0x{rva:X} ({refs} refs) -> 0x{c['ptr']:X}, vtable=0x{c.get('vtable', 0):X}")

    # Phase 4: Movement verification
    candidates_to_verify = player_candidates if player_candidates else all_valid[:50]

    if candidates_to_verify:
        print("\n" + "=" * 70)
        print("PHASE 4: Movement verification (3 second window)...")
        print("*** MOVE YOUR CHARACTER IN-GAME NOW! ***")
        print("-" * 70)

        moved = verify_movement(mem, candidates_to_verify, wait_time=3)

        if moved:
            print(f"\nPositions that CHANGED ({len(moved)}):")
            for m in moved[:20]:
                print(f"\n  RVA 0x{m['rva']:X} (refs={m['ref_count']}, formid=0x{m.get('formid', 0):X})")
                print(f"    Offset: +0x{m['offset']:X}")
                p1 = m['pos1']
                p2 = m['pos2']
                print(f"    Before: ({p1['x']:.2f}, {p1['y']:.2f}, {p1['z']:.2f})")
                print(f"    After:  ({p2['x']:.2f}, {p2['y']:.2f}, {p2['z']:.2f})")
                print(f"    Movement: {m['movement']:.2f} game units")

            best = moved[0]
            print(f"\n{'=' * 70}")
            print(f"BEST g_player CANDIDATE:")
            print(f"{'=' * 70}")
            print(f"  .data address: 0x{best['data_addr']:X}")
            print(f"  RVA:           0x{best['rva']:X}")
            print(f"  Pointer:       0x{best['ptr']:X}")
            print(f"  Position offset: +0x{best['offset']:X}")
            print(f"  Refs from .text: {best['ref_count']}")
            print(f"  FormID:        0x{best.get('formid', 0):X}")
            print(f"  Movement:      {best['movement']:.2f} units")
            print(f"  Current pos:   ({best['pos2']['x']:.2f}, {best['pos2']['y']:.2f}, {best['pos2']['z']:.2f})")

            target_addr = best['data_addr']
            if target_addr in target_refs:
                print(f"\n  Code references from .text:")
                for ia, reg, opname in target_refs[target_addr][:10]:
                    print(f"    0x{ia:X} (RVA 0x{ia - IMAGE_BASE:X}): {opname} {reg}, [rip+disp]")
        else:
            print("\n  No movement detected!")
            print("  Make sure you are ACTIVELY WALKING in-game during the verification.")
    else:
        print("\nNo candidates to verify.")

    # Phase 5: Reference summary
    print("\n" + "=" * 70)
    print("TOP 20 .data TARGETS BY REFERENCE COUNT:")
    print("-" * 70)

    for i, (addr, count) in enumerate(top_targets[:20]):
        rva = addr - IMAGE_BASE
        refs = target_refs[addr][:2]
        ref_str = ", ".join(f"{opname} {reg}" for _, reg, opname in refs)

        ptr = read_ptr(mem, addr)
        ptr_str = f"0x{ptr:X}" if ptr else "NULL"

        formid = None
        if is_valid_heap_ptr(ptr):
            formid = read_uint32(mem, ptr + FORMID_OFFSET)

        fid_str = f" formid=0x{formid:X}" if formid is not None else ""
        print(f"  #{i+1:2d}: RVA 0x{rva:X} -- {count:5d} refs -- ptr={ptr_str}{fid_str} -- {ref_str}")

    # Save results
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_DIR / "g_player_scan.json"

    result = {
        "timestamp": datetime.now().isoformat(),
        "pid": pid,
        "image_base": f"0x{IMAGE_BASE:X}",
        "sections": {
            name: {"va": f"0x{s['va']:X}", "end": f"0x{s['end']:X}", "vsize": s['vsize']}
            for name, s in sections.items()
        },
        "total_data_refs": len(target_counter),
        "player_candidates": [
            {
                "rva": f"0x{c['rva']:X}",
                "ptr": f"0x{c['ptr']:X}",
                "vtable": f"0x{c.get('vtable', 0):X}",
                "ref_count": c.get('ref_count', 0),
                "formid": f"0x{c.get('formid', 0):X}",
                "position": c.get('position'),
                "alt_positions": c.get('alt_positions', [])[:5],
            }
            for c in player_candidates
        ],
        "top_30_by_refcount": [
            {"addr": f"0x{a:X}", "rva": f"0x{a - IMAGE_BASE:X}", "refs": c}
            for a, c in top_targets[:30]
        ],
    }

    output_file.write_text(json.dumps(result, indent=2))
    print(f"\nResults saved to: {output_file}")

    mem.close()


if __name__ == "__main__":
    main()
