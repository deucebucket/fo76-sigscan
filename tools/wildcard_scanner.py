#!/usr/bin/env python3
"""
Wildcard Signature Scanner for FO76 Address Library v3.1

Multi-strategy approach to match dev build signatures against retail:

Strategy 1: Variable-length prefix matching with wildcard masks
  - Try prefix lengths 48 down to 8, mask relocation bytes
  - Accept only unique matches

Strategy 2: Aggressive masks (also mask MOV immediates)
  - Accept unique matches with at least 10 concrete bytes

Strategy 3: Interior subsequence matching
  - For signatures where prefix fails, try matching interior subsequences
  - Use function boundary detection to find actual function start
  - Require at least 10 concrete bytes for interior matches

Post-processing: Remove duplicate retail addresses (keep best match only)
"""

import json
import struct
import time
from pathlib import Path
from collections import defaultdict

RETAIL_EXE = Path("/home/deucebucket/.steam/steam/steamapps/common/Fallout76/Fallout76.exe")
SIGS_FILE = Path("/var/home/deucebucket/ai-drive/gamecryptids/tools/sfe_scanner/dev_build_signatures.json")
ADDR_LIB = Path("/var/home/deucebucket/ai-drive/gamecryptids/tools/sfe_scanner/address_library.json")
ADDR_LIB_COPY = Path("/var/home/deucebucket/ai-drive/fo76-data/data/dev_build/address_library.json")
IMAGE_BASE = 0x140000000

PREFIX_LENGTHS = [48, 40, 32, 24, 20, 16, 14, 12, 10, 8]
MIN_CONCRETE_PREFIX = 6   # For prefix matches
MIN_CONCRETE_INTERIOR = 10  # For interior matches (stricter)


def parse_pe_sections(exe_path):
    """Extract all PE sections."""
    sections = {}
    with open(exe_path, 'rb') as f:
        f.seek(0x3C)
        pe_offset = struct.unpack('<I', f.read(4))[0]
        f.seek(pe_offset + 4)
        _machine, num_sections = struct.unpack('<HH', f.read(4))
        f.read(12)
        opt_header_size = struct.unpack('<H', f.read(2))[0]
        f.read(2)
        f.seek(pe_offset + 24 + opt_header_size)

        for _ in range(num_sections):
            name = f.read(8).rstrip(b'\x00').decode('ascii', errors='replace')
            virt_size, virt_addr, raw_size, raw_offset = struct.unpack('<IIII', f.read(16))
            f.read(16)
            sections[name] = {
                'va': virt_addr,
                'vsize': virt_size,
                'raw_offset': raw_offset,
                'raw_size': raw_size
            }

        result = {}
        for name, info in sections.items():
            f.seek(info['raw_offset'])
            result[name] = {
                'data': f.read(info['raw_size']),
                'rva': info['va'],
                'size': info['raw_size']
            }
    return result


def build_mask(sig_bytes):
    """Build wildcard mask, masking RIP-relative displacements."""
    n = len(sig_bytes)
    mask = [True] * n

    i = 0
    while i < n:
        byte = sig_bytes[i]

        # E8/E9 rel32
        if byte in (0xE8, 0xE9) and i + 4 < n:
            for j in range(i + 1, min(i + 5, n)):
                mask[j] = False
            i += 5
            continue

        # 0F 8x rel32
        if byte == 0x0F and i + 1 < n and 0x80 <= sig_bytes[i + 1] <= 0x8F and i + 5 < n:
            for j in range(i + 2, min(i + 6, n)):
                mask[j] = False
            i += 6
            continue

        # REX (40-4F) + opcode + ModRM[rip] (mod=00 rm=101)
        if 0x40 <= byte <= 0x4F and i + 2 < n:
            opcode = sig_bytes[i + 1]
            modrm = sig_bytes[i + 2]
            if (modrm >> 6) == 0 and (modrm & 7) == 5 and i + 6 < n:
                for j in range(i + 3, min(i + 7, n)):
                    mask[j] = False
                i += 7
                continue
            if opcode == 0x0F and i + 3 < n:
                modrm2 = sig_bytes[i + 3]
                if (modrm2 >> 6) == 0 and (modrm2 & 7) == 5 and i + 7 < n:
                    for j in range(i + 4, min(i + 8, n)):
                        mask[j] = False
                    i += 8
                    continue

        # Non-REX ModRM[rip]
        modrm_opcodes = {
            0x01, 0x03, 0x09, 0x0B, 0x11, 0x13, 0x19, 0x1B,
            0x21, 0x23, 0x29, 0x2B, 0x31, 0x33, 0x39, 0x3B,
            0x63, 0x69, 0x6B,
            0x80, 0x81, 0x83, 0x85, 0x87, 0x89, 0x8B, 0x8D,
            0xC7, 0xD1, 0xD3, 0xF7, 0xFF
        }
        if byte in modrm_opcodes and i + 1 < n:
            modrm = sig_bytes[i + 1]
            if (modrm >> 6) == 0 and (modrm & 7) == 5 and i + 5 < n:
                for j in range(i + 2, min(i + 6, n)):
                    mask[j] = False
                i += 6
                continue

        i += 1

    return mask


def build_aggressive_mask(sig_bytes):
    """More aggressive masking: also mask MOV reg, imm32 patterns."""
    mask = build_mask(sig_bytes)
    n = len(sig_bytes)

    i = 0
    while i < n:
        byte = sig_bytes[i]

        # MOV reg, imm32 (B8+rd)
        if 0xB8 <= byte <= 0xBF and i + 4 < n:
            for j in range(i + 1, min(i + 5, n)):
                mask[j] = False
            i += 5
            continue

        # REX + MOV reg, imm32
        if 0x48 <= byte <= 0x4F and i + 1 < n and 0xB8 <= sig_bytes[i + 1] <= 0xBF and i + 5 < n:
            for j in range(i + 2, min(i + 6, n)):
                mask[j] = False
            i += 6
            continue

        i += 1

    return mask


def search_masked(text_data, sig_bytes, mask, max_matches=2):
    """Search with wildcard mask. Returns list of offsets."""
    n = len(sig_bytes)
    text_len = len(text_data)
    if n > text_len:
        return []

    concrete = [(i, sig_bytes[i]) for i in range(n) if mask[i]]
    if len(concrete) < MIN_CONCRETE_PREFIX:
        return []

    # Find longest consecutive concrete run for anchor
    best_start = concrete[0][0]
    best_len = 1
    run_start = concrete[0][0]
    run_len = 1
    for k in range(1, len(concrete)):
        if concrete[k][0] == concrete[k-1][0] + 1:
            run_len += 1
            if run_len > best_len:
                best_len = run_len
                best_start = run_start
        else:
            run_start = concrete[k][0]
            run_len = 1

    matches = []
    if best_len >= 3:
        anchor = bytes(sig_bytes[best_start:best_start + best_len])
        pos = 0
        while pos <= text_len - n:
            idx = text_data.find(anchor, pos + best_start, text_len - n + best_start + best_len)
            if idx == -1:
                break
            start = idx - best_start
            if start < 0:
                pos = idx + 1
                continue
            ok = True
            for off, b in concrete:
                if best_start <= off < best_start + best_len:
                    continue
                if text_data[start + off] != b:
                    ok = False
                    break
            if ok:
                matches.append(start)
                if len(matches) > max_matches:
                    return matches
            pos = idx + 1
    else:
        first_off, first_byte = concrete[0]
        fb = bytes([first_byte])
        pos = 0
        while pos <= text_len - n:
            idx = text_data.find(fb, pos + first_off, text_len - n + first_off + 1)
            if idx == -1:
                break
            start = idx - first_off
            if start < 0:
                pos = idx + 1
                continue
            ok = True
            for off, b in concrete[1:]:
                if text_data[start + off] != b:
                    ok = False
                    break
            if ok:
                matches.append(start)
                if len(matches) > max_matches:
                    return matches
            pos = idx + 1

    return matches


def find_function_start(text_data, offset):
    """
    Given an offset within .text, find the function start by searching
    backwards for CC/90 padding (function boundary markers).
    Returns the offset of the first instruction after padding, or None.
    """
    search_start = max(0, offset - 512)
    for i in range(offset - 1, search_start, -1):
        b = text_data[i]
        if b == 0xCC or b == 0x90:
            # Found padding - check next byte is a real instruction
            candidate = i + 1
            if candidate < len(text_data):
                next_b = text_data[candidate]
                # Common function starts: push, sub rsp, mov, REX prefixes
                if next_b in (0x40, 0x41, 0x44, 0x45, 0x48, 0x49, 0x4C, 0x4D,
                              0x53, 0x55, 0x56, 0x57, 0xE8, 0xE9, 0x33, 0xB8,
                              0x8B, 0x89, 0x0F, 0x83, 0x85, 0xF6, 0x80, 0xC6,
                              0xC7, 0x45, 0xFF):
                    return candidate
            # Check if we're at the start of a padding run
            if i > 0 and text_data[i-1] != 0xCC and text_data[i-1] != 0x90:
                return i + 1
    return None


def match_confidence(data):
    """Score a match for deduplication. Higher = more confident."""
    score = 0
    concrete = data.get('concrete_bytes', 0)
    sig_len = data.get('sig_length_used', 0)
    mt = data.get('match_type', '')

    score += concrete * 10  # More concrete bytes = better
    score += sig_len * 2    # Longer sig = better

    if 'prefix' in mt or 'exact' in mt or 'unique' in mt:
        score += 100  # Prefix/exact matches anchor at function start
    if 'aggressive' in mt:
        score += 50
    if 'interior' in mt:
        score += 20
        # Penalize interior matches with function start detection
        if data.get('interior_offset', 0) > 15:
            score -= 10

    return score


def main():
    print("=== FO76 Wildcard Signature Scanner v3.1 ===\n")

    print("Loading dev build signatures...")
    with open(SIGS_FILE) as f:
        dev_sigs = json.load(f)
    print(f"  {len(dev_sigs)} signatures loaded")

    print("Loading existing address library...")
    with open(ADDR_LIB) as f:
        addr_lib = json.load(f)

    # First, remove any previous wildcard/interior matches that were low quality
    # Keep only: 'unique', 'exact', and high-quality matches
    clean_lib = {}
    removed = 0
    for name, data in addr_lib.items():
        mt = data.get('match_type', 'unique')
        if mt in ('unique', 'exact'):
            clean_lib[name] = data
        elif 'prefix' in mt or 'aggressive' in mt:
            # Keep if concrete bytes >= 10
            if data.get('concrete_bytes', 0) >= 10:
                clean_lib[name] = data
            else:
                removed += 1
        elif 'wildcard' in mt:
            if data.get('concrete_bytes', 0) >= 10:
                clean_lib[name] = data
            else:
                removed += 1
        elif 'interior' in mt:
            if data.get('concrete_bytes', 0) >= 10:
                clean_lib[name] = data
            else:
                removed += 1
        else:
            clean_lib[name] = data

    if removed > 0:
        print(f"  Removed {removed} low-quality previous matches")
    addr_lib = clean_lib
    print(f"  {len(addr_lib)} clean existing matches")

    already_matched = set(addr_lib.keys())

    print("Loading retail PE sections...")
    sections = parse_pe_sections(RETAIL_EXE)
    text_data = sections['.text']['data']
    text_rva = sections['.text']['rva']
    print(f"  .text: RVA=0x{text_rva:X}, size={len(text_data)/1024/1024:.1f}MB")

    unmatched = {name: data for name, data in dev_sigs.items() if name not in already_matched}
    total = len(unmatched)
    print(f"\n{total} unmatched signatures to scan")

    new_matches = {}
    strategy_stats = defaultdict(int)
    start_time = time.time()

    for idx, (name, data) in enumerate(unmatched.items()):
        if (idx + 1) % 500 == 0 or idx == 0:
            elapsed = time.time() - start_time
            rate = (idx + 1) / elapsed if elapsed > 0 else 0
            print(f"  [{idx+1}/{total}] {len(new_matches)} new matches, {rate:.0f} sigs/sec", flush=True)

        full_sig = bytes.fromhex(data['signature'])
        dev_rva = data['dev_rva']
        found = False

        # Strategy 1: Variable-length prefix with standard masks
        for plen in PREFIX_LENGTHS:
            if plen > len(full_sig):
                continue
            prefix = list(full_sig[:plen])
            mask = build_mask(prefix)
            if mask.count(True) < MIN_CONCRETE_PREFIX:
                continue

            matches = search_masked(text_data, prefix, mask)
            if len(matches) == 1:
                retail_rva = text_rva + matches[0]
                wc = mask.count(False)
                new_matches[name] = {
                    "dev_va": data['dev_va'],
                    "dev_rva": dev_rva,
                    "retail_rva": retail_rva,
                    "retail_va": IMAGE_BASE + retail_rva,
                    "sig_length_used": plen,
                    "match_type": f"prefix-{plen}b" + (f"-{wc}wc" if wc else ""),
                    "wildcarded_bytes": wc,
                    "concrete_bytes": mask.count(True)
                }
                strategy_stats[f"S1-prefix-{plen}b"] += 1
                found = True
                break

        if found:
            continue

        # Strategy 2: Aggressive masks
        for plen in [48, 32, 24, 20, 16]:
            if plen > len(full_sig):
                continue
            prefix = list(full_sig[:plen])
            mask = build_aggressive_mask(prefix)
            if mask.count(True) < MIN_CONCRETE_PREFIX:
                continue
            std_mask = build_mask(prefix)
            if mask == std_mask:
                continue

            matches = search_masked(text_data, prefix, mask)
            if len(matches) == 1:
                retail_rva = text_rva + matches[0]
                wc = mask.count(False)
                new_matches[name] = {
                    "dev_va": data['dev_va'],
                    "dev_rva": dev_rva,
                    "retail_rva": retail_rva,
                    "retail_va": IMAGE_BASE + retail_rva,
                    "sig_length_used": plen,
                    "match_type": f"aggressive-{plen}b-{wc}wc",
                    "wildcarded_bytes": wc,
                    "concrete_bytes": mask.count(True)
                }
                strategy_stats[f"S2-aggressive-{plen}b"] += 1
                found = True
                break

        if found:
            continue

        # Strategy 3: Interior subsequence matching
        # Require longer subsequences for interior (more concrete bytes to avoid false positives)
        for start_off in [5, 1, 10, 15, 20]:
            if start_off >= len(full_sig) - 12:
                continue
            for sublen in [32, 28, 24, 20, 16]:
                end = start_off + sublen
                if end > len(full_sig):
                    continue
                sub = list(full_sig[start_off:end])
                mask = build_mask(sub)
                concrete_count = mask.count(True)
                if concrete_count < MIN_CONCRETE_INTERIOR:
                    continue

                matches = search_masked(text_data, sub, mask)
                if len(matches) == 1:
                    match_offset = matches[0]
                    func_start = find_function_start(text_data, match_offset)
                    if func_start is None:
                        func_start = match_offset - start_off
                        if func_start < 0:
                            continue

                    retail_rva = text_rva + func_start
                    wc = mask.count(False)
                    new_matches[name] = {
                        "dev_va": data['dev_va'],
                        "dev_rva": dev_rva,
                        "retail_rva": retail_rva,
                        "retail_va": IMAGE_BASE + retail_rva,
                        "sig_length_used": sublen,
                        "match_type": f"interior-off{start_off}-{sublen}b-{wc}wc",
                        "wildcarded_bytes": wc,
                        "concrete_bytes": concrete_count,
                        "interior_offset": start_off
                    }
                    strategy_stats[f"S3-interior-off{start_off}"] += 1
                    found = True
                    break
            if found:
                break

    elapsed = time.time() - start_time
    print(f"\nScan complete in {elapsed:.1f}s")

    print(f"\nNew matches by strategy:")
    for strat, count in sorted(strategy_stats.items(), key=lambda x: -x[1]):
        print(f"  {strat}: {count}")
    print(f"  Total new: {len(new_matches)}")

    # Merge with existing
    merged = dict(addr_lib)
    merged.update(new_matches)

    # Post-processing: deduplicate retail addresses
    # If multiple functions map to the same retail address, keep only the best one
    rva_to_names = defaultdict(list)
    for name, data in merged.items():
        rva_to_names[data['retail_rva']].append(name)

    dupes_removed = 0
    for rva, names in rva_to_names.items():
        if len(names) > 1:
            # Some legitimate cases: dev had different names for same function
            # But 10+ at same address is certainly wrong
            if len(names) > 3:
                # Keep the one with highest confidence
                best_name = max(names, key=lambda n: match_confidence(merged[n]))
                for n in names:
                    if n != best_name:
                        del merged[n]
                        dupes_removed += 1

    if dupes_removed > 0:
        print(f"\nRemoved {dupes_removed} duplicate-address entries (kept best match)")

    total_matches = len(merged)
    print(f"\nTotal matches: {total_matches}/{len(dev_sigs)} ({100*total_matches/len(dev_sigs):.1f}%)")
    print(f"  Previously (cleaned): {len(addr_lib)} ({100*len(addr_lib)/len(dev_sigs):.1f}%)")
    print(f"  Added: {len(new_matches)}")
    print(f"  After dedup: {total_matches}")

    # Verify unique retail addresses
    rva_counts = defaultdict(int)
    for data in merged.values():
        rva_counts[data['retail_rva']] += 1
    multi = sum(1 for c in rva_counts.values() if c > 1)
    print(f"  Unique retail addresses: {len(rva_counts)} (remaining dupes: {multi} addresses)")

    # Save
    print(f"\nSaving to {ADDR_LIB}...")
    with open(ADDR_LIB, 'w') as f:
        json.dump(merged, f, indent=2)

    ADDR_LIB_COPY.parent.mkdir(parents=True, exist_ok=True)
    print(f"Saving copy to {ADDR_LIB_COPY}...")
    with open(ADDR_LIB_COPY, 'w') as f:
        json.dump(merged, f, indent=2)

    # Match type breakdown
    type_counts = defaultdict(int)
    for data in merged.values():
        mt = data.get('match_type', 'unknown')
        type_counts[mt] += 1
    print("\nMatch type distribution (top 20):")
    for mt, c in sorted(type_counts.items(), key=lambda x: -x[1])[:20]:
        print(f"  {mt}: {c}")

    # Sample new matches
    if new_matches:
        print(f"\nSample new matches (first 15):")
        for i, (name, d) in enumerate(list(new_matches.items())[:15]):
            if name in merged:  # wasn't deduped
                print(f"  {name}")
                print(f"    dev=0x{d['dev_rva']:X} -> retail=0x{d['retail_rva']:X} ({d['match_type']}, {d['concrete_bytes']}cb)")


if __name__ == '__main__':
    main()
