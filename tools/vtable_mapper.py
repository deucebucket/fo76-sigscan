#!/usr/bin/env python3
"""
RTTI VTable Mapper for Fallout 76
Cross-references vtables between dev (Project76Profile.exe) and retail (Fallout76.exe)
to map additional functions for the Address Library.

Strategy:
1. Find RTTI type descriptors and vtables in both builds
2. Match classes by name between dev and retail
3. For each matched class vtable:
   a. If a dev vtable function has a name from dev_build_signatures, use that name
   b. Otherwise, generate a positional name like "ClassName::vfunc_N"
4. Map the corresponding retail function RVA

MSVC x64 RTTI layout:
  - TypeDescriptor: { pVFTable(8), spare(8), name[] } where name starts with ".?AV"
  - CompleteObjectLocator (COL): { signature(4), offset(4), cdOffset(4), typeDescriptorRVA(4),
    classHierarchyDescriptorRVA(4), selfRVA(4) } = 24 bytes
  - vtable[-1] = VA of COL, vtable[0..N] = virtual function VAs
"""

import json
import struct
import sys
import os
import mmap
from collections import defaultdict

IMAGE_BASE = 0x140000000

DEV_PATH = os.path.expanduser("~/ai-drive/gamecryptids/tools/old_exes/Project76Profile.exe")
RETAIL_PATH = os.path.expanduser("~/.steam/steam/steamapps/common/Fallout76/Fallout76.exe")
ADDR_LIB_PATH = os.path.expanduser("~/ai-drive/gamecryptids/tools/sfe_scanner/address_library.json")
DEV_SIGS_PATH = os.path.expanduser("~/ai-drive/gamecryptids/tools/sfe_scanner/dev_build_signatures.json")


def parse_pe_sections(mm):
    """Parse PE section headers from mmap'd file."""
    e_lfanew = struct.unpack_from('<I', mm, 0x3C)[0]
    coff = e_lfanew + 4
    nsec = struct.unpack_from('<H', mm, coff + 2)[0]
    optsize = struct.unpack_from('<H', mm, coff + 16)[0]
    secoff = coff + 20 + optsize

    sections = {}
    for i in range(nsec):
        o = secoff + i * 40
        name = mm[o:o+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize, va, rsize, roff = struct.unpack_from('<IIII', mm, o + 8)
        sections[name] = {'va': va, 'vsize': vsize, 'roff': roff, 'rsize': rsize}

    return sections


def find_type_descriptors(mm, sections):
    """Find all RTTI type descriptors."""
    tds = {}  # td_rva -> class_name
    pattern = b'.?AV'

    for sec_name in ['.rdata', '.data']:
        sec = sections.get(sec_name)
        if not sec:
            continue
        start = sec['roff']
        end = start + sec['rsize']
        pos = start
        while True:
            idx = mm.find(pattern, pos, end)
            if idx == -1:
                break
            name_end = mm.find(b'\x00', idx + 4, min(idx + 300, end))
            if name_end == -1:
                pos = idx + 1
                continue
            full = mm[idx:name_end].decode('ascii', errors='replace')
            if '@@' not in full:
                pos = idx + 1
                continue

            class_name = full[4:full.index('@@')]
            # Clean up namespace separators
            class_name = class_name.replace('@', '::').rstrip(':')

            # Skip anonymous namespaces (hash-based names like ?A0x793047ac)
            # These won't match between builds
            if '?A0x' in class_name:
                pos = idx + 1
                continue

            td_rva = sec['va'] + (idx - 16 - sec['roff'])
            tds[td_rva] = class_name
            pos = idx + 1

    return tds


def find_cols(mm, sections, td_set):
    """Find CompleteObjectLocators in .rdata that reference known type descriptors."""
    rdata = sections['.rdata']
    start = rdata['roff']
    end = start + rdata['rsize'] - 24
    rdata_va = rdata['va']

    cols = {}  # col_rva -> (td_rva, offset, class_name)
    pos = start
    while pos < end:
        sig = struct.unpack_from('<I', mm, pos)[0]
        if sig == 1:
            td_rva = struct.unpack_from('<I', mm, pos + 12)[0]
            self_rva = struct.unpack_from('<I', mm, pos + 20)[0]
            col_rva = rdata_va + (pos - start)
            if self_rva == col_rva and td_rva in td_set:
                offset = struct.unpack_from('<I', mm, pos + 4)[0]
                cols[col_rva] = (td_rva, offset, td_set[td_rva])
        pos += 4

    return cols


def find_vtables(mm, sections, cols):
    """Find vtables by locating COL VA pointers in .rdata."""
    rdata = sections['.rdata']
    text = sections['.text']
    start = rdata['roff']
    end = start + rdata['rsize'] - 8
    rdata_va = rdata['va']
    text_va = text['va']
    text_end = text_va + text['vsize']

    col_va_map = {IMAGE_BASE + rva: (rva, info) for rva, info in cols.items()}

    # class_name -> [(offset, vtable_rva, [func_rvas])]
    vtables = defaultdict(list)

    pos = start
    while pos < end:
        val = struct.unpack_from('<Q', mm, pos)[0]
        if val in col_va_map:
            col_rva, (td_rva, offset, class_name) = col_va_map[val]

            # Read vtable entries starting at pos + 8
            func_rvas = []
            epos = pos + 8
            while epos + 8 <= start + rdata['rsize']:
                ev = struct.unpack_from('<Q', mm, epos)[0]
                if ev < IMAGE_BASE:
                    break
                frva = ev - IMAGE_BASE
                if not (text_va <= frva < text_end):
                    break
                func_rvas.append(frva)
                epos += 8

            if func_rvas:
                vtable_rva = rdata_va + (pos + 8 - start)
                vtables[class_name].append((offset, vtable_rva, func_rvas))

        pos += 8

    return vtables


def main():
    print("=" * 70)
    print("RTTI VTable Mapper for Fallout 76")
    print("=" * 70)

    # Load dev build signatures
    print("\nLoading dev build signatures...")
    with open(DEV_SIGS_PATH) as f:
        dev_sigs = json.load(f)

    dev_rva_to_name = {}
    for name, info in dev_sigs.items():
        rva = info['dev_rva']
        if rva not in dev_rva_to_name or len(name) < len(dev_rva_to_name[rva]):
            dev_rva_to_name[rva] = name
    print(f"  {len(dev_sigs)} named functions, {len(dev_rva_to_name)} unique RVAs")

    # Load existing address library
    print("\nLoading existing address library...")
    with open(ADDR_LIB_PATH) as f:
        addr_lib = json.load(f)
    existing_count = len(addr_lib)
    print(f"  {existing_count} existing entries")

    existing_dev_rvas = {info['dev_rva'] for info in addr_lib.values()}
    existing_retail_rvas = {info['retail_rva'] for info in addr_lib.values()}
    existing_names = set(addr_lib.keys())

    # Process dev build
    print("\nProcessing dev build...")
    with open(DEV_PATH, 'rb') as f:
        dev_mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        dev_sections = parse_pe_sections(dev_mm)
        print(f"  .text: 0x{dev_sections['.text']['va']:X} size 0x{dev_sections['.text']['vsize']:X}")
        print(f"  .rdata: 0x{dev_sections['.rdata']['va']:X} size 0x{dev_sections['.rdata']['vsize']:X}")

        dev_tds = find_type_descriptors(dev_mm, dev_sections)
        print(f"  Type descriptors: {len(dev_tds)}")
        dev_cols = find_cols(dev_mm, dev_sections, dev_tds)
        print(f"  COLs: {len(dev_cols)}")
        dev_vtables = find_vtables(dev_mm, dev_sections, dev_cols)
        total_vt = sum(len(v) for v in dev_vtables.values())
        total_entries = sum(len(e) for vts in dev_vtables.values() for _, _, e in vts)
        print(f"  Vtables: {total_vt} across {len(dev_vtables)} classes ({total_entries} entries)")
        dev_mm.close()

    # Process retail build
    print("\nProcessing retail build...")
    with open(RETAIL_PATH, 'rb') as f:
        retail_mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        retail_sections = parse_pe_sections(retail_mm)
        print(f"  .text: 0x{retail_sections['.text']['va']:X} size 0x{retail_sections['.text']['vsize']:X}")
        print(f"  .rdata: 0x{retail_sections['.rdata']['va']:X} size 0x{retail_sections['.rdata']['vsize']:X}")

        retail_tds = find_type_descriptors(retail_mm, retail_sections)
        print(f"  Type descriptors: {len(retail_tds)}")
        retail_cols = find_cols(retail_mm, retail_sections, retail_tds)
        print(f"  COLs: {len(retail_cols)}")
        retail_vtables = find_vtables(retail_mm, retail_sections, retail_cols)
        total_vt = sum(len(v) for v in retail_vtables.values())
        total_entries = sum(len(e) for vts in retail_vtables.values() for _, _, e in vts)
        print(f"  Vtables: {total_vt} across {len(retail_vtables)} classes ({total_entries} entries)")
        retail_mm.close()

    # Cross-reference
    print("\n" + "=" * 70)
    print("Cross-referencing vtables...")
    print("=" * 70)

    common_classes = set(dev_vtables.keys()) & set(retail_vtables.keys())
    print(f"  Common classes (excluding anonymous namespaces): {len(common_classes)}")

    new_matches = {}
    stats = defaultdict(int)
    per_class_new = defaultdict(int)

    # Priority classes get named entries (vfunc_N format)
    # All classes with dev signatures get checked for named function matches
    priority_classes = {
        'Actor', 'TESObjectREFR', 'TESForm', 'PlayerCharacter',
        'TESObjectCELL', 'AIProcess', 'ActiveEffect', 'BGSInventoryItem',
        'ExtraDataList', 'TESQuest', 'NiNode', 'BSFadeNode',
        'TESWorldSpace', 'Character', 'TESNPC', 'TESActorBase',
        'ActorValueOwner', 'MagicTarget', 'BGSKeyword', 'TESBoundObject',
        'TESObject', 'AlchemyItem', 'TESAmmo', 'TESObjectWEAP',
        'TESObjectARMO', 'SpellItem', 'EffectSetting', 'EnchantmentItem',
        'BGSLocation', 'TESPackage', 'BSInputEventUser',
        'bhkWorld', 'hkpWorld', 'TESEffectShader', 'BGSPerk',
        'TESGlobal', 'TESObjectSTAT', 'TESObjectMISC', 'TESObjectBOOK',
        'TESKey', 'TESObjectDOOR', 'TESObjectLIGH', 'TESFlora',
        'TESFurniture', 'TESObjectACTI', 'TESObjectCONT', 'TESTopic',
        'TESTopicInfo', 'BGSScene', 'BGSStoryManagerBranchNode',
        'BGSStoryManagerQuestNode', 'BGSStoryManagerEventNode',
        'TESObjectLAND', 'TESWaterForm', 'NavMesh', 'BSGeometry',
        'NiAVObject', 'NiObjectNET', 'NiObject', 'BSTriShape',
        'hkpRigidBody', 'hkpEntity', 'hkpWorldObject',
        'TESCondition', 'TESRace', 'TESClass', 'TESFaction',
        'TESCombatStyle', 'BGSEncounterZone', 'BGSMusicType',
        'TESImageSpace', 'TESWeather', 'TESClimate', 'TESRegion',
        'BGSMessage', 'BGSTextureSet', 'TESSound', 'BGSSoundDescriptorForm',
        'BGSProjectile', 'BGSExplosion', 'BGSHazard',
        'BGSConstructibleObject', 'BGSTerminal', 'BGSIdleMarker',
        'TESIdleForm', 'TESLoadScreen', 'BGSCameraShot',
        'InventoryChanges', 'ActorEquipManager', 'BGSDefaultObjectManager',
        'UI', 'IMenu', 'HUDMenu', 'PipboyMenu', 'ContainerMenu',
        'BarterMenu', 'LockpickingMenu', 'FavoritesMenu',
        'ExamineMenu', 'CraftingMenu', 'MapMenu', 'StatsMenu',
        'BSScript::NativeFunction', 'GameScript::HandlePolicy',
    }

    for class_name in sorted(common_classes):
        dev_vts = dev_vtables[class_name]
        retail_vts = retail_vtables[class_name]

        # Build lookup by offset
        dev_by_offset = {}
        for offset, vt_rva, entries in dev_vts:
            if offset not in dev_by_offset:
                dev_by_offset[offset] = (vt_rva, entries)

        retail_by_offset = {}
        for offset, vt_rva, entries in retail_vts:
            if offset not in retail_by_offset:
                retail_by_offset[offset] = (vt_rva, entries)

        common_offsets = set(dev_by_offset.keys()) & set(retail_by_offset.keys())

        # Determine the base class name (strip namespaces for display)
        base_name = class_name.split('::')[-1] if '::' in class_name else class_name
        is_priority = base_name in priority_classes or class_name in priority_classes

        for offset in sorted(common_offsets):
            dev_vt_rva, dev_entries = dev_by_offset[offset]
            retail_vt_rva, retail_entries = retail_by_offset[offset]

            match_len = min(len(dev_entries), len(retail_entries))

            # Sanity check: if vtable sizes differ dramatically, skip
            size_ratio = min(len(dev_entries), len(retail_entries)) / max(len(dev_entries), len(retail_entries))
            if size_ratio < 0.7 and max(len(dev_entries), len(retail_entries)) > 10:
                stats['size_mismatch'] += 1
                continue

            for i in range(match_len):
                dev_func_rva = dev_entries[i]
                retail_func_rva = retail_entries[i]

                # Skip already mapped
                if dev_func_rva in existing_dev_rvas:
                    stats['already_mapped'] += 1
                    continue

                # Check if dev function has a known name
                if dev_func_rva in dev_rva_to_name:
                    func_name = dev_rva_to_name[dev_func_rva]
                    stats['named_found'] += 1
                else:
                    # Generate positional name for priority classes
                    if not is_priority:
                        stats['skipped_non_priority'] += 1
                        continue

                    offset_suffix = f"_base{offset}" if offset > 0 else ""
                    func_name = f"{class_name}::vfunc_{i}{offset_suffix}"
                    stats['generated_name'] += 1

                # Skip duplicate names
                if func_name in existing_names or func_name in new_matches:
                    stats['name_collision'] += 1
                    continue

                # Skip if retail RVA already mapped
                if retail_func_rva in existing_retail_rvas:
                    stats['retail_already_mapped'] += 1
                    continue

                dev_va = IMAGE_BASE + dev_func_rva
                retail_va = IMAGE_BASE + retail_func_rva

                new_matches[func_name] = {
                    'dev_va': dev_va,
                    'dev_rva': dev_func_rva,
                    'retail_rva': retail_func_rva,
                    'retail_va': retail_va,
                    'match_type': 'vtable',
                    'vtable_class': class_name,
                    'vtable_index': i,
                }
                per_class_new[class_name] += 1
                stats['new_matches'] += 1

    # Results
    print(f"\nStats:")
    for k, v in sorted(stats.items()):
        print(f"  {k}: {v}")

    print(f"\nNew matches: {len(new_matches)}")

    if per_class_new:
        sorted_classes = sorted(per_class_new.items(), key=lambda x: -x[1])
        print(f"\nTop classes by new matches ({len(per_class_new)} classes):")
        for cls, count in sorted_classes[:60]:
            print(f"  {cls}: {count}")

    if new_matches:
        # Show named matches (from dev_sigs, not generated)
        named_from_sigs = {k: v for k, v in new_matches.items() if '::vfunc_' not in k}
        generated = {k: v for k, v in new_matches.items() if '::vfunc_' in k}

        if named_from_sigs:
            print(f"\nNamed matches from dev signatures ({len(named_from_sigs)}):")
            for name, info in sorted(named_from_sigs.items()):
                print(f"  {name}")
                print(f"    dev=0x{info['dev_rva']:X} retail=0x{info['retail_rva']:X}")

        print(f"\nGenerated vfunc names: {len(generated)}")
        if generated:
            print("Sample generated matches (first 30):")
            for i, (name, info) in enumerate(sorted(generated.items())):
                if i >= 30:
                    print("  ...")
                    break
                print(f"  {name}: dev=0x{info['dev_rva']:X} retail=0x{info['retail_rva']:X}")

        # Merge and save
        addr_lib.update(new_matches)
        print(f"\nAddress library: {existing_count} -> {len(addr_lib)} (+{len(new_matches)})")

        with open(ADDR_LIB_PATH, 'w') as f:
            json.dump(addr_lib, f, indent=2)
        print(f"Saved to {ADDR_LIB_PATH}")

        vtable_path = ADDR_LIB_PATH.replace('.json', '_vtable_matches.json')
        with open(vtable_path, 'w') as f:
            json.dump(new_matches, f, indent=2)
        print(f"VTable matches saved to {vtable_path}")
    else:
        print("\nNo new matches found.")

    # Summary of all vtable classes found
    print(f"\n\nSummary:")
    print(f"  Dev classes (non-anonymous): {len(dev_vtables)}")
    print(f"  Retail classes (non-anonymous): {len(retail_vtables)}")
    print(f"  Common classes: {len(common_classes)}")
    print(f"  Priority classes found in both: {len([c for c in common_classes if c.split('::')[-1] in priority_classes or c in priority_classes])}")


if __name__ == '__main__':
    main()
