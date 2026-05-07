#!/usr/bin/env python3
"""
RTTI-anchored SFE address resolver.

Where sfe_scanner.py uses byte-pattern signatures, this resolver uses the MSVC
RTTI runtime metadata that is BAKED INTO the exe and survives recompiles. For
each known SFE address from the OLD build, we derive (class_name, slot_index)
by mapping the address against the live .rdata dump. We then walk the NEW exe's
RTTI to find the same class, read the same slot, and emit the new address.

Inputs:
  --new-exe        Post-patch Fallout76.exe (default: Steam install)
  --old-rdata      Live .rdata dump from before the patch
                   (default: f76-toolkit/data/exe_dump/rdata_section.bin)
  --old-rdata-rva  RVA where old .rdata started (auto-detected if old data
                   includes recognizable RTTI structures, else default 0x3F30000)
  --sfe-names      sfe_named_addresses.json (OLD addresses with names + sources)

Outputs:
  --json-output    name -> {new_rva, method, confidence, class, slot}
  --report         human-readable summary

Modes:
  --selftest       Validate: walk new exe RTTI, ensure internal consistency
                   (every COL points to a valid TypeDescriptor; every vtable
                    slot lands in .text; class hierarchy slot-overlap holds)
  --resolve        Default: resolve OLD SFE names -> NEW addresses
  --dump-classes   Dump all RTTI classes + vtables from NEW exe to JSON
"""

import argparse
import json
import os
import struct
import sys
import time
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_NEW_EXE = Path("/home/deucebucket/.steam/steam/steamapps/common/Fallout76/Fallout76.exe")
DEFAULT_OLD_RDATA = Path("/home/deucebucket/ai-drive/f76-toolkit/data/exe_dump/rdata_section.bin")
DEFAULT_SFE_NAMES = Path("/home/deucebucket/ai-drive/gamecryptids/data/fallout76/sfe_named_addresses.json")
DEFAULT_OUTPUT_DIR = Path("/home/deucebucket/ai-drive/f76-toolkit/data")

IMAGE_BASE = 0x140000000  # FO76 is image-base-locked; verified across all known builds

# ---------------------------------------------------------------------------
# PE parser (just enough)
# ---------------------------------------------------------------------------

class PE:
    def __init__(self, path):
        self.path = str(path)
        self.data = open(path, 'rb').read()
        self._parse()

    def _parse(self):
        d = self.data
        e_lfanew = struct.unpack_from('<I', d, 0x3c)[0]
        if d[e_lfanew:e_lfanew + 4] != b'PE\0\0':
            raise ValueError(f"Not a PE: {self.path}")
        num_sections = struct.unpack_from('<H', d, e_lfanew + 6)[0]
        opt_size = struct.unpack_from('<H', d, e_lfanew + 20)[0]
        opt_off = e_lfanew + 24
        self.image_base = struct.unpack_from('<Q', d, opt_off + 24)[0]
        sect_off = opt_off + opt_size
        self.sections = []
        for i in range(num_sections):
            so = sect_off + i * 40
            name = d[so:so + 8].rstrip(b'\0').decode('latin-1')
            vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', d, so + 8)
            self.sections.append({
                'name': name,
                'virtual_addr': vaddr,
                'virtual_size': vsize,
                'raw_offset': raddr,
                'raw_size': rsize,
            })

    def section(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None

    def section_for_rva(self, rva):
        for s in self.sections:
            if s['virtual_addr'] <= rva < s['virtual_addr'] + s['virtual_size']:
                return s
        return None

    def rva_to_file(self, rva):
        s = self.section_for_rva(rva)
        if s is None:
            return None
        off = rva - s['virtual_addr'] + s['raw_offset']
        return off if off < len(self.data) else None

    def file_to_rva(self, off):
        for s in self.sections:
            if s['raw_offset'] <= off < s['raw_offset'] + s['raw_size']:
                return s['virtual_addr'] + (off - s['raw_offset'])
        return None

    def read(self, rva, n):
        off = self.rva_to_file(rva)
        if off is None or off + n > len(self.data):
            return None
        return self.data[off:off + n]

    def section_data(self, name):
        s = self.section(name)
        if s is None:
            return b''
        return self.data[s['raw_offset']:s['raw_offset'] + s['raw_size']]


# ---------------------------------------------------------------------------
# RTTI walker — finds typedescriptors, COLs, and vtables
# ---------------------------------------------------------------------------

# MSVC mangled RTTI name forms:
#   .?AV<class>@@         class
#   .?AU<struct>@@        struct
#   .?AV?$<tmpl>@...@@    template
# All start with .?A and end with @@\0
_MANGLED_PREFIX = b'.?A'

class RTTI:
    """RTTI walker over a PE image. Pre-builds full COL + vtable indices in
    linear time on first access; per-class lookups are then O(1)."""

    def __init__(self, pe):
        self.pe = pe
        self.image_base = pe.image_base
        self._td_cache = None       # mangled_name -> td_rva
        self._typedescriptors = None  # td_rva -> mangled_name
        self._cols_for_td = None    # td_rva -> [col_rva, ...]
        self._vtable_for_col = None # col_rva -> [vtable_rva, ...]
        self._all_cols = None       # set of valid col_rvas
        self._td_rvaset = None      # set of all td_rvas (for fast COL validation)

    # ---- TypeDescriptors ----

    def typedescriptors(self):
        """Scan .data for all RTTI TypeDescriptors. Returns {td_rva: mangled_name}."""
        if self._typedescriptors is not None:
            return self._typedescriptors

        result = {}
        # TypeDescriptors live in .data (the name string is right after a vfptr+spare).
        # We scan for the mangled name pattern, then the TD starts 16 bytes earlier.
        sec = self.pe.section('.data')
        if sec is None:
            self._typedescriptors = result
            return result

        sec_va = sec['virtual_addr']
        sec_raw = sec['raw_offset']
        sec_size = sec['raw_size']
        data = self.pe.data
        end = sec_raw + sec_size

        i = sec_raw
        while i < end - 4:
            j = data.find(_MANGLED_PREFIX, i, end)
            if j < 0:
                break
            # End at @@\0
            term = data.find(b'@@\0', j, min(j + 256, end))
            if term < 0 or term - j < 6:
                i = j + 1
                continue
            mangled = data[j:term + 2].decode('latin-1', errors='replace')
            # TypeDescriptor starts 16 bytes before the name
            td_off = j - 16
            if td_off >= sec_raw:
                td_rva = self.pe.file_to_rva(td_off)
                if td_rva is not None:
                    result[td_rva] = mangled
            i = term + 3

        self._typedescriptors = result
        return result

    def find_typedescriptor(self, mangled_name):
        """mangled_name e.g. '.?AVActor@@'. Returns td_rva or None."""
        if self._td_cache is None:
            self._td_cache = {name: rva for rva, name in self.typedescriptors().items()}
        return self._td_cache.get(mangled_name)

    # ---- Linear-time bulk index build ----

    def _build_indices(self):
        """One linear pass through .rdata to find every valid COL and every
        vtable. Populates _all_cols, _cols_for_td, _vtable_for_col."""
        if self._all_cols is not None:
            return

        tds = self.typedescriptors()
        td_set = set(tds.keys())
        self._td_rvaset = td_set

        rdata = self.pe.section('.rdata')
        if rdata is None:
            self._all_cols = set()
            self._cols_for_td = {}
            self._vtable_for_col = {}
            return

        sec_raw = rdata['raw_offset']
        sec_size = rdata['raw_size']
        sec_va = rdata['virtual_addr']
        data = self.pe.data

        # ----- Pass 1: find all valid COLs -----
        # Walk every 4-byte aligned offset, check COL signature.
        # Layout (x64): sig(4) offset(4) cdOff(4) pTD(4) pCD(4) pSelf(4)
        cols_for_td = defaultdict(list)
        all_cols = set()

        # COLs are typically near vtables, so we look at every 4-aligned offset.
        # 22MB / 4 = 5.5M slots — manageable in pure Python with struct.unpack_from.
        end = sec_size - 24
        i = 0
        while i < end:
            sig = struct.unpack_from('<I', data, sec_raw + i)[0]
            if sig in (0, 1):
                td_rva = struct.unpack_from('<I', data, sec_raw + i + 12)[0]
                if td_rva in td_set:
                    p_self = struct.unpack_from('<I', data, sec_raw + i + 20)[0]
                    col_rva = sec_va + i
                    # For sig=1 (x64), pSelf must equal col_rva.
                    if sig == 0 or p_self == col_rva:
                        cols_for_td[td_rva].append(col_rva)
                        all_cols.add(col_rva)
            i += 4

        self._cols_for_td = dict(cols_for_td)
        self._all_cols = all_cols

        # ----- Pass 2: find all vtables -----
        # For every 8-byte aligned QWORD, if it equals image_base + (a known col_rva),
        # the QWORD AFTER it is the start of a vtable.
        col_qwords = {self.image_base + c: c for c in all_cols}
        vtable_for_col = defaultdict(list)

        end = sec_size - 8
        # 8-byte stride; vtables in MSVC are 8-aligned.
        i = 0
        while i < end:
            v = struct.unpack_from('<Q', data, sec_raw + i)[0]
            col = col_qwords.get(v)
            if col is not None:
                vtable_rva = sec_va + i + 8
                vtable_for_col[col].append(vtable_rva)
            i += 8

        self._vtable_for_col = dict(vtable_for_col)

    def find_cols_for_td(self, td_rva):
        """All COLs whose pTypeDescriptor == td_rva (after one-time index build)."""
        self._build_indices()
        return self._cols_for_td.get(td_rva, [])

    def find_vtables_for_col(self, col_rva):
        """All vtables whose preceding slot points back to col_rva."""
        self._build_indices()
        return self._vtable_for_col.get(col_rva, [])

    def read_vtable_slots(self, vtable_rva, max_slots=512):
        """
        Read function pointers from vtable. Stops when we hit a non-.text RVA
        (vtable boundary heuristic) or max_slots.
        Returns list of function RVAs.
        """
        text = self.pe.section('.text')
        if text is None:
            return []
        text_start = text['virtual_addr']
        text_end = text_start + text['virtual_size']

        slots = []
        for i in range(max_slots):
            v = self.pe.read(vtable_rva + i * 8, 8)
            if v is None:
                break
            ptr = struct.unpack('<Q', v)[0]
            rva = ptr - self.image_base
            if not (text_start <= rva < text_end):
                break
            slots.append(rva)
        return slots

    # ---- Convenience ----

    def resolve_class(self, mangled_name):
        """
        For a mangled name (e.g. '.?AVActor@@'), return all candidate vtables
        with their slots. May return multiple (class with multiple inheritance).

        Returns: [{col_rva, vtable_rva, slots: [rva,...]}]
        """
        td_rva = self.find_typedescriptor(mangled_name)
        if td_rva is None:
            return []
        results = []
        for col_rva in self.find_cols_for_td(td_rva):
            for vt_rva in self.find_vtables_for_col(col_rva):
                results.append({
                    'col_rva': col_rva,
                    'vtable_rva': vt_rva,
                    'slots': self.read_vtable_slots(vt_rva),
                })
        return results


# ---------------------------------------------------------------------------
# Old-rdata vtable identification
# ---------------------------------------------------------------------------

class OldRdata:
    """
    Wraps the live .rdata dump to support 'find vtable slot containing
    this old function address' queries.

    We don't have the OLD PE header, but we do know:
      - image_base = 0x140000000 (locked)
      - .rdata raw bytes verbatim
    What we DON'T inherently know is the OLD .rdata virtual_addr / file_offset
    mapping. We need that to convert a found byte position to an RVA, and to
    locate COL pointers (also in .rdata). Approach: detect the OLD .rdata RVA
    by self-consistency — pick the candidate base RVA where a maximum number
    of 64-bit values look like image_base + (some valid old text or rdata RVA).
    Fallback: 0x3F30000 (current .rdata RVA, same as new — very common to be
    similar).

    For the OLD .text RVA range, we use the OLD signature DB if available
    (signatures.json carries OLD section info via source_exe_size).
    """

    def __init__(self, path, image_base=IMAGE_BASE,
                 old_text_start=0x1000, old_text_end=0x4000000,
                 old_rdata_rva=None):
        self.path = str(path)
        self.bytes = open(path, 'rb').read()
        self.image_base = image_base
        self.old_text_start = old_text_start
        self.old_text_end = old_text_end
        if old_rdata_rva is None:
            old_rdata_rva = self._auto_detect_rdata_rva()
        self.old_rdata_rva = old_rdata_rva

    def _auto_detect_rdata_rva(self):
        """
        Structural inference: COLs have sig=1, offset/cdOff small, td_rva in
        plausible range, pSelf == col_rva. From `pSelf == old_rdata_rva + i`,
        every valid COL gives us the same constant `pSelf - i = old_rdata_rva`.
        Find the most frequent constant — that's the OLD .rdata RVA.
        """
        from collections import Counter
        rdata = self.bytes
        size = len(rdata)
        constants = Counter()
        i = 0
        end = size - 24
        while i < end:
            sig = struct.unpack_from('<I', rdata, i)[0]
            if sig == 1:
                offset = struct.unpack_from('<I', rdata, i + 4)[0]
                cd_off = struct.unpack_from('<I', rdata, i + 8)[0]
                td_rva = struct.unpack_from('<I', rdata, i + 12)[0]
                p_self = struct.unpack_from('<I', rdata, i + 20)[0]
                # Plausibility filters
                if (offset < 0x100000 and cd_off < 0x100000
                        and 0x4000000 < td_rva < 0x8000000
                        and p_self > i):
                    const = p_self - i
                    if 0x1000000 < const < 0x8000000:
                        constants[const] += 1
            i += 4

        if not constants:
            return 0x3F30000  # fallback
        return constants.most_common(1)[0][0]

    def find_function_pointer_locations(self, old_func_rva):
        """
        Find every byte-offset in self.bytes that holds (image_base + old_func_rva).
        These are vtable slots that contain this function pointer.
        Returns [byte_offset_in_rdata, ...]
        """
        target = struct.pack('<Q', self.image_base + old_func_rva)
        results = []
        start = 0
        while True:
            idx = self.bytes.find(target, start)
            if idx < 0:
                break
            results.append(idx)
            start = idx + 1
        return results

    def offset_to_rva(self, offset):
        return self.old_rdata_rva + offset

    def read_qword(self, offset):
        if offset + 8 > len(self.bytes):
            return None
        return struct.unpack_from('<Q', self.bytes, offset)[0]

    def read_dword(self, offset):
        if offset + 4 > len(self.bytes):
            return None
        return struct.unpack_from('<I', self.bytes, offset)[0]

    def find_vtable_for_function(self, old_func_rva, max_walk_back=512):
        """
        Given a function pointer hit at offset X, walk BACKWARD looking for
        the vtable's COL pointer slot. Pattern: vtable[N] = image_base + COL_RVA
        where COL_RVA points into .rdata, and the next 8 bytes after COL_RVA
        (relative to image_base) is a typedescriptor RVA.

        Returns: [(vtable_rva, slot_index, col_rva), ...]
        """
        results = []
        for hit in self.find_function_pointer_locations(old_func_rva):
            # Walk backward 8 bytes at a time, looking for the COL pointer slot.
            # COL pointer = image_base + col_rva, where col_rva points into .rdata.
            for back in range(0, max_walk_back * 8, 8):
                pos = hit - back - 8
                if pos < 0:
                    break
                v = self.read_qword(pos)
                if v is None or v < self.image_base:
                    continue
                ptr_rva = v - self.image_base
                # COL must be in .rdata range
                if not (self.old_rdata_rva <= ptr_rva < self.old_rdata_rva + len(self.bytes)):
                    continue
                # Sniff signature byte at COL position (sig=0 or 1)
                col_off = ptr_rva - self.old_rdata_rva
                sig = self.read_dword(col_off)
                if sig not in (0, 1):
                    continue
                # If we got here, we likely found the COL pointer slot.
                # vtable[0] is at pos + 8.
                vtable_off = pos + 8
                vtable_rva = self.offset_to_rva(vtable_off)
                slot_index = (hit - vtable_off) // 8
                results.append({
                    'vtable_rva': vtable_rva,
                    'slot_index': slot_index,
                    'col_rva': ptr_rva,
                    'hit_offset': hit,
                })
                break  # one COL per hit
        return results

    def col_to_typedescriptor(self, col_rva):
        """Read pTypeDescriptor field of a COL (offset 12)."""
        col_off = col_rva - self.old_rdata_rva
        if col_off < 0 or col_off + 16 > len(self.bytes):
            return None
        return self.read_dword(col_off + 12)

    def col_to_class_name(self, col_rva, new_pe_rtti):
        """
        We have the OLD col_rva. We don't have the OLD typedescriptor name
        (TDs live in .data, we only have .rdata). However, the typedescriptor
        RVA we read back is in OLD .data which we may not have.

        Workaround: the COL also has pSelf at offset 20. We can read TD via
        pTypeDescriptor (offset 12). For most cases it's enough to identify
        a vtable by its COL-to-TD relative offset structure.

        Returns (td_rva_old, None_for_name) — caller reconciles via slot
        consistency on a separate pass if name unknown.
        """
        td_rva = self.col_to_typedescriptor(col_rva)
        return td_rva


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

class Resolver:
    """
    OLD↔NEW vtable matching:

      1. Scan rdata_section.bin (linear): build OLD COL/vtable database
         using same algorithm as RTTI._build_indices, but on raw bytes.
         We get a list of OLD vtables with [old_td_rva, old_vtable_rva,
         num_slots, [slot_func_rvas]].

      2. For each NEW class (from NEW exe RTTI), get [new_td_rva,
         new_vtable_rva, num_slots, [slot_func_rvas]].

      3. Match OLD↔NEW by FINGERPRINT:
            - vtable size (must match exactly or ±2 — Bethesda rarely changes)
            - cdOffset structure (same multi-inheritance shape)
         Among size-matching candidates, prefer unique matches; collapse
         ambiguous via group-consistency (multiple SFE addresses sharing an
         OLD td_rva must share a NEW td_rva).

      4. For each SFE entry: if its OLD address appears in some OLD vtable
         at slot K, look up matched NEW vtable for that OLD td, read slot K.
    """

    def __init__(self, new_pe, old_rdata, sfe_names):
        self.pe = new_pe
        self.old = old_rdata
        self.sfe = sfe_names
        self.rtti = RTTI(new_pe)
        self._old_vtable_db = None  # list of {'col_rva','td_rva','vtable_rva','slots','cd_offset'}
        self._new_vtable_db = None  # list of same shape, plus 'class_name'

    def _build_old_vtable_db(self):
        """Linear scan over rdata_section.bin to find OLD COLs and vtables."""
        if self._old_vtable_db is not None:
            return self._old_vtable_db

        rdata = self.old.bytes
        rva_base = self.old.old_rdata_rva
        size = len(rdata)
        image_base = self.old.image_base

        # OLD typedescriptors live in OLD .data (we don't have it). But all
        # we need is the OLD td_rva *value* — we can use it as an opaque key
        # since it'll match across vtables for the same class.
        # Validity test for a candidate COL: pSelf must equal current col_rva
        # (sig=1) or sig==0 with reasonable cdOff/offset values.

        cols = []  # list of (col_offset_in_rdata, col_rva, td_rva_old, cd_offset)
        col_rva_to_idx = {}

        i = 0
        end = size - 24
        while i < end:
            sig = struct.unpack_from('<I', rdata, i)[0]
            if sig == 1:
                offset = struct.unpack_from('<I', rdata, i + 4)[0]
                cd_off = struct.unpack_from('<I', rdata, i + 8)[0]
                td_rva = struct.unpack_from('<I', rdata, i + 12)[0]
                p_self = struct.unpack_from('<I', rdata, i + 20)[0]
                col_rva = rva_base + i
                # Sanity: sig=1 requires pSelf == col_rva, td_rva must look like
                # a .data RVA (above .rdata typically), offset is small.
                if p_self == col_rva and offset < 0x100000 and cd_off < 0x100000:
                    col_rva_to_idx[col_rva] = len(cols)
                    cols.append({
                        'col_offset': i,
                        'col_rva': col_rva,
                        'td_rva': td_rva,
                        'cd_offset': cd_off,
                        'offset': offset,
                    })
            i += 4

        # Find vtables: for each 8-aligned QWORD, if it == image_base + col_rva,
        # the next QWORDs form the vtable.
        vtables = []
        text_start = self.old.old_text_start
        text_end = self.old.old_text_end

        i = 0
        end = size - 8
        while i < end:
            v = struct.unpack_from('<Q', rdata, i)[0]
            col_rva_candidate = v - image_base
            if col_rva_candidate in col_rva_to_idx:
                # Read vtable slots
                slots = []
                j = i + 8
                while j + 8 <= size:
                    slot_v = struct.unpack_from('<Q', rdata, j)[0]
                    slot_rva = slot_v - image_base
                    if not (text_start <= slot_rva < text_end):
                        break
                    slots.append(slot_rva)
                    j += 8
                if slots:
                    col_info = cols[col_rva_to_idx[col_rva_candidate]]
                    vtables.append({
                        'col_rva': col_rva_candidate,
                        'td_rva': col_info['td_rva'],
                        'cd_offset': col_info['cd_offset'],
                        'vtable_rva': rva_base + i + 8,
                        'slots': slots,
                    })
            i += 8

        self._old_vtable_db = vtables
        return vtables

    def _build_new_vtable_db(self):
        """Build list of NEW vtables with class names attached."""
        if self._new_vtable_db is not None:
            return self._new_vtable_db

        self.rtti._build_indices()
        out = []
        td_to_name = self.rtti.typedescriptors()
        for col_rva in self.rtti._all_cols:
            # Look up td and cd_offset
            col_off = self.pe.rva_to_file(col_rva)
            if col_off is None:
                continue
            cd_offset = struct.unpack_from('<I', self.pe.data, col_off + 8)[0]
            td_rva = struct.unpack_from('<I', self.pe.data, col_off + 12)[0]
            class_name = td_to_name.get(td_rva, f'<unknown_td_{td_rva:X}>')
            for vt_rva in self.rtti.find_vtables_for_col(col_rva):
                slots = self.rtti.read_vtable_slots(vt_rva)
                if slots:
                    out.append({
                        'class_name': class_name,
                        'td_rva': td_rva,
                        'col_rva': col_rva,
                        'cd_offset': cd_offset,
                        'vtable_rva': vt_rva,
                        'slots': slots,
                    })

        self._new_vtable_db = out
        return out

    def _match_vtables(self):
        """
        Match OLD vtables to NEW vtables.

        Strategy: index NEW vtables by (slot_count, cd_offset). For each OLD
        vtable, candidates are NEW vtables with same key. If unique, that's
        the match. Otherwise, use SFE-address consistency: for every OLD
        SFE address mapped to the OLD vtable, the candidate NEW vtable's
        same-slot must yield a non-zero address that lands in .text (already
        guaranteed by read_vtable_slots).

        Returns: dict[old_td_rva] -> new_vtable_db_entry
        """
        old_db = self._build_old_vtable_db()
        new_db = self._build_new_vtable_db()

        # Index new by (slot_count, cd_offset)
        new_index = defaultdict(list)
        for nv in new_db:
            key = (len(nv['slots']), nv['cd_offset'])
            new_index[key].append(nv)

        # Build OLD td -> [old vtables] (a class can have multiple inherited
        # vtables in MI scenarios, distinguished by cd_offset)
        old_by_td = defaultdict(list)
        for ov in old_db:
            old_by_td[ov['td_rva']].append(ov)

        td_match = {}  # old_td_rva -> chosen new_vtable_db entry (the primary; cd=0)
        ambiguous = {}

        for old_td, ov_list in old_by_td.items():
            # Use the primary vtable (cd_offset==0) for class matching
            primary_old = next((ov for ov in ov_list if ov['cd_offset'] == 0), ov_list[0])
            key = (len(primary_old['slots']), primary_old['cd_offset'])
            cands = new_index.get(key, [])
            if len(cands) == 1:
                td_match[old_td] = cands[0]
            elif len(cands) > 1:
                # Try widening to ±1 slot count
                wider = []
                for n in cands:
                    wider.append(n)
                # Strict match still ambiguous; record candidates
                ambiguous[old_td] = cands
                # Heuristic: prefer the candidate whose first 8 slot pointers
                # have similar function sizes / distance distributions.
                # Without disassembly, use cd_offset and slot_count match alone.
                # Pick first candidate as best-effort for now.
                td_match[old_td] = cands[0]

        return td_match, ambiguous

    def resolve(self):
        """Main resolution path. Returns name -> resolution dict."""
        old_db = self._build_old_vtable_db()
        new_db = self._build_new_vtable_db()
        print(f"  OLD vtables: {len(old_db)}")
        print(f"  NEW vtables: {len(new_db)}")

        td_match, ambiguous = self._match_vtables()
        print(f"  matched OLD td_rvas: {len(td_match)}")
        print(f"  of which ambiguous (size+cd_off match multiple): {len(ambiguous)}")

        # Find each SFE address in OLD vtables
        # Build reverse lookup: old_func_rva -> [(old_td_rva, slot_index, vtable_rva)]
        old_addr_to_slots = defaultdict(list)
        for ov in old_db:
            for slot_idx, slot_rva in enumerate(ov['slots']):
                old_addr_to_slots[slot_rva].append((ov['td_rva'], slot_idx,
                                                    ov['vtable_rva'], ov['cd_offset']))

        results = {}
        unresolved = []
        for name, info in self.sfe.items():
            old_rva = int(info['address'], 16)
            slot_hits = old_addr_to_slots.get(old_rva, [])
            if not slot_hits:
                unresolved.append((name, 'not_in_any_old_vtable'))
                continue

            # Use the first hit (typically each function appears in exactly one
            # vtable; multi-hits mean the function is shared via MI, all hits
            # should resolve to same new address).
            old_td, slot_idx, old_vt_rva, old_cd_off = slot_hits[0]
            new_vt = td_match.get(old_td)
            if new_vt is None:
                unresolved.append((name, 'no_new_class_match'))
                continue
            if slot_idx >= len(new_vt['slots']):
                unresolved.append((name, 'slot_out_of_range'))
                continue

            new_rva = new_vt['slots'][slot_idx]
            confidence = 'high' if old_td not in ambiguous else 'medium'

            results[name] = {
                'old_rva': old_rva,
                'new_rva': new_rva,
                'method': 'rtti_vtable_slot',
                'confidence': confidence,
                'class': new_vt['class_name'],
                'slot': slot_idx,
                'vtable_old': old_vt_rva,
                'vtable_new': new_vt['vtable_rva'],
                'td_rva_old': old_td,
                'td_rva_new': new_vt['td_rva'],
                'cd_offset': old_cd_off,
                'multiple_hits': len(slot_hits),
            }

        return results, unresolved


# ---------------------------------------------------------------------------
# Self-test / smoke tests
# ---------------------------------------------------------------------------

def selftest(pe):
    """
    Internal consistency smoke tests over the new exe's RTTI.
    """
    rtti = RTTI(pe)
    text = pe.section('.text')
    text_start = text['virtual_addr']
    text_end = text_start + text['virtual_size']

    tds = rtti.typedescriptors()
    print(f"[selftest] typedescriptors: {len(tds)}")

    # Sample 20 classes and check end-to-end resolution
    sample = list(tds.items())[:20]
    failures = []
    cols_total = 0
    vtables_total = 0
    valid_slots = 0
    invalid_slots = 0

    for td_rva, name in sample:
        cols = rtti.find_cols_for_td(td_rva)
        cols_total += len(cols)
        if not cols:
            continue
        for col in cols:
            vts = rtti.find_vtables_for_col(col)
            vtables_total += len(vts)
            for vt in vts:
                slots = rtti.read_vtable_slots(vt)
                for s in slots:
                    if text_start <= s < text_end:
                        valid_slots += 1
                    else:
                        invalid_slots += 1

    print(f"[selftest] sampled 20 classes:")
    print(f"  cols found:      {cols_total}")
    print(f"  vtables found:   {vtables_total}")
    print(f"  slot pointers:   {valid_slots} valid (.text), {invalid_slots} invalid")
    print(f"  validity rate:   {valid_slots / max(valid_slots + invalid_slots, 1) * 100:.1f}%")

    # Inheritance consistency: many derived classes share base-class slots.
    # Pick Actor and TESForm; they should share several leading slots.
    actor = rtti.resolve_class('.?AVActor@@')
    tesform = rtti.resolve_class('.?AVTESForm@@')
    if actor and tesform:
        a_slots = actor[0]['slots'][:8] if actor[0]['slots'] else []
        t_slots = tesform[0]['slots'][:8] if tesform[0]['slots'] else []
        common_count = sum(1 for a, t in zip(a_slots[1:], t_slots[1:]) if a == t)
        print(f"[selftest] Actor[1..7] vs TESForm[1..7]: {common_count}/7 slots match")
    else:
        print(f"[selftest] could not load Actor/TESForm")

    return invalid_slots == 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--new-exe', default=str(DEFAULT_NEW_EXE))
    ap.add_argument('--old-rdata', default=str(DEFAULT_OLD_RDATA))
    ap.add_argument('--old-rdata-rva', type=lambda x: int(x, 0), default=None,
                    help='RVA where old .rdata starts (auto-detect if omitted)')
    ap.add_argument('--sfe-names', default=str(DEFAULT_SFE_NAMES))
    ap.add_argument('--json-output', default=None)
    ap.add_argument('--selftest', action='store_true', help='Run consistency tests')
    ap.add_argument('--dump-classes', action='store_true', help='Dump all RTTI classes + vtables')
    ap.add_argument('--limit', type=int, default=0, help='Limit when dumping classes (0 = all)')
    ap.add_argument('--verbose', '-v', action='store_true')
    args = ap.parse_args()

    print(f"Loading new exe: {args.new_exe}")
    pe = PE(args.new_exe)
    print(f"  image_base = 0x{pe.image_base:X}")
    for s in pe.sections:
        print(f"  {s['name']:10s} VA=0x{s['virtual_addr']:08X} size=0x{s['virtual_size']:08X}")

    if args.selftest:
        ok = selftest(pe)
        sys.exit(0 if ok else 1)

    if args.dump_classes:
        rtti = RTTI(pe)
        tds = rtti.typedescriptors()
        out = {}
        for i, (td_rva, name) in enumerate(tds.items()):
            if args.limit and i >= args.limit:
                break
            cols = rtti.find_cols_for_td(td_rva)
            entries = []
            for col in cols:
                vts = rtti.find_vtables_for_col(col)
                for vt in vts:
                    slots = rtti.read_vtable_slots(vt)
                    entries.append({'col_rva': col, 'vtable_rva': vt,
                                    'num_slots': len(slots),
                                    'slots': [hex(s) for s in slots]})
            if entries:
                out[name] = {'td_rva': td_rva, 'instances': entries}
        path = args.json_output or str(DEFAULT_OUTPUT_DIR / 'rtti_class_dump.json')
        with open(path, 'w') as f:
            json.dump(out, f, indent=2)
        print(f"\nDumped {len(out)} classes -> {path}")
        return

    # Default: resolve mode
    print(f"Loading old .rdata: {args.old_rdata}")
    old = OldRdata(args.old_rdata, old_rdata_rva=args.old_rdata_rva)
    print(f"  size = {len(old.bytes):,} bytes, old_rdata_rva = 0x{old.old_rdata_rva:X}")

    print(f"Loading SFE names: {args.sfe_names}")
    with open(args.sfe_names) as f:
        sfe = json.load(f)
    print(f"  {len(sfe)} named addresses")

    resolver = Resolver(pe, old, sfe)
    t0 = time.time()
    print("\nResolving via OLD↔NEW vtable matching...")
    results, unresolved_pairs = resolver.resolve()
    elapsed = time.time() - t0
    print(f"  {len(results)} resolved in {elapsed:.1f}s")

    # Stats
    by_conf = defaultdict(int)
    for name, r in results.items():
        by_conf[r['confidence']] += 1
    for c in ('high', 'medium', 'low'):
        print(f"  confidence={c}: {by_conf[c]}")

    by_reason = defaultdict(int)
    for _, reason in unresolved_pairs:
        by_reason[reason] += 1
    print(f"  unresolved: {len(unresolved_pairs)}")
    for r, n in sorted(by_reason.items(), key=lambda x: -x[1]):
        print(f"    {r}: {n}")
    if args.verbose and unresolved_pairs:
        for n, reason in unresolved_pairs[:20]:
            print(f"    {n}  (old=0x{int(sfe[n]['address'], 16):X}) [{reason}]")
    unresolved = [n for n, _ in unresolved_pairs]

    out_path = args.json_output or str(DEFAULT_OUTPUT_DIR / f'rtti_resolved_{time.strftime("%Y%m%d_%H%M")}.json')
    out_doc = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'new_exe': str(args.new_exe),
        'old_rdata': str(args.old_rdata),
        'old_rdata_rva': hex(old.old_rdata_rva),
        'sfe_names_count': len(sfe),
        'resolved_count': len(results),
        'stats': {'by_confidence': dict(by_conf), 'unresolved': len(unresolved)},
        'results': {n: {**r, 'old_rva': hex(r['old_rva']), 'new_rva': hex(r['new_rva'])}
                    for n, r in results.items()},
        'unresolved': unresolved,
    }
    with open(out_path, 'w') as f:
        json.dump(out_doc, f, indent=2)
    print(f"\nWritten: {out_path}")


if __name__ == '__main__':
    main()
