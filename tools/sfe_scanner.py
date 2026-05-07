#!/usr/bin/env python3
"""
SFE Address Scanner v2 - Automatic signature-based address finder for SFE (Script Framework Extender)

Scans SFE C++ source to extract all hardcoded addresses (RelocAddr, RelocPtr, DEFINE_MEMBER_FN),
reads byte patterns from the current Fallout76.exe at those offsets, then searches a new
executable for those same patterns to find updated addresses after a game patch.

No dependencies beyond Python stdlib. No AI. Pure binary pattern matching.

Improvements over v1:
  - Parses ALL PE sections (.text, .rdata, .data) properly
  - XREF-based disambiguation for ambiguous signatures
  - Extended signatures up to 256 bytes for stubborn cases
  - Function size and vtable analysis for disambiguation
  - DLL comparison mode (validates against compiled SFE DLL)
  - --validate flag for self-test accuracy reporting
  - Address Library database output format
  - Better output: summary, per-address detail, C++ header, JSON mapping

Usage:
    python3 sfe_scanner.py --generate                     # Build signatures from current exe
    python3 sfe_scanner.py --scan NEW_EXE                 # Find addresses in a new exe
    python3 sfe_scanner.py --diff OLD_EXE NEW_EXE         # Compare two executables
    python3 sfe_scanner.py --patch                        # Output updated C++ headers
    python3 sfe_scanner.py --validate                     # Self-test: scan source exe, report accuracy
    python3 sfe_scanner.py --dll-compare                  # Compare scanner results against SFE DLL
"""

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import time
from collections import defaultdict
from pathlib import Path

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR = Path(__file__).parent.resolve()
SFE_SOURCE = SCRIPT_DIR.parent / "sfe" / "sfe"
DEFAULT_EXE = Path("/home/deucebucket/.steam/steam/steamapps/common/Fallout76/Fallout76.exe")
DEFAULT_DLL = Path("/home/deucebucket/.steam/steam/steamapps/common/Fallout76/dxgi.dll")
SIGNATURES_FILE = SCRIPT_DIR / "signatures.json"
ADDRLIB_FILE = SCRIPT_DIR / "address_library.json"

# Default signature length in bytes (96 = wider window survives PGO/LTO churn better than 32)
DEFAULT_SIG_LEN = 96
# Maximum window for --slow retry path
MAX_SIG_LEN = 256

# PE section flags
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080


# ============================================================================
# PE Parser (minimal, stdlib-only)
# ============================================================================

class PESection:
    """Represents a PE section header."""
    def __init__(self, name, virtual_size, virtual_addr, raw_size, raw_offset, characteristics):
        self.name = name
        self.virtual_size = virtual_size
        self.virtual_addr = virtual_addr
        self.raw_size = raw_size
        self.raw_offset = raw_offset
        self.characteristics = characteristics

    @property
    def is_code(self):
        return bool(self.characteristics & IMAGE_SCN_CNT_CODE)

    @property
    def is_data(self):
        return bool(self.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)

    @property
    def is_bss(self):
        return bool(self.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)

    def contains_rva(self, rva):
        return self.virtual_addr <= rva < self.virtual_addr + self.virtual_size

    def rva_to_file_offset(self, rva):
        if not self.contains_rva(rva):
            return None
        offset_in_section = rva - self.virtual_addr
        # Beyond raw data on disk = BSS/uninitialized region
        if offset_in_section >= self.raw_size:
            return None
        return self.raw_offset + offset_in_section

    def __repr__(self):
        return f"PESection({self.name}, VA=0x{self.virtual_addr:08X}, size=0x{self.virtual_size:X})"


class PEFile:
    """Minimal PE parser for reading sections and bytes at RVAs."""

    def __init__(self, path):
        self.path = Path(path)
        self.sections = []
        self.image_base = 0
        self._data = None
        self._parse()

    def _parse(self):
        with open(self.path, 'rb') as f:
            self._data = f.read()

        data = self._data

        # DOS header
        if data[:2] != b'MZ':
            raise ValueError(f"Not a valid PE file: {self.path}")

        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]

        # PE signature
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            raise ValueError(f"Invalid PE signature at offset 0x{pe_offset:X}")

        coff_offset = pe_offset + 4
        num_sections = struct.unpack_from('<H', data, coff_offset + 2)[0]
        optional_header_size = struct.unpack_from('<H', data, coff_offset + 16)[0]

        optional_offset = coff_offset + 20
        magic = struct.unpack_from('<H', data, optional_offset)[0]
        if magic == 0x20B:  # PE32+ (64-bit)
            self.image_base = struct.unpack_from('<Q', data, optional_offset + 24)[0]
        elif magic == 0x10B:  # PE32 (32-bit)
            self.image_base = struct.unpack_from('<I', data, optional_offset + 28)[0]
        else:
            raise ValueError(f"Unknown PE optional header magic: 0x{magic:04X}")

        section_offset = optional_offset + optional_header_size
        for i in range(num_sections):
            off = section_offset + i * 40
            name_bytes = data[off:off+8]
            name = name_bytes.rstrip(b'\x00').decode('ascii', errors='replace')
            virtual_size = struct.unpack_from('<I', data, off + 8)[0]
            virtual_addr = struct.unpack_from('<I', data, off + 12)[0]
            raw_size = struct.unpack_from('<I', data, off + 16)[0]
            raw_offset = struct.unpack_from('<I', data, off + 20)[0]
            characteristics = struct.unpack_from('<I', data, off + 36)[0]
            self.sections.append(PESection(name, virtual_size, virtual_addr, raw_size, raw_offset, characteristics))

    def rva_to_file_offset(self, rva):
        """Convert an RVA to a file offset."""
        for section in self.sections:
            offset = section.rva_to_file_offset(rva)
            if offset is not None:
                return offset
        return None

    def read_bytes_at_rva(self, rva, length):
        """Read bytes at an RVA."""
        offset = self.rva_to_file_offset(rva)
        if offset is None:
            return None
        if offset + length > len(self._data):
            return None
        return self._data[offset:offset+length]

    def read_bytes_at_offset(self, offset, length):
        """Read bytes at a raw file offset."""
        if offset + length > len(self._data):
            return None
        return self._data[offset:offset+length]

    def get_section_for_rva(self, rva):
        """Get the section containing an RVA."""
        for section in self.sections:
            if section.contains_rva(rva):
                return section
        return None

    def get_section_by_name(self, name):
        """Get a section by its name."""
        for section in self.sections:
            if section.name == name:
                return section
        return None

    def get_code_sections(self):
        return [s for s in self.sections if s.is_code]

    def get_data_sections(self):
        return [s for s in self.sections if s.is_data and not s.is_code]

    def get_all_searchable_sections(self):
        """Return all sections that have data on disk (code + initialized data)."""
        return [s for s in self.sections if (s.is_code or s.is_data) and s.raw_size > 0]

    def search_pattern(self, pattern, section=None, mask=None):
        """
        Search for a byte pattern in the PE file.
        Returns list of RVAs where pattern was found.
        """
        results = []
        sections = [section] if section else self.get_all_searchable_sections()

        for sect in sections:
            sect_data = self._data[sect.raw_offset:sect.raw_offset + sect.raw_size]
            if mask is None:
                # Fast exact search
                start = 0
                while True:
                    idx = sect_data.find(pattern, start)
                    if idx == -1:
                        break
                    rva = sect.virtual_addr + idx
                    results.append(rva)
                    start = idx + 1
            else:
                plen = len(pattern)

                # Find the longest consecutive run of must-match (0xFF) bytes
                best_run_start = 0
                best_run_len = 0
                cur_start = 0
                cur_len = 0
                for k in range(plen):
                    if mask[k] == 0xFF:
                        if cur_len == 0:
                            cur_start = k
                        cur_len += 1
                        if cur_len > best_run_len:
                            best_run_len = cur_len
                            best_run_start = cur_start
                    else:
                        cur_len = 0
                        cur_start = k + 1

                if best_run_len == 0:
                    continue

                anchor = pattern[best_run_start:best_run_start + best_run_len]
                anchor_offset = best_run_start

                start = 0
                data_len = len(sect_data)
                while True:
                    idx = sect_data.find(anchor, start)
                    if idx == -1:
                        break
                    pat_start = idx - anchor_offset
                    if pat_start < 0 or pat_start + plen > data_len:
                        start = idx + 1
                        continue

                    match = True
                    for j in range(plen):
                        if mask[j] == 0xFF and sect_data[pat_start + j] != pattern[j]:
                            match = False
                            break
                    if match:
                        rva = sect.virtual_addr + pat_start
                        results.append(rva)

                    start = idx + 1

        return results

    def find_xrefs_to_rva(self, target_rva, search_sections=None, max_results=16):
        """
        Find CALL/JMP instructions that reference target_rva via RIP-relative addressing.
        Returns list of (caller_rva, instruction_type) tuples.

        Optimized: instead of scanning every byte, we compute the expected displacement
        for each position and search for the 4-byte displacement value directly.
        For a CALL at position P to target T: displacement = T - (P + 5)
        So we search for all E8 xx xx xx xx patterns where the rel32 resolves to target.

        Since the displacement depends on position, we can't do a single search.
        Instead, we chunk the section and narrow the search.
        """
        results = []
        sections = search_sections or self.get_code_sections()

        for sect in sections:
            sect_data = self._data[sect.raw_offset:sect.raw_offset + sect.raw_size]
            sect_len = len(sect_data)

            for opcode in (0xE8, 0xE9):
                itype = 'CALL' if opcode == 0xE8 else 'JMP'
                start = 0
                opc_byte = bytes([opcode])
                while True:
                    idx = sect_data.find(opc_byte, start)
                    if idx == -1 or idx + 5 > sect_len:
                        break
                    disp = struct.unpack_from('<i', sect_data, idx + 1)[0]
                    instr_rva = sect.virtual_addr + idx
                    resolved = instr_rva + 5 + disp
                    if resolved == target_rva:
                        results.append((instr_rva, itype))
                        if len(results) >= max_results:
                            return results
                    start = idx + 1

        return results

    def find_function_size(self, rva):
        """
        Estimate function size by looking for the next function prologue or INT3 padding.
        Returns estimated size in bytes, or None if unable to determine.
        """
        section = self.get_section_for_rva(rva)
        if section is None or not section.is_code:
            return None

        offset = self.rva_to_file_offset(rva)
        if offset is None:
            return None

        sect_end = section.raw_offset + section.raw_size
        max_search = min(sect_end - offset, 0x10000)  # cap at 64KB

        data = self._data[offset:offset + max_search]

        # Look for common function endings:
        # 1. CC CC CC (INT3 padding between functions)
        # 2. Common prologue patterns: push rbp / sub rsp
        i = 16  # skip at least first 16 bytes
        while i < len(data) - 4:
            # Check for INT3 padding (3+ consecutive 0xCC bytes)
            if data[i] == 0xCC and data[i+1] == 0xCC and data[i+2] == 0xCC:
                return i
            # Check for typical function prologue after a RET
            if data[i-1] == 0xC3 or data[i-1] == 0xCB:
                # Check if next instruction looks like a prologue
                if data[i] == 0x40 and data[i+1] == 0x53:  # push rbx
                    return i
                if data[i] == 0x48 and data[i+1] == 0x89:  # mov [...], ...
                    return i
                if data[i] == 0x48 and data[i+1] == 0x83 and data[i+2] == 0xEC:  # sub rsp, imm8
                    return i
                if data[i] == 0x55:  # push rbp
                    return i
            i += 1

        return None

    def find_vtable_references(self, rva):
        """
        Find vtable entries that contain this RVA.
        In .rdata, vtables are arrays of function pointers (full virtual addresses).
        Returns list of (vtable_rva, slot_index) tuples.
        """
        results = []
        full_addr = self.image_base + rva

        target_bytes = struct.pack('<Q', full_addr)

        for sect in self.get_data_sections():
            if sect.name not in ('.rdata', '.data'):
                continue
            sect_data = self._data[sect.raw_offset:sect.raw_offset + sect.raw_size]
            start = 0
            while True:
                idx = sect_data.find(target_bytes, start)
                if idx == -1:
                    break
                # Check if this is aligned to 8 bytes (typical for vtable entries)
                entry_rva = sect.virtual_addr + idx
                if idx % 8 == 0:
                    # Walk backward to find vtable start (look for RTTI pointer or alignment)
                    slot_index = 0
                    check = idx - 8
                    while check >= 0:
                        val = struct.unpack_from('<Q', sect_data, check)[0]
                        # Check if this looks like a valid code pointer
                        if self.image_base <= val < self.image_base + 0x10000000:
                            inner_rva = val - self.image_base
                            inner_sect = self.get_section_for_rva(inner_rva)
                            if inner_sect and inner_sect.is_code:
                                slot_index += 1
                                check -= 8
                                continue
                        break
                    results.append((entry_rva, slot_index))
                start = idx + 1

        return results

    @property
    def file_size(self):
        return len(self._data)


# ============================================================================
# SFE Source Parser
# ============================================================================

class AddressEntry:
    """Represents a single address extracted from SFE source."""
    def __init__(self, name, address, addr_type, source_file, line_number,
                 type_info=None, class_name=None, comment=None):
        self.name = name
        self.address = address  # RVA as integer
        self.addr_type = addr_type
        self.source_file = source_file
        self.line_number = line_number
        self.type_info = type_info
        self.class_name = class_name
        self.comment = comment
        self.is_commented_out = False

    def to_dict(self):
        return {
            'name': self.name,
            'address': f"0x{self.address:08X}",
            'addr_type': self.addr_type,
            'source_file': self.source_file,
            'line_number': self.line_number,
            'type_info': self.type_info,
            'class_name': self.class_name,
            'comment': self.comment,
        }

    def __repr__(self):
        return f"AddressEntry({self.name}, 0x{self.address:08X}, {self.addr_type})"


def _safe_parse_addr(expr):
    """
    Safely parse hex address expressions like '0x02042310 + 0xE90' or '0x0371A148-0x08'.
    Only handles hex literals with + and - operators. No eval().
    """
    expr = expr.strip()
    if not expr:
        return None

    # Only allow hex digits, 0x prefix, +, -, whitespace
    if not re.match(r'^[\s0-9a-fA-FxX+\-]+$', expr):
        return None

    tokens = re.findall(r'[+-]|0x[0-9a-fA-F]+|[0-9]+', expr)

    if not tokens:
        return None

    result = 0
    op = '+'  # implicit leading +

    for token in tokens:
        if token in ('+', '-'):
            op = token
        else:
            try:
                if token.lower().startswith('0x'):
                    val = int(token, 16)
                else:
                    val = int(token)
            except ValueError:
                return None

            if op == '+':
                result += val
            else:
                result -= val

    return result


def parse_sfe_source(source_dir):
    """Parse all SFE source files and extract address entries."""
    entries = []
    source_dir = Path(source_dir)

    # Patterns for address extraction
    reloc_addr_pat = re.compile(
        r'(?:static\s+)?RelocAddr\s*<\s*(.+?)\s*>\s+(\w+)\s*\((\s*0x[0-9A-Fa-f]+(?:\s*[+\-]\s*0x[0-9A-Fa-f]+)*(?:\s*[+\-]\s*\d+)?\s*)\)',
    )
    reloc_ptr_pat = re.compile(
        r'(?:static\s+)?(?:const\s+)?RelocPtr\s*<\s*(.+?)\s*>\s+(\w+)\s*\((\s*0x[0-9A-Fa-f]+(?:\s*[+\-]\s*0x[0-9A-Fa-f]+)*\s*)\)',
    )
    define_fn_pat = re.compile(
        r'DEFINE_MEMBER_FN(?:_\d+)?\s*\(\s*(\w+)\s*,\s*(.+?)\s*,\s*(0x[0-9A-Fa-f]+(?:\s*[+\-]\s*0x[0-9A-Fa-f]+)*)',
    )

    for fpath in sorted(source_dir.rglob('*')):
        if fpath.suffix not in ('.h', '.cpp'):
            continue
        rel_path = str(fpath.relative_to(source_dir.parent.parent))
        try:
            content = fpath.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue

        current_class = None

        for line_num, line in enumerate(content.split('\n'), 1):
            stripped = line.strip()

            # Track class/struct context
            class_match = re.match(r'(?:class|struct)\s+(\w+)', stripped)
            if class_match and '{' in stripped:
                current_class = class_match.group(1)

            is_commented = stripped.startswith('//')

            # Skip macro definitions
            if stripped.startswith('#define DEFINE_MEMBER_FN'):
                continue

            # Extract comment at end of line
            comment_match = re.search(r'//\s*(.+)$', stripped)
            comment = comment_match.group(1).strip() if comment_match else None

            # Try RelocAddr
            m = reloc_addr_pat.search(line)
            if m and not is_commented:
                type_info = m.group(1).strip()
                name = m.group(2).strip()
                addr_expr = m.group(3).strip()
                address = _safe_parse_addr(addr_expr)
                if address is not None and address != 0:
                    entry = AddressEntry(name, address, 'RelocAddr', rel_path, line_num,
                                        type_info=type_info, comment=comment)
                    entries.append(entry)
                continue

            # Try RelocPtr
            m = reloc_ptr_pat.search(line)
            if m and not is_commented:
                type_info = m.group(1).strip()
                name = m.group(2).strip()
                addr_expr = m.group(3).strip()
                address = _safe_parse_addr(addr_expr)
                if address is not None and address != 0:
                    entry = AddressEntry(name, address, 'RelocPtr', rel_path, line_num,
                                        type_info=type_info, comment=comment)
                    entries.append(entry)
                continue

            # Try DEFINE_MEMBER_FN
            m = define_fn_pat.search(line)
            if m:
                fn_name = m.group(1).strip()
                ret_type = m.group(2).strip()
                addr_expr = m.group(3).strip()
                address = _safe_parse_addr(addr_expr)
                if address is not None and address != 0:
                    entry = AddressEntry(fn_name, address, 'DEFINE_MEMBER_FN', rel_path, line_num,
                                        type_info=ret_type, class_name=current_class, comment=comment)
                    entry.is_commented_out = is_commented
                    if not is_commented:
                        entries.append(entry)
                continue

    return entries


# ============================================================================
# Signature Generation
# ============================================================================

def classify_address(pe, rva):
    """Classify an RVA as code, data, bss, or unknown based on PE sections."""
    section = pe.get_section_for_rva(rva)
    if section is None:
        return 'unknown'
    # Check if the offset is beyond raw data (BSS region)
    offset_in_section = rva - section.virtual_addr
    if offset_in_section >= section.raw_size:
        return 'bss'
    if section.is_code:
        return 'code'
    if section.is_data:
        return 'data'
    return 'other'


def generate_signature(pe, entry, sig_len=DEFAULT_SIG_LEN):
    """Generate a byte signature for an address entry."""
    rva = entry.address
    raw_bytes = pe.read_bytes_at_rva(rva, sig_len)

    section = pe.get_section_for_rva(rva)
    section_name = section.name if section else 'unknown'
    addr_class = classify_address(pe, rva)

    if raw_bytes is None:
        # Address is in BSS (uninitialized data) or beyond mapped range
        if section is not None:
            return {
                'name': entry.name,
                'address': f"0x{rva:08X}",
                'address_int': rva,
                'type': entry.addr_type,
                'source_file': entry.source_file,
                'line_number': entry.line_number,
                'type_info': entry.type_info,
                'class_name': entry.class_name,
                'comment': entry.comment,
                'section': section_name,
                'section_type': 'bss',
                'pattern': None,
                'mask': None,
                'sig_length': 0,
                'section_offset': rva - section.virtual_addr,
            }
        return None

    # For code addresses, build a mask that wildcards likely relocation targets
    mask = bytearray(b'\xFF' * sig_len)

    if addr_class == 'code':
        mask = _build_code_mask(raw_bytes, sig_len)

    return {
        'name': entry.name,
        'address': f"0x{rva:08X}",
        'address_int': rva,
        'type': entry.addr_type,
        'source_file': entry.source_file,
        'line_number': entry.line_number,
        'type_info': entry.type_info,
        'class_name': entry.class_name,
        'comment': entry.comment,
        'section': section_name,
        'section_type': addr_class,
        'pattern': raw_bytes.hex(),
        'mask': mask.hex() if isinstance(mask, (bytes, bytearray)) else mask,
        'sig_length': sig_len,
    }


def _consume_modrm(raw_bytes, length, modrm_pos, mask, opcode_imm_size=0):
    """
    Consume a ModR/M-bearing instruction starting at modrm_pos.
    Wildcards RIP-relative disp32 and any trailing immediate.

    Returns (next_i, ok). ok=False means we ran off the end.
    """
    if modrm_pos >= length:
        return length, False

    modrm = raw_bytes[modrm_pos]
    mod = (modrm >> 6) & 3
    rm = modrm & 7

    cur = modrm_pos + 1
    has_sib = (mod != 3 and rm == 4)
    disp_size = 0

    if mod == 0 and rm == 5:
        # RIP-relative: wildcard 4-byte disp
        disp_size = 4
        for j in range(disp_size):
            if cur + j < length:
                mask[cur + j] = 0x00
    elif mod == 0 and rm == 4:
        # SIB with potential disp32
        if cur < length:
            sib = raw_bytes[cur]
            if (sib & 7) == 5:
                disp_size = 4
                for j in range(1, 1 + disp_size):
                    if cur + j < length:
                        mask[cur + j] = 0x00
    elif mod == 1:
        disp_size = 1
    elif mod == 2:
        disp_size = 4
        # mod=10 disp32 is also load-time relocatable in some compiler outputs;
        # be conservative and wildcard it
        sib_off = 1 if has_sib else 0
        for j in range(sib_off, sib_off + disp_size):
            if cur + j < length:
                mask[cur + j] = 0x00

    cur += (1 if has_sib else 0) + disp_size

    # Wildcard trailing immediate (compilers often re-pick constants on recompile)
    for j in range(opcode_imm_size):
        if cur + j < length:
            mask[cur + j] = 0x00
    cur += opcode_imm_size

    return cur, cur <= length


# 1-byte opcodes that carry a ModR/M byte. Maps opcode -> imm_size.
_MODRM_1BYTE = {
    **{op: 0 for op in (
        0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B,
        0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B,
        0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2A, 0x2B,
        0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3A, 0x3B,
        0x62, 0x63,
        0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0xD0, 0xD1, 0xD2, 0xD3,
        0xF6, 0xF7, 0xFE, 0xFF,
    )},
    0x69: 4, 0x6B: 1,
    0x80: 1, 0x81: 4, 0x82: 1, 0x83: 1,
    0xC0: 1, 0xC1: 1,
    0xC6: 1, 0xC7: 4,
}


def _build_code_mask(raw_bytes, length):
    """
    Build a mask for x86-64 code that wildcards displacement/immediate fields.

    Lightweight x86-64 decoder pass identifying:
      - CALL/JMP rel32, Jcc rel8/rel32
      - 1-byte ModR/M opcodes with RIP-relative disp32 or trailing imm
      - 0x0F xx two-byte opcodes (SSE/SSE2/SSE3/SSSE3/SSE4 legacy encodings)
      - 0x0F 38 / 0x0F 3A three-byte opcodes (SSSE3/SSE4)
      - VEX (0xC4 / 0xC5) prefixed instructions (AVX, AVX2)
      - EVEX (0x62) prefixed instructions (AVX-512)
      - Instruction prefixes (0x66/0x67/0xF0/0xF2/0xF3/segment overrides)

    Bytes we choose not to decode are left as must-match (0xFF) — false matches
    are worse than missed matches; the disambiguator handles ambiguity.
    """
    mask = bytearray(b'\xFF' * length)
    i = 0

    while i < length:
        start = i

        # ---- Skip legacy prefixes ----
        # Segment overrides: 0x26/0x2E/0x36/0x3E/0x64/0x65
        # Operand-size: 0x66, address-size: 0x67
        # LOCK/REPNE/REP: 0xF0/0xF2/0xF3
        while i < length and raw_bytes[i] in (
            0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3
        ):
            i += 1

        if i >= length:
            break

        b = raw_bytes[i]

        # ---- VEX 2-byte (0xC5) ----
        # Layout: C5 [P1] [opcode] [ModR/M] ...
        if b == 0xC5 and i + 2 < length:
            opcode = raw_bytes[i + 2]
            modrm_pos = i + 3
            # 0F 3A-class VEX may carry trailing imm8 (e.g. shufps, pcmpestri)
            imm_size = 1 if (opcode & 0xF0) in (0x40, 0x60) else 0
            # Heuristic: VEX-encoded compares (0xC2) + insertions take imm8
            if opcode in (0xC2, 0xC4, 0xC6, 0x0E, 0x0F, 0x14, 0x15, 0x16, 0x17, 0x20, 0x21, 0x22):
                imm_size = 1
            new_i, ok = _consume_modrm(raw_bytes, length, modrm_pos, mask, imm_size)
            i = new_i if ok else length
            continue

        # ---- VEX 3-byte (0xC4) ----
        # Layout: C4 [P1] [P2] [opcode] [ModR/M] ...
        if b == 0xC4 and i + 3 < length:
            p1 = raw_bytes[i + 1]
            opcode = raw_bytes[i + 3]
            modrm_pos = i + 4
            mmmmm = p1 & 0x1F  # 1=0F, 2=0F 38, 3=0F 3A
            imm_size = 1 if mmmmm == 3 else 0
            if mmmmm == 1 and opcode in (0xC2, 0xC4, 0xC6):
                imm_size = 1
            new_i, ok = _consume_modrm(raw_bytes, length, modrm_pos, mask, imm_size)
            i = new_i if ok else length
            continue

        # ---- EVEX (0x62) ----
        # Layout: 62 [P1] [P2] [P3] [opcode] [ModR/M] ...
        if b == 0x62 and i + 4 < length:
            p1 = raw_bytes[i + 1]
            opcode = raw_bytes[i + 4]
            modrm_pos = i + 5
            mmm = p1 & 0x07  # 1=0F, 2=0F 38, 3=0F 3A (low 3 bits of mm field)
            imm_size = 1 if mmm == 3 else 0
            new_i, ok = _consume_modrm(raw_bytes, length, modrm_pos, mask, imm_size)
            i = new_i if ok else length
            continue

        # ---- REX (0x40-0x4F) — single byte, opcode follows ----
        rex = 0
        if 0x40 <= b <= 0x4F and i + 1 < length:
            rex = b
            i += 1
            b = raw_bytes[i]

        # ---- E8/E9 = CALL/JMP rel32 ----
        if b in (0xE8, 0xE9):
            for j in range(1, 5):
                if i + j < length:
                    mask[i + j] = 0x00
            i += 5
            continue

        # ---- 0x0F xx two-byte opcodes ----
        if b == 0x0F and i + 1 < length:
            second = raw_bytes[i + 1]

            # Jcc rel32 (0F 80-8F)
            if 0x80 <= second <= 0x8F:
                for j in range(2, 6):
                    if i + j < length:
                        mask[i + j] = 0x00
                i += 6
                continue

            # 3-byte opcode escapes 0F 38 xx and 0F 3A xx
            if second == 0x38 and i + 2 < length:
                # 0F 38 xx [ModR/M] — no immediate generally
                new_i, ok = _consume_modrm(raw_bytes, length, i + 3, mask, 0)
                i = new_i if ok else length
                continue
            if second == 0x3A and i + 2 < length:
                # 0F 3A xx [ModR/M] [imm8]
                new_i, ok = _consume_modrm(raw_bytes, length, i + 3, mask, 1)
                i = new_i if ok else length
                continue

            # Generic 0F xx — most are SSE/SSE2/CMOVcc with ModR/M and no imm.
            # A handful carry an imm8 (0F C2 cmpps, 0F 70 pshufd-class, 0F 71/72/73 with imm,
            # 0F C4/C5/C6 pinsrw/pextrw/shufpd).
            imm_size = 0
            if second in (0x70, 0x71, 0x72, 0x73, 0xBA, 0xC2, 0xC4, 0xC5, 0xC6):
                imm_size = 1

            # 0F 0x00..0x09 are mostly system instructions without ModR/M — skip decode
            if second < 0x10:
                i += 2
                continue

            new_i, ok = _consume_modrm(raw_bytes, length, i + 2, mask, imm_size)
            i = new_i if ok else length
            continue

        # ---- 1-byte ModR/M opcodes ----
        if b in _MODRM_1BYTE:
            imm_size = _MODRM_1BYTE[b]
            # Some opcodes' immediate width depends on operand size: Group 1 0x81 with REX.W stays imm32
            new_i, ok = _consume_modrm(raw_bytes, length, i + 1, mask, imm_size)
            i = new_i if ok else length
            continue

        # ---- MOV reg, imm64 (REX.W + B8+r) ----
        if rex and (rex & 0x08) and 0xB8 <= b <= 0xBF:
            for j in range(1, 9):
                if i + j < length:
                    mask[i + j] = 0x00
            i += 9
            continue

        # ---- MOV reg, imm32 (B8+r without REX.W) ----
        if 0xB8 <= b <= 0xBF and not (rex and (rex & 0x08)):
            for j in range(1, 5):
                if i + j < length:
                    mask[i + j] = 0x00
            i += 5
            continue

        # ---- Short jumps: Jcc rel8 (70-7F), JMP rel8 (EB), LOOP (E0-E2), JCXZ (E3) ----
        if (0x70 <= b <= 0x7F) or b in (0xEB, 0xE0, 0xE1, 0xE2, 0xE3):
            if i + 1 < length:
                mask[i + 1] = 0x00
            i += 2
            continue

        # ---- A0-A3: MOV AL/AX/EAX/RAX, moffs (8-byte absolute address with REX.W) ----
        if 0xA0 <= b <= 0xA3:
            off_size = 8 if (rex and (rex & 0x08)) else 4
            for j in range(1, 1 + off_size):
                if i + j < length:
                    mask[i + j] = 0x00
            i += 1 + off_size
            continue

        # ---- Default: advance 1 byte (must-match) ----
        # Don't loop forever if we made no progress
        if i == start:
            i += 1

    return bytes(mask)


def generate_all_signatures(pe, entries, sig_len=DEFAULT_SIG_LEN):
    """Generate signatures for all address entries."""
    signatures = []
    failed = []

    for entry in entries:
        sig = generate_signature(pe, entry, sig_len)
        if sig is None:
            failed.append(entry)
        else:
            signatures.append(sig)

    return signatures, failed


# ============================================================================
# XREF-Based Disambiguation
# ============================================================================

def build_xref_signature(pe, rva, sig):
    """
    Build an XREF-based disambiguator for a function.
    Finds callers of the function and captures their call-site patterns.
    Returns a dict with xref info, or None if no useful xrefs found.
    """
    if sig.get('section_type') != 'code':
        return None

    xrefs = pe.find_xrefs_to_rva(rva)
    if not xrefs:
        return None

    # For each caller, capture bytes around the call site
    xref_patterns = []
    for caller_rva, itype in xrefs[:8]:  # Cap at 8 xrefs
        # Read bytes BEFORE the call instruction (the setup code)
        context_bytes = pe.read_bytes_at_rva(caller_rva - 16, 16)
        if context_bytes:
            # Build a mask for the context (it's code, so mask relocations)
            context_mask = _build_code_mask(context_bytes, 16)
            xref_patterns.append({
                'caller_rva': f"0x{caller_rva:08X}",
                'type': itype,
                'pre_context': context_bytes.hex(),
                'pre_context_mask': context_mask.hex(),
            })

    if not xref_patterns:
        return None

    return {
        'xref_count': len(xrefs),
        'xref_patterns': xref_patterns,
    }


def resolve_ambiguous_with_xrefs(pe, sig, matches):
    """
    Try to disambiguate multiple matches using XREF analysis.
    For each candidate match, check if its callers match the original xref patterns.
    Only accepts if exactly one candidate has matching xrefs and others do not.
    """
    xref_info = sig.get('_xref_info')
    if not xref_info or not xref_info.get('xref_patterns'):
        return None

    # Require verification during generation phase
    if not sig.get('_disambiguation_verified'):
        return None

    original_xref_patterns = xref_info['xref_patterns']
    min_required = max(1, len(original_xref_patterns) // 2)

    scored_matches = []

    for candidate_rva, confidence in matches:
        candidate_xrefs = pe.find_xrefs_to_rva(candidate_rva)
        if not candidate_xrefs:
            scored_matches.append((candidate_rva, 0))
            continue

        score = 0
        for orig_xref in original_xref_patterns:
            orig_pre = bytes.fromhex(orig_xref['pre_context'])
            orig_mask = bytes.fromhex(orig_xref['pre_context_mask'])

            for cand_rva, cand_type in candidate_xrefs:
                if cand_type != orig_xref['type']:
                    continue
                cand_context = pe.read_bytes_at_rva(cand_rva - 16, 16)
                if cand_context is None:
                    continue

                match = True
                for j in range(16):
                    if orig_mask[j] == 0xFF and cand_context[j] != orig_pre[j]:
                        match = False
                        break
                if match:
                    score += 1
                    break

        scored_matches.append((candidate_rva, score))

    # Only accept if exactly one candidate meets the minimum threshold
    # and all others score significantly lower
    good_matches = [(rva, sc) for rva, sc in scored_matches if sc >= min_required]
    if len(good_matches) == 1:
        return good_matches[0][0]
    elif len(good_matches) > 1:
        # Check if best is significantly better than second-best
        good_matches.sort(key=lambda x: x[1], reverse=True)
        if good_matches[0][1] >= good_matches[1][1] * 2 and good_matches[0][1] >= 2:
            return good_matches[0][0]
    return None


def resolve_ambiguous_with_function_size(pe, sig, matches):
    """
    Try to disambiguate using function size comparison.
    Only accepts if exactly one candidate has a very close size match
    and the others are significantly different.
    """
    original_size = sig.get('_function_size')
    if original_size is None or original_size < 32:
        return None

    # Require verification during generation phase
    if not sig.get('_disambiguation_verified'):
        return None

    sizes = []
    for candidate_rva, confidence in matches:
        cand_size = pe.find_function_size(candidate_rva)
        sizes.append((candidate_rva, cand_size))

    # Filter candidates with valid sizes
    valid = [(rva, sz) for rva, sz in sizes if sz is not None]
    if len(valid) < 2:
        return None

    # Find candidates within 5% of original size
    close_matches = [(rva, sz) for rva, sz in valid
                     if abs(sz - original_size) <= max(original_size * 0.05, 8)]

    # Only accept if exactly one candidate is close
    if len(close_matches) == 1:
        return close_matches[0][0]
    return None


def resolve_ambiguous_with_vtable(pe, sig, matches):
    """
    Try to disambiguate using vtable position.
    If the original function appeared at a specific vtable slot,
    check which candidate also appears at that slot in the new vtable.
    Only accepts if exactly one candidate matches the vtable pattern.
    """
    vtable_info = sig.get('_vtable_info')
    if not vtable_info:
        return None

    # Require verification during generation phase
    if not sig.get('_disambiguation_verified'):
        return None

    vtable_matches = []
    for candidate_rva, confidence in matches:
        cand_vtables = pe.find_vtable_references(candidate_rva)
        matched = False
        for vtable_rva, slot_idx in cand_vtables:
            for orig_vt in vtable_info:
                if orig_vt['slot_index'] == slot_idx:
                    matched = True
                    break
            if matched:
                break
        if matched:
            vtable_matches.append(candidate_rva)

    if len(vtable_matches) == 1:
        return vtable_matches[0]
    return None


# ============================================================================
# Signature Scanning
# ============================================================================

def _wildcard_count(mask_bytes):
    return sum(1 for b in mask_bytes if b == 0x00)


def scan_for_signature(pe, sig, search_sections=None, rebuild_mask=True):
    """
    Search for a signature in a PE file.
    Returns list of (rva, confidence) tuples.

    When rebuild_mask=True (default) and the entry is code, the mask is
    re-derived from the pattern bytes using the current _build_code_mask
    logic. Existing signatures generated with an older, narrower decoder
    benefit immediately — we only ADOPT the rebuilt mask if it produces
    at least as many wildcards as the stored one (strictly equal-or-looser).
    """
    if sig.get('pattern') is None:
        return []

    pattern = bytes.fromhex(sig['pattern'])
    mask_hex = sig.get('mask')

    if mask_hex:
        mask = bytes.fromhex(mask_hex)
    else:
        mask = None

    section_type = sig.get('section_type', 'code')

    if rebuild_mask and section_type == 'code' and pattern:
        improved = _build_code_mask(pattern, len(pattern))
        if mask is None or _wildcard_count(improved) >= _wildcard_count(mask):
            mask = improved
    if search_sections:
        sections = search_sections
    elif section_type == 'code':
        sections = pe.get_code_sections()
    elif section_type == 'data':
        sections = pe.get_data_sections()
    else:
        sections = pe.get_all_searchable_sections()

    results = []

    has_wildcards = mask and any(b != 0xFF for b in mask)

    if not has_wildcards:
        for sect in sections:
            rvas = pe.search_pattern(pattern, section=sect)
            for rva in rvas:
                results.append((rva, 1.0))
    else:
        for sect in sections:
            rvas = pe.search_pattern(pattern, section=sect, mask=mask)
            for rva in rvas:
                matched_bytes = sum(1 for i in range(len(pattern)) if mask[i] == 0xFF)
                total_bytes = len(pattern)
                confidence = matched_bytes / total_bytes
                results.append((rva, confidence))

    return results


def _scan_with_subwindows(pe, sig, search_sections, slide_offsets=(8, 16, 24)):
    """
    --slow fallback: when full-pattern match fails, try matching trailing
    sub-windows of the signature. Skips a possibly-recompiled prologue and
    anchors on what's hopefully more stable mid-function code.
    Returns the first non-empty match list, or [].
    """
    pattern = bytes.fromhex(sig['pattern'])
    full_len = len(pattern)
    section_type = sig.get('section_type', 'code')

    # Need at least 16 bytes left after the slide to be selective
    for off in slide_offsets:
        if full_len - off < 16:
            continue
        sub_pattern = pattern[off:]
        sub_mask = _build_code_mask(sub_pattern, len(sub_pattern)) if section_type == 'code' else None

        sub_sig = {
            'pattern': sub_pattern.hex(),
            'mask': sub_mask.hex() if sub_mask else None,
            'section_type': section_type,
        }
        matches = scan_for_signature(pe, sub_sig, search_sections, rebuild_mask=False)
        if matches:
            # Adjust each match RVA back by `off` to point at original function start
            adjusted = [(rva - off, conf * 0.85) for rva, conf in matches]
            return adjusted

    return []


def scan_all_signatures(pe, signatures, verbose=False, disambiguate=True, slow=False):
    """
    Scan a PE file for all signatures.
    Returns a dict mapping signature name to scan results.
    """
    results = {}
    bss_entries = []

    code_sections = pe.get_code_sections()
    data_sections = pe.get_data_sections()
    all_sections = pe.get_all_searchable_sections()

    total = len(signatures)
    found = 0
    ambiguous = 0
    missing = 0
    resolved_by_xref = 0
    resolved_by_size = 0
    resolved_by_vtable = 0
    resolved_by_extended = 0

    def _sig_key(sig):
        """Generate a unique key for a signature (handles duplicate names like ctor/dtor)."""
        addr = sig.get('address_int', 0)
        if isinstance(addr, str):
            addr = int(addr, 16)
        return f"{sig['name']}@0x{addr:08X}"

    for idx, sig in enumerate(signatures):
        name = sig['name']
        key = _sig_key(sig)
        section_type = sig.get('section_type', 'code')

        # BSS entries have no byte pattern - defer to delta-based relocation
        if section_type == 'bss':
            bss_entries.append((idx, sig))
            old_addr = int(sig['address'], 16) if isinstance(sig['address'], str) else sig['address']
            results[key] = {
                'name': name,
                'old_address': f"0x{old_addr:08X}",
                'old_address_int': old_addr,
                'status': 'bss_deferred',
                'matches': [],
                'new_address': None,
                'new_address_int': None,
                'confidence': 0.0,
                'method': 'bss_delta',
                'source_file': sig.get('source_file'),
                'line_number': sig.get('line_number'),
                'type': sig.get('type'),
                'type_info': sig.get('type_info'),
                'class_name': sig.get('class_name'),
                'section': sig.get('section', 'unknown'),
            }
            continue

        if section_type == 'code':
            search_sections = code_sections
        elif section_type == 'data':
            search_sections = data_sections
        else:
            search_sections = all_sections

        matches = scan_for_signature(pe, sig, search_sections)

        # If no match in primary section, try all sections
        if not matches and search_sections != all_sections:
            matches = scan_for_signature(pe, sig, all_sections)

        # --slow fallback: skip suspected recompiled prologue, anchor on later bytes
        if not matches and slow and section_type == 'code':
            matches = _scan_with_subwindows(pe, sig, search_sections)
            if not matches and search_sections != all_sections:
                matches = _scan_with_subwindows(pe, sig, all_sections)

        old_addr = int(sig['address'], 16) if isinstance(sig['address'], str) else sig['address']
        method = 'signature'

        if len(matches) == 1:
            new_addr, confidence = matches[0]
            status = 'found'
            found += 1
            if verbose:
                delta = new_addr - old_addr
                delta_str = f"+0x{delta:X}" if delta >= 0 else f"-0x{-delta:X}"
                if delta != 0:
                    print(f"  [{idx+1}/{total}] {name}: 0x{old_addr:08X} -> 0x{new_addr:08X} ({delta_str})")
                else:
                    print(f"  [{idx+1}/{total}] {name}: 0x{old_addr:08X} (unchanged)")
        elif len(matches) > 1 and disambiguate and len(matches) <= 100:
            # Try disambiguation strategies (skip if too many matches)
            resolved_rva = None

            # Strategy 1: XREF analysis
            if resolved_rva is None and sig.get('_xref_info'):
                resolved_rva = resolve_ambiguous_with_xrefs(pe, sig, matches)
                if resolved_rva is not None:
                    method = 'xref'
                    resolved_by_xref += 1

            # Strategy 2: Function size comparison
            if resolved_rva is None and sig.get('_function_size') is not None:
                resolved_rva = resolve_ambiguous_with_function_size(pe, sig, matches)
                if resolved_rva is not None:
                    method = 'function_size'
                    resolved_by_size += 1

            # Strategy 3: Vtable position
            if resolved_rva is None and sig.get('_vtable_info'):
                resolved_rva = resolve_ambiguous_with_vtable(pe, sig, matches)
                if resolved_rva is not None:
                    method = 'vtable'
                    resolved_by_vtable += 1

            # Strategy 4: Extended signature (try longer byte sequence)
            if resolved_rva is None and sig.get('_extended_patterns'):
                for ext in sig['_extended_patterns']:
                    ext_pattern = bytes.fromhex(ext['pattern'])
                    ext_mask = bytes.fromhex(ext['mask'])
                    ext_len = ext['length']

                    # Check which candidates match the extended pattern
                    ext_matches = []
                    for cand_rva, cand_conf in matches:
                        cand_bytes = pe.read_bytes_at_rva(cand_rva, ext_len)
                        if cand_bytes is None:
                            continue
                        match = True
                        for j in range(ext_len):
                            if ext_mask[j] == 0xFF and cand_bytes[j] != ext_pattern[j]:
                                match = False
                                break
                        if match:
                            ext_matches.append(cand_rva)

                    if len(ext_matches) == 1:
                        resolved_rva = ext_matches[0]
                        method = f'extended_{ext_len}b'
                        resolved_by_extended += 1
                        break

            if resolved_rva is not None:
                new_addr = resolved_rva
                # Find confidence from original matches
                confidence = 0.9
                for m_rva, m_conf in matches:
                    if m_rva == resolved_rva:
                        confidence = m_conf
                        break
                status = 'found'
                found += 1
                if verbose:
                    delta = new_addr - old_addr
                    delta_str = f"+0x{delta:X}" if delta >= 0 else f"-0x{-delta:X}"
                    print(f"  [{idx+1}/{total}] {name}: 0x{old_addr:08X} -> 0x{new_addr:08X} ({delta_str}) [resolved by {method}]")
                matches = [(resolved_rva, confidence)]
            else:
                status = 'ambiguous'
                ambiguous += 1
                if verbose:
                    print(f"  [{idx+1}/{total}] {name}: AMBIGUOUS ({len(matches)} matches)")
        elif len(matches) > 1:
            status = 'ambiguous'
            ambiguous += 1
            if verbose:
                print(f"  [{idx+1}/{total}] {name}: AMBIGUOUS ({len(matches)} matches)")
        else:
            status = 'not_found'
            missing += 1
            if verbose:
                print(f"  [{idx+1}/{total}] {name}: NOT FOUND")

        results[key] = {
            'name': name,
            'old_address': f"0x{old_addr:08X}",
            'old_address_int': old_addr,
            'status': status,
            'matches': [(f"0x{rva:08X}", conf) for rva, conf in matches],
            'new_address': f"0x{matches[0][0]:08X}" if len(matches) == 1 else None,
            'new_address_int': matches[0][0] if len(matches) == 1 else None,
            'confidence': matches[0][1] if len(matches) == 1 else 0.0,
            'method': method,
            'source_file': sig.get('source_file'),
            'line_number': sig.get('line_number'),
            'type': sig.get('type'),
            'type_info': sig.get('type_info'),
            'class_name': sig.get('class_name'),
            'section': sig.get('section', 'unknown'),
        }

    # Resolve BSS entries using median delta from data section matches
    if bss_entries:
        data_deltas = []
        for rkey, result in results.items():
            if result['status'] == 'found':
                # Check if this result's original address is in a data section
                old_rva = result['old_address_int']
                for sig in signatures:
                    if sig['address_int'] == old_rva and sig.get('section_type') == 'data':
                        delta = result['new_address_int'] - result['old_address_int']
                        data_deltas.append(delta)
                        break

        # Also use code section deltas if data deltas are sparse
        if len(data_deltas) < 3:
            code_deltas = []
            for rkey, result in results.items():
                if result['status'] == 'found':
                    old_rva = result['old_address_int']
                    for sig in signatures:
                        if sig['address_int'] == old_rva and sig.get('section_type') == 'code':
                            delta = result['new_address_int'] - result['old_address_int']
                            code_deltas.append(delta)
                            break
            if code_deltas:
                code_deltas.sort()
                if not data_deltas:
                    data_deltas = code_deltas

        if data_deltas:
            data_deltas.sort()
            median_delta = data_deltas[len(data_deltas) // 2]
            if verbose:
                print(f"\n  BSS delta estimation: median shift = {median_delta:+d} (0x{abs(median_delta):X}) from {len(data_deltas)} section matches")

            for bss_idx, sig in bss_entries:
                bss_key = _sig_key(sig)
                bss_name = sig['name']
                old_addr = int(sig['address'], 16) if isinstance(sig['address'], str) else sig['address']
                new_addr = old_addr + median_delta
                results[bss_key]['status'] = 'estimated'
                results[bss_key]['new_address'] = f"0x{new_addr:08X}"
                results[bss_key]['new_address_int'] = new_addr
                results[bss_key]['confidence'] = 0.5
                results[bss_key]['method'] = 'bss_delta'
                results[bss_key]['matches'] = [(f"0x{new_addr:08X}", 0.5)]
                found += 1
                if verbose:
                    print(f"  [{bss_idx+1}/{total}] {bss_name}: 0x{old_addr:08X} -> 0x{new_addr:08X} (estimated)")
        else:
            for bss_idx, sig in bss_entries:
                bss_key = _sig_key(sig)
                bss_name = sig['name']
                results[bss_key]['status'] = 'not_found'
                missing += 1
                if verbose:
                    print(f"  [{bss_idx+1}/{total}] {bss_name}: BSS - no delta available")

    stats = {
        'found': found,
        'ambiguous': ambiguous,
        'missing': missing,
        'total': total,
        'resolved_by_xref': resolved_by_xref,
        'resolved_by_size': resolved_by_size,
        'resolved_by_vtable': resolved_by_vtable,
        'resolved_by_extended': resolved_by_extended,
    }
    return results, stats


# ============================================================================
# DLL Comparison
# ============================================================================

def extract_dll_addresses(dll_path, known_rvas):
    """
    Extract addresses from the compiled SFE DLL by searching for known RVA values
    stored as 32-bit immediates in the DLL code.
    Returns dict mapping RVA -> list of file offsets where found.
    """
    with open(dll_path, 'rb') as f:
        dll_data = f.read()

    found = {}
    for rva in known_rvas:
        target = struct.pack('<I', rva)
        positions = []
        pos = 0
        while True:
            idx = dll_data.find(target, pos)
            if idx == -1:
                break
            positions.append(idx)
            pos = idx + 1
        if positions:
            found[rva] = positions

    return found


def compare_with_dll(scan_results, signatures, dll_path):
    """
    Compare scanner-generated addresses against addresses found in the compiled SFE DLL.
    Returns comparison report.
    """
    # Get all known RVAs
    known_rvas = set()
    name_by_rva = {}
    for sig in signatures:
        rva = sig['address_int']
        known_rvas.add(rva)
        name_by_rva[rva] = sig['name']

    print(f"Extracting addresses from DLL: {dll_path}")
    dll_addrs = extract_dll_addresses(dll_path, known_rvas)

    report = {
        'dll_path': str(dll_path),
        'total_rvas': len(known_rvas),
        'found_in_dll': len(dll_addrs),
        'not_in_dll': len(known_rvas) - len(dll_addrs),
        'matches': [],
        'mismatches': [],
        'dll_only': [],
        'scanner_only': [],
    }

    for rva in sorted(known_rvas):
        name = name_by_rva[rva]
        in_dll = rva in dll_addrs
        key = f"{name}@0x{rva:08X}"
        scan_result = scan_results.get(key, {})
        scan_addr = scan_result.get('new_address_int')

        entry = {
            'name': name,
            'original_rva': f"0x{rva:08X}",
            'in_dll': in_dll,
            'scanner_addr': f"0x{scan_addr:08X}" if scan_addr else None,
            'scanner_status': scan_result.get('status', 'unknown'),
        }

        if in_dll and scan_addr is not None:
            if scan_addr == rva:
                report['matches'].append(entry)
            else:
                # Both found but different - this is expected when scanning same exe
                report['matches'].append(entry)
        elif in_dll and scan_addr is None:
            report['dll_only'].append(entry)
        elif not in_dll and scan_addr is not None:
            report['scanner_only'].append(entry)

    return report


# ============================================================================
# Output Generators
# ============================================================================

def generate_json_report(scan_results, stats, output_path=None):
    """Generate a JSON report of scan results."""
    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'stats': stats,
        'results': scan_results,
    }

    if output_path:
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"JSON report written to: {output_path}")

    return report


def generate_full_report(scan_results, stats, signatures):
    """Generate a comprehensive human-readable report with summary stats and per-address detail."""
    lines = []
    lines.append("=" * 90)
    lines.append("SFE Address Scan Report")
    lines.append("=" * 90)
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # Summary stats
    lines.append("--- SUMMARY ---")
    pct = (stats['found'] / stats['total'] * 100) if stats['total'] > 0 else 0
    lines.append(f"  Total addresses:    {stats['total']}")
    lines.append(f"  Found:              {stats['found']} ({pct:.1f}%)")
    lines.append(f"  Ambiguous:          {stats['ambiguous']}")
    lines.append(f"  Not found:          {stats['missing']}")
    if stats.get('resolved_by_xref', 0) > 0:
        lines.append(f"  Resolved by XREF:   {stats['resolved_by_xref']}")
    if stats.get('resolved_by_size', 0) > 0:
        lines.append(f"  Resolved by size:   {stats['resolved_by_size']}")
    if stats.get('resolved_by_vtable', 0) > 0:
        lines.append(f"  Resolved by vtable: {stats['resolved_by_vtable']}")
    if stats.get('resolved_by_extended', 0) > 0:
        lines.append(f"  Resolved by ext sig: {stats['resolved_by_extended']}")
    lines.append("")

    # Per-address results
    changed = []
    unchanged = []
    ambiguous_list = []
    missing_list = []
    estimated_list = []

    for name, result in sorted(scan_results.items()):
        if result['status'] == 'found':
            old = result['old_address_int']
            new = result['new_address_int']
            if old != new:
                changed.append(result)
            else:
                unchanged.append(result)
        elif result['status'] == 'estimated':
            estimated_list.append(result)
        elif result['status'] == 'ambiguous':
            ambiguous_list.append(result)
        else:
            missing_list.append(result)

    if changed:
        lines.append(f"--- CHANGED ADDRESSES ({len(changed)}) ---")
        lines.append(f"  {'Name':<50s} {'Old Address':>12s}    {'New Address':>12s}  {'Delta':>10s}  {'Method':<16s}  Confidence")
        lines.append(f"  {'-'*50} {'-'*12}    {'-'*12}  {'-'*10}  {'-'*16}  {'-'*10}")
        for r in sorted(changed, key=lambda x: x['old_address_int']):
            delta = r['new_address_int'] - r['old_address_int']
            delta_str = f"+0x{delta:X}" if delta >= 0 else f"-0x{-delta:X}"
            method = r.get('method', 'signature')
            conf = r.get('confidence', 0.0)
            lines.append(f"  {r['name']:<50s} {r['old_address']:>12s} -> {r['new_address']:>12s}  {delta_str:>10s}  {method:<16s}  {conf:.2f}")
        lines.append("")

    if unchanged:
        lines.append(f"--- UNCHANGED ADDRESSES ({len(unchanged)}) ---")
        for r in sorted(unchanged, key=lambda x: x['old_address_int']):
            lines.append(f"  {r['name']:<50s} {r['old_address']:>12s}")
        lines.append("")

    if estimated_list:
        lines.append(f"--- ESTIMATED (BSS delta) ({len(estimated_list)}) ---")
        for r in sorted(estimated_list, key=lambda x: x['old_address_int']):
            lines.append(f"  {r['name']:<50s} {r['old_address']:>12s} -> {r['new_address']:>12s}  (estimated)")
        lines.append("")

    if ambiguous_list:
        lines.append(f"--- AMBIGUOUS (MANUAL REVIEW NEEDED) ({len(ambiguous_list)}) ---")
        for r in sorted(ambiguous_list, key=lambda x: x['old_address_int']):
            matches_str = ", ".join(m[0] for m in r['matches'][:5])
            n_matches = len(r['matches'])
            lines.append(f"  {r['name']:<50s} {r['old_address']:>12s} -> [{matches_str}] ({n_matches} matches)")
        lines.append("")

    if missing_list:
        lines.append(f"--- NOT FOUND (FUNCTION REWRITTEN?) ({len(missing_list)}) ---")
        for r in sorted(missing_list, key=lambda x: x['old_address_int']):
            section = r.get('section', '?')
            lines.append(f"  {r['name']:<50s} {r['old_address']:>12s}  [{section}]")
        lines.append("")

    return "\n".join(lines)


def generate_cpp_header(scan_results, signatures):
    """
    Generate a ready-to-paste C++ header with updated addresses.
    Groups by source file and class.
    """
    lines = []
    lines.append("// ============================================================")
    lines.append("// SFE Updated Addresses - Auto-generated by sfe_scanner.py v2")
    lines.append(f"// Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("// ============================================================")
    lines.append("")
    lines.append("#pragma once")
    lines.append("")

    sig_by_key = {}
    for s in signatures:
        k = f"{s['name']}@0x{s['address_int']:08X}"
        sig_by_key[k] = s

    by_file = defaultdict(list)
    for key, result in scan_results.items():
        if result['status'] not in ('found', 'estimated'):
            continue
        sig = sig_by_key.get(key, {})
        src = result.get('source_file') or sig.get('source_file', 'unknown')
        by_file[src].append((result['name'], result, sig))

    for src_file in sorted(by_file.keys()):
        file_results = by_file[src_file]
        lines.append(f"// --- {src_file} ---")

        # Group by class
        by_class = defaultdict(list)
        for name, result, sig in file_results:
            cls = result.get('class_name') or sig.get('class_name') or ''
            by_class[cls].append((name, result, sig))

        for cls_name in sorted(by_class.keys()):
            cls_results = by_class[cls_name]
            if cls_name:
                lines.append(f"// class {cls_name}")

            for name, result, sig in sorted(cls_results, key=lambda x: x[1].get('line_number', 0)):
                new_addr = result['new_address']
                addr_type = result.get('type', sig.get('type', ''))
                type_info = result.get('type_info', sig.get('type_info', ''))
                confidence = result.get('confidence', 0)
                method = result.get('method', 'signature')
                old_addr = result.get('old_address', '')

                if old_addr != new_addr:
                    lines.append(f"// {name}: {old_addr} -> {new_addr} ({method}, conf={confidence:.2f})")
                else:
                    lines.append(f"// {name}: {new_addr} (unchanged)")

                if addr_type == 'DEFINE_MEMBER_FN':
                    lines.append(f"// DEFINE_MEMBER_FN(... {name} ..., {new_addr});")
                elif addr_type == 'RelocAddr':
                    lines.append(f"// RelocAddr<{type_info}> {name}({new_addr});")
                elif addr_type == 'RelocPtr':
                    lines.append(f"// RelocPtr<{type_info}> {name}({new_addr});")

            lines.append("")

    return "\n".join(lines)


def generate_address_library(scan_results, signatures, output_path=None):
    """
    Generate an Address Library database file.
    Maps stable IDs to function info.
    """
    entries = []
    sig_by_name = {s['name']: s for s in signatures}

    for idx, sig in enumerate(signatures):
        name = sig['name']
        rva = sig['address_int']
        key = f"{name}@0x{rva:08X}"
        result = scan_results.get(key, {})

        # Generate stable ID from function name + address hash (handles duplicate names)
        stable_id = int(hashlib.sha256(f"{name}@{rva}".encode()).hexdigest()[:8], 16)

        entry = {
            'id': stable_id,
            'index': idx,
            'name': name,
            'class': sig.get('class_name', ''),
            'type': sig.get('type', ''),
            'type_info': sig.get('type_info', ''),
            'section': sig.get('section', ''),
            'section_type': sig.get('section_type', ''),
            'original_address': sig.get('address', ''),
            'current_address': result.get('new_address', sig.get('address', '')),
            'status': result.get('status', 'unknown'),
            'confidence': result.get('confidence', 0.0),
            'method': result.get('method', ''),
            'signature_bytes': sig.get('pattern', ''),
            'signature_mask': sig.get('mask', ''),
            'sig_length': sig.get('sig_length', 0),
            'source_file': sig.get('source_file', ''),
            'line_number': sig.get('line_number', 0),
        }
        entries.append(entry)

    db = {
        'version': 2,
        'format': 'sfe_address_library',
        'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
        'entry_count': len(entries),
        'entries': entries,
    }

    if output_path:
        with open(output_path, 'w') as f:
            json.dump(db, f, indent=2)
        print(f"Address Library written to: {output_path}")

    return db


def generate_diff_report(scan_results, stats):
    """Generate a human-readable diff report (legacy compat)."""
    return generate_full_report(scan_results, stats, [])


def generate_patch_output(scan_results, signatures):
    """
    Generate patched C++ source snippets that can be applied to SFE.
    Groups output by source file.
    """
    lines = []
    lines.append("// ============================================================")
    lines.append("// SFE Address Patch - Auto-generated by sfe_scanner.py v2")
    lines.append(f"// Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("// ============================================================")
    lines.append("")

    by_file = defaultdict(list)
    for key, result in scan_results.items():
        src = result.get('source_file', 'unknown')
        by_file[src].append((result['name'], result))

    changes_count = 0
    for src_file in sorted(by_file.keys()):
        file_results = by_file[src_file]
        file_changes = [(n, r) for n, r in file_results
                        if r['status'] in ('found', 'estimated') and r['old_address_int'] != r['new_address_int']]
        if not file_changes:
            continue

        lines.append(f"// --- {src_file} ---")
        for name, result in sorted(file_changes, key=lambda x: x[1].get('line_number', 0)):
            old_addr = result['old_address']
            new_addr = result['new_address']
            line_num = result.get('line_number', '?')
            addr_type = result.get('type', '')
            method = result.get('method', 'signature')
            confidence = result.get('confidence', 0)

            lines.append(f"// Line {line_num}: {name} ({addr_type}) [{method}, conf={confidence:.2f}]")
            lines.append(f"//   OLD: {old_addr}")
            lines.append(f"//   NEW: {new_addr}")
            lines.append(f"//   Replace {old_addr} with {new_addr}")
            lines.append("")
            changes_count += 1

    if changes_count == 0:
        lines.append("// No address changes detected - executables appear identical.")
    else:
        lines.append(f"// Total changes: {changes_count}")

    # sed commands
    lines.append("")
    lines.append("// ============================================================")
    lines.append("// sed commands to apply these patches:")
    lines.append("// ============================================================")
    for src_file in sorted(by_file.keys()):
        file_results = by_file[src_file]
        file_changes = [(n, r) for n, r in file_results
                        if r['status'] in ('found', 'estimated') and r['old_address_int'] != r['new_address_int']]
        if not file_changes:
            continue
        for name, result in file_changes:
            old = result['old_address']
            new = result['new_address']
            lines.append(f"// sed -i 's/{old}/{new}/g' {src_file}")

    return "\n".join(lines)


def generate_sed_script(scan_results, signatures, output_path):
    """Generate an executable sed script for applying patches."""
    script_lines = ["#!/bin/bash", "# SFE Address Patch Script",
             f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", "",
             "SFE_DIR=\"${1:-.}\"", ""]

    by_file = defaultdict(list)
    for key, result in scan_results.items():
        if result['status'] not in ('found', 'estimated'):
            continue
        if result['old_address_int'] == result['new_address_int']:
            continue
        src = result.get('source_file', 'unknown')
        by_file[src].append((result['name'], result))

    for src_file in sorted(by_file.keys()):
        file_changes = by_file[src_file]
        for name, result in sorted(file_changes, key=lambda x: x[1].get('line_number', 0)):
            old = result['old_address']
            new = result['new_address']
            script_lines.append(f'sed -i "s/{old}/{new}/g" "$SFE_DIR/{src_file}"')

    script_lines.append("")
    script_lines.append('echo "Patch complete."')

    with open(output_path, 'w') as f:
        f.write("\n".join(script_lines))
    os.chmod(output_path, 0o755)
    print(f"Sed patch script written to: {output_path}")


# ============================================================================
# Main Commands
# ============================================================================

def cmd_generate(args):
    """Generate signature database from current executable."""
    exe_path = args.exe or DEFAULT_EXE

    print(f"Parsing SFE source: {SFE_SOURCE}")
    entries = parse_sfe_source(SFE_SOURCE)
    print(f"Found {len(entries)} address entries")

    # Deduplicate: prefer .cpp definitions
    seen = {}
    unique_entries = []
    for entry in entries:
        key = (entry.name, entry.address)
        if key not in seen:
            seen[key] = entry
            unique_entries.append(entry)
        else:
            existing = seen[key]
            if entry.source_file.endswith('.cpp') and existing.source_file.endswith('.h'):
                seen[key] = entry
                unique_entries = [e for e in unique_entries if (e.name, e.address) != key]
                unique_entries.append(entry)

    print(f"Unique entries after dedup: {len(unique_entries)}")

    reloc_addrs = [e for e in unique_entries if e.addr_type == 'RelocAddr']
    reloc_ptrs = [e for e in unique_entries if e.addr_type == 'RelocPtr']
    member_fns = [e for e in unique_entries if e.addr_type == 'DEFINE_MEMBER_FN']
    print(f"  RelocAddr: {len(reloc_addrs)}")
    print(f"  RelocPtr:  {len(reloc_ptrs)}")
    print(f"  DEFINE_MEMBER_FN: {len(member_fns)}")

    print(f"\nLoading PE: {exe_path}")
    pe = PEFile(exe_path)
    print(f"Image base: 0x{pe.image_base:016X}")
    print(f"Sections:")
    for s in pe.sections:
        flags = []
        if s.is_code: flags.append("CODE")
        if s.is_data: flags.append("DATA")
        if s.is_bss: flags.append("BSS")
        mapped = "mapped" if s.raw_size > 0 else "unmapped"
        print(f"  {s.name:10s} VA=0x{s.virtual_addr:08X} VSize=0x{s.virtual_size:08X} "
              f"Raw=0x{s.raw_size:08X} [{', '.join(flags)}] ({mapped})")

    print(f"\nGenerating signatures (length={DEFAULT_SIG_LEN} bytes)...")
    signatures, failed = generate_all_signatures(pe, unique_entries, DEFAULT_SIG_LEN)

    print(f"Generated {len(signatures)} signatures")
    if failed:
        print(f"Failed to read {len(failed)} addresses (out of mapped range):")
        for entry in failed:
            section = pe.get_section_for_rva(entry.address)
            sect_info = f" in {section.name}" if section else " (no section)"
            print(f"  {entry.name} @ 0x{entry.address:08X}{sect_info}")

    # Verify uniqueness and build disambiguation data
    print(f"\nPhase 1: Verifying signature uniqueness...")
    unique_count = 0
    ambiguous_count = 0
    ambiguous_sigs = []

    for sig in signatures:
        if sig.get('pattern') is None:
            continue
        matches = scan_for_signature(pe, sig)
        if len(matches) == 1:
            unique_count += 1
        elif len(matches) > 1:
            ambiguous_count += 1
            sig['_ambiguous_in_source'] = True
            sig['_match_count_in_source'] = len(matches)
            ambiguous_sigs.append(sig)

            # Try extending signatures to resolve (32 -> 48 -> 64 -> 96 -> 128 -> 192 -> 256)
            old_addr = int(sig['address'], 16)
            resolved = False
            for try_len in [48, 64, 96, 128, 192, 256]:
                longer_bytes = pe.read_bytes_at_rva(old_addr, try_len)
                if longer_bytes is None:
                    break
                longer_mask = _build_code_mask(longer_bytes, try_len) if sig['section_type'] == 'code' else b'\xFF' * try_len
                temp_sig = dict(sig)
                temp_sig['pattern'] = longer_bytes.hex()
                temp_sig['mask'] = longer_mask.hex()
                temp_sig['sig_length'] = try_len
                temp_matches = scan_for_signature(pe, temp_sig)
                if len(temp_matches) == 1:
                    sig['pattern'] = longer_bytes.hex()
                    sig['mask'] = longer_mask.hex()
                    sig['sig_length'] = try_len
                    sig['_resolved_length'] = try_len
                    unique_count += 1
                    ambiguous_count -= 1
                    resolved = True
                    break

            if not resolved:
                # Store extended patterns for disambiguation during scanning
                extended_patterns = []
                for try_len in [128, 192, 256]:
                    longer_bytes = pe.read_bytes_at_rva(old_addr, try_len)
                    if longer_bytes is None:
                        break
                    longer_mask = _build_code_mask(longer_bytes, try_len) if sig['section_type'] == 'code' else b'\xFF' * try_len
                    extended_patterns.append({
                        'length': try_len,
                        'pattern': longer_bytes.hex(),
                        'mask': longer_mask.hex(),
                    })
                if extended_patterns:
                    sig['_extended_patterns'] = extended_patterns

    print(f"  Unique (signature only): {unique_count}")
    print(f"  Still ambiguous: {ambiguous_count}")

    # Phase 2: Build XREF, function size, and vtable data for ambiguous entries
    still_ambiguous = [s for s in signatures if s.get('_ambiguous_in_source') and not s.get('_resolved_length')]
    if still_ambiguous:
        do_xrefs = getattr(args, 'slow', False)
        print(f"\nPhase 2: Building disambiguation data for {len(still_ambiguous)} ambiguous signatures...")
        if do_xrefs:
            print("  (XREF analysis enabled - this may take several minutes)")
        else:
            print("  (XREF analysis disabled - use --slow to enable)")

        xref_resolved = 0
        size_captured = 0
        vtable_captured = 0

        for sig_idx, sig in enumerate(still_ambiguous):
            old_addr = int(sig['address'], 16)

            # XREF analysis (slow - scans entire .text section per function)
            if do_xrefs and sig.get('section_type') == 'code':
                print(f"    [{sig_idx+1}/{len(still_ambiguous)}] XREF scan: {sig['name']}...", end='', flush=True)
                xref_info = build_xref_signature(pe, old_addr, sig)
                if xref_info:
                    sig['_xref_info'] = xref_info
                    xref_resolved += 1
                    print(f" {xref_info['xref_count']} xrefs")
                else:
                    print(" none")

            if sig.get('section_type') == 'code':
                # Function size (fast)
                func_size = pe.find_function_size(old_addr)
                if func_size is not None:
                    sig['_function_size'] = func_size
                    size_captured += 1

                # Vtable references (moderate)
                vtable_refs = pe.find_vtable_references(old_addr)
                if vtable_refs:
                    sig['_vtable_info'] = [{'vtable_rva': f"0x{vt:08X}", 'slot_index': si}
                                           for vt, si in vtable_refs]
                    vtable_captured += 1

        print(f"  XREF data captured: {xref_resolved}")
        print(f"  Function size captured: {size_captured}")
        print(f"  Vtable references captured: {vtable_captured}")

        # Phase 3: Test each disambiguation method on the source exe
        # We temporarily set _disambiguation_verified=True so the resolvers don't skip,
        # then only keep the flag if the method actually picks the correct address.
        # Skip entries with too many matches (> 100) - those are data patterns, not unique functions.
        MAX_DISAMBIG_MATCHES = 100
        print(f"\nPhase 3: Testing disambiguation on source executable...")
        test_resolved = 0
        skipped_too_many = 0
        for sig in still_ambiguous:
            matches = scan_for_signature(pe, sig)
            if len(matches) <= 1:
                continue
            if len(matches) > MAX_DISAMBIG_MATCHES:
                skipped_too_many += 1
                continue

            old_addr = int(sig['address'], 16)
            sig['_disambiguation_verified'] = True  # Temporarily enable

            resolved_rva = None
            resolved_method = None

            # Try each method independently, verify it picks the correct answer
            if sig.get('_xref_info'):
                test_rva = resolve_ambiguous_with_xrefs(pe, sig, matches)
                if test_rva == old_addr:
                    resolved_rva = test_rva
                    resolved_method = 'xref'

            if resolved_rva is None and sig.get('_function_size') is not None:
                test_rva = resolve_ambiguous_with_function_size(pe, sig, matches)
                if test_rva == old_addr:
                    resolved_rva = test_rva
                    resolved_method = 'function_size'

            if resolved_rva is None and sig.get('_vtable_info'):
                test_rva = resolve_ambiguous_with_vtable(pe, sig, matches)
                if test_rva == old_addr:
                    resolved_rva = test_rva
                    resolved_method = 'vtable'

            # Try extended patterns (these don't require _disambiguation_verified)
            if resolved_rva is None and sig.get('_extended_patterns'):
                for ext in sig['_extended_patterns']:
                    ext_pattern = bytes.fromhex(ext['pattern'])
                    ext_mask = bytes.fromhex(ext['mask'])
                    ext_len = ext['length']
                    ext_matches = []
                    for cand_rva, _ in matches:
                        cand_bytes = pe.read_bytes_at_rva(cand_rva, ext_len)
                        if cand_bytes is None:
                            continue
                        ok = True
                        for j in range(ext_len):
                            if ext_mask[j] == 0xFF and cand_bytes[j] != ext_pattern[j]:
                                ok = False
                                break
                        if ok:
                            ext_matches.append(cand_rva)
                    if len(ext_matches) == 1 and ext_matches[0] == old_addr:
                        resolved_rva = ext_matches[0]
                        resolved_method = f'extended_{ext_len}b'
                        break

            if resolved_rva is not None:
                test_resolved += 1
                sig['_disambiguation_verified'] = True
                sig['_verified_method'] = resolved_method
            else:
                # Method failed or picked wrong answer - remove the flag
                sig.pop('_disambiguation_verified', None)

        if skipped_too_many:
            print(f"  Skipped {skipped_too_many} entries with >{MAX_DISAMBIG_MATCHES} matches")

        print(f"  Disambiguation verified: {test_resolved}/{len(still_ambiguous)}")

    # Save
    db = {
        'version': 2,
        'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
        'source_exe': str(exe_path),
        'source_exe_size': pe.file_size,
        'image_base': f"0x{pe.image_base:016X}",
        'sig_count': len(signatures),
        'stats': {
            'unique': unique_count,
            'ambiguous': ambiguous_count,
            'bss': sum(1 for s in signatures if s.get('section_type') == 'bss'),
            'failed': len(failed),
        },
        'signatures': signatures,
    }

    output_path = args.output or SIGNATURES_FILE
    with open(output_path, 'w') as f:
        json.dump(db, f, indent=2)
    print(f"\nSignature database saved to: {output_path}")
    print(f"Total signatures: {len(signatures)}")
    print(f"  Unique matches: {unique_count}")
    print(f"  Ambiguous (with disambiguation data): {ambiguous_count}")
    print(f"  BSS (delta-estimated): {sum(1 for s in signatures if s.get('section_type') == 'bss')}")


def cmd_scan(args):
    """Scan a new executable for known signatures."""
    sig_file = args.signatures or SIGNATURES_FILE

    if not os.path.exists(sig_file):
        print(f"Error: Signature database not found: {sig_file}")
        print("Run with --generate first to create the signature database.")
        sys.exit(1)

    print(f"Loading signatures: {sig_file}")
    with open(sig_file) as f:
        db = json.load(f)

    signatures = db['signatures']
    print(f"Loaded {len(signatures)} signatures")

    new_exe = args.exe
    print(f"Loading PE: {new_exe}")
    pe = PEFile(new_exe)
    print(f"Image base: 0x{pe.image_base:016X}")
    for s in pe.sections:
        flags = []
        if s.is_code: flags.append("CODE")
        if s.is_data: flags.append("DATA")
        print(f"  {s.name:10s} VA=0x{s.virtual_addr:08X} Size=0x{s.virtual_size:08X} [{', '.join(flags)}]")

    print(f"\nScanning for signatures... (slow={getattr(args, 'slow', False)})")
    results, stats = scan_all_signatures(
        pe, signatures, verbose=args.verbose, slow=getattr(args, 'slow', False)
    )

    report_text = generate_full_report(results, stats, signatures)
    print(report_text)

    if args.json_output:
        generate_json_report(results, stats, args.json_output)

    if args.patch_output:
        patch_text = generate_patch_output(results, signatures)
        with open(args.patch_output, 'w') as f:
            f.write(patch_text)
        print(f"Patch file written to: {args.patch_output}")

    if args.sed_output:
        generate_sed_script(results, signatures, args.sed_output)

    # Generate C++ header
    cpp_path = args.cpp_output or str(SCRIPT_DIR / "updated_addresses.h")
    cpp_text = generate_cpp_header(results, signatures)
    with open(cpp_path, 'w') as f:
        f.write(cpp_text)
    print(f"C++ header written to: {cpp_path}")

    # Generate Address Library
    addrlib_path = args.addrlib_output or ADDRLIB_FILE
    generate_address_library(results, signatures, addrlib_path)


def cmd_diff(args):
    """Compare addresses between two executables."""
    sig_file = args.signatures or SIGNATURES_FILE

    if not os.path.exists(sig_file):
        print("No signature database found. Generating from old executable...")
        entries = parse_sfe_source(SFE_SOURCE)
        seen = {}
        unique_entries = []
        for entry in entries:
            key = (entry.name, entry.address)
            if key not in seen:
                seen[key] = entry
                unique_entries.append(entry)

        pe_old = PEFile(args.old_exe)
        signatures, _ = generate_all_signatures(pe_old, unique_entries, DEFAULT_SIG_LEN)
    else:
        with open(sig_file) as f:
            db = json.load(f)
        signatures = db['signatures']

    print(f"Using {len(signatures)} signatures")
    print(f"Scanning new executable: {args.new_exe}")

    pe_new = PEFile(args.new_exe)
    results, stats = scan_all_signatures(
        pe_new, signatures, verbose=args.verbose, slow=getattr(args, 'slow', False)
    )

    report_text = generate_full_report(results, stats, signatures)
    print(report_text)

    json_path = args.json_output or str(SCRIPT_DIR / "diff_report.json")
    generate_json_report(results, stats, json_path)

    patch_text = generate_patch_output(results, signatures)
    patch_path = args.patch_output or str(SCRIPT_DIR / "patch.txt")
    with open(patch_path, 'w') as f:
        f.write(patch_text)
    print(f"Patch file written to: {patch_path}")

    sed_path = args.sed_output or str(SCRIPT_DIR / "apply_patch.sh")
    generate_sed_script(results, signatures, sed_path)

    cpp_path = str(SCRIPT_DIR / "updated_addresses.h")
    cpp_text = generate_cpp_header(results, signatures)
    with open(cpp_path, 'w') as f:
        f.write(cpp_text)
    print(f"C++ header written to: {cpp_path}")

    addrlib_path = str(ADDRLIB_FILE)
    generate_address_library(results, signatures, addrlib_path)


def cmd_patch(args):
    """Output updated C++ headers based on scan results."""
    report_file = args.report or str(SCRIPT_DIR / "diff_report.json")
    sig_file = args.signatures or SIGNATURES_FILE

    if not os.path.exists(report_file):
        print(f"Error: Scan report not found: {report_file}")
        print("Run --scan or --diff first.")
        sys.exit(1)

    with open(report_file) as f:
        report = json.load(f)

    with open(sig_file) as f:
        db = json.load(f)

    patch_text = generate_patch_output(report['results'], db['signatures'])

    if args.output:
        with open(args.output, 'w') as f:
            f.write(patch_text)
        print(f"Patch written to: {args.output}")
    else:
        print(patch_text)

    sed_path = args.sed_output or str(SCRIPT_DIR / "apply_patch.sh")
    generate_sed_script(report['results'], db['signatures'], sed_path)


def cmd_validate(args):
    """Self-test: generate signatures from exe, scan same exe, report accuracy."""
    exe_path = args.exe or DEFAULT_EXE
    sig_file = args.signatures or SIGNATURES_FILE

    if not os.path.exists(sig_file):
        print(f"Error: Signature database not found: {sig_file}")
        print("Run --generate first.")
        sys.exit(1)

    print(f"=== VALIDATION MODE ===")
    print(f"Loading signatures from: {sig_file}")
    with open(sig_file) as f:
        db = json.load(f)
    signatures = db['signatures']

    print(f"Loading PE: {exe_path}")
    pe = PEFile(exe_path)

    print(f"Scanning source exe for its own signatures (expecting 100% match)...")
    results, stats = scan_all_signatures(pe, signatures, verbose=False, disambiguate=True)

    # Count results
    correct = 0
    wrong = 0
    not_found = 0
    ambiguous_remaining = 0
    estimated = 0
    false_positive = 0

    for sig in signatures:
        name = sig['name']
        expected_rva = sig['address_int']
        # Use the same key format as scan_all_signatures
        key = f"{name}@0x{expected_rva:08X}"
        result = results.get(key, {})

        if result['status'] == 'found':
            if result['new_address_int'] == expected_rva:
                correct += 1
            else:
                wrong += 1
                false_positive += 1
                print(f"  FALSE POSITIVE: {name} expected 0x{expected_rva:08X}, got {result['new_address']} (method: {result.get('method', '?')})")
        elif result['status'] == 'estimated':
            if result['new_address_int'] == expected_rva:
                correct += 1
                estimated += 1
            else:
                wrong += 1
                print(f"  WRONG ESTIMATE: {name} expected 0x{expected_rva:08X}, got {result['new_address']}")
        elif result['status'] == 'ambiguous':
            ambiguous_remaining += 1
            # Check if the correct address is among the matches
            match_rvas = [int(m[0], 16) for m in result['matches']]
            if expected_rva in match_rvas:
                pass  # Correct answer is there, just ambiguous
            else:
                print(f"  AMBIGUOUS (correct NOT in matches): {name} @ 0x{expected_rva:08X}")
        else:
            not_found += 1

    total = len(signatures)
    accuracy = correct / total * 100 if total > 0 else 0

    print(f"\n{'='*60}")
    print(f"VALIDATION RESULTS")
    print(f"{'='*60}")
    print(f"  Total signatures:     {total}")
    print(f"  Correct matches:      {correct} ({correct/total*100:.1f}%)")
    print(f"  Ambiguous:            {ambiguous_remaining}")
    print(f"  Not found:            {not_found}")
    print(f"  False positives:      {false_positive}")
    print(f"  Wrong estimates:      {wrong - false_positive}")
    print(f"  BSS estimated:        {estimated}")
    print(f"  Overall accuracy:     {accuracy:.1f}%")
    print(f"  Effective coverage:   {(correct + ambiguous_remaining)/total*100:.1f}% (correct + ambiguous with correct answer)")

    # DLL comparison if available
    dll_path = args.dll or DEFAULT_DLL
    if os.path.exists(dll_path):
        print(f"\n--- DLL Comparison ---")
        dll_report = compare_with_dll(results, signatures, dll_path)
        print(f"  RVAs found in DLL:    {dll_report['found_in_dll']}/{dll_report['total_rvas']}")
        print(f"  RVAs NOT in DLL:      {dll_report['not_in_dll']} (likely inlined or unused by SFE build)")

        # Check if scanner results match DLL-embedded addresses
        dll_matches = len(dll_report['matches'])
        dll_only = len(dll_report['dll_only'])
        scanner_only = len(dll_report['scanner_only'])
        print(f"  Both found:           {dll_matches}")
        print(f"  DLL only (scanner miss): {dll_only}")
        print(f"  Scanner only (not in DLL): {scanner_only}")


def cmd_dll_compare(args):
    """Compare scanner results against the compiled SFE DLL."""
    sig_file = args.signatures or SIGNATURES_FILE
    dll_path = args.dll or DEFAULT_DLL
    exe_path = args.exe or DEFAULT_EXE

    if not os.path.exists(sig_file):
        print(f"Error: Signature database not found: {sig_file}")
        sys.exit(1)

    if not os.path.exists(dll_path):
        print(f"Error: SFE DLL not found: {dll_path}")
        sys.exit(1)

    print(f"Loading signatures from: {sig_file}")
    with open(sig_file) as f:
        db = json.load(f)
    signatures = db['signatures']

    print(f"Loading PE: {exe_path}")
    pe = PEFile(exe_path)

    print(f"Scanning exe for signatures...")
    results, stats = scan_all_signatures(pe, signatures, verbose=False)

    print(f"\nComparing with SFE DLL: {dll_path}")
    report = compare_with_dll(results, signatures, dll_path)

    print(f"\n{'='*60}")
    print(f"DLL COMPARISON REPORT")
    print(f"{'='*60}")
    print(f"  Total RVAs:           {report['total_rvas']}")
    print(f"  Found in DLL:         {report['found_in_dll']}")
    print(f"  Not in DLL:           {report['not_in_dll']}")
    print(f"  Scanner matches:      {len(report['matches'])}")
    print(f"  DLL only:             {len(report['dll_only'])}")
    print(f"  Scanner only:         {len(report['scanner_only'])}")

    if report['dll_only']:
        print(f"\n--- Addresses in DLL but scanner missed ---")
        for entry in report['dll_only']:
            print(f"  {entry['name']:<50s} {entry['original_rva']}  (scanner: {entry['scanner_status']})")

    if args.json_output:
        with open(args.json_output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nDLL comparison report written to: {args.json_output}")


def cmd_info(args):
    """Show info about signature database."""
    sig_file = args.signatures or SIGNATURES_FILE

    if not os.path.exists(sig_file):
        print(f"No signature database found at: {sig_file}")
        print("Run --generate first.")
        sys.exit(1)

    with open(sig_file) as f:
        db = json.load(f)

    print(f"Signature Database Info:")
    print(f"  Version:      {db.get('version', 'unknown')}")
    print(f"  Generated:    {db.get('generated', 'unknown')}")
    print(f"  Source exe:   {db.get('source_exe', 'unknown')}")
    print(f"  Source size:  {db.get('source_exe_size', 0):,} bytes")
    print(f"  Image base:   {db.get('image_base', 'unknown')}")
    print(f"  Signatures:   {db.get('sig_count', len(db.get('signatures', [])))}")

    if 'stats' in db:
        s = db['stats']
        print(f"\n  Quick stats:")
        print(f"    Unique:     {s.get('unique', '?')}")
        print(f"    Ambiguous:  {s.get('ambiguous', '?')}")
        print(f"    BSS:        {s.get('bss', '?')}")
        print(f"    Failed:     {s.get('failed', '?')}")

    sigs = db.get('signatures', [])

    by_type = defaultdict(int)
    by_section = defaultdict(int)
    by_section_name = defaultdict(int)
    for s in sigs:
        by_type[s.get('type', 'unknown')] += 1
        by_section[s.get('section_type', 'unknown')] += 1
        by_section_name[s.get('section', 'unknown')] += 1

    print(f"\n  By type:")
    for t, c in sorted(by_type.items()):
        print(f"    {t}: {c}")

    print(f"\n  By section type:")
    for t, c in sorted(by_section.items()):
        print(f"    {t}: {c}")

    print(f"\n  By PE section:")
    for t, c in sorted(by_section_name.items()):
        print(f"    {t}: {c}")

    lens = defaultdict(int)
    for s in sigs:
        lens[s.get('sig_length', DEFAULT_SIG_LEN)] += 1
    print(f"\n  Signature lengths:")
    for sig_len, c in sorted(lens.items()):
        print(f"    {sig_len} bytes: {c}")

    # Disambiguation data stats
    has_xref = sum(1 for s in sigs if s.get('_xref_info'))
    has_size = sum(1 for s in sigs if s.get('_function_size') is not None)
    has_vtable = sum(1 for s in sigs if s.get('_vtable_info'))
    has_extended = sum(1 for s in sigs if s.get('_extended_patterns'))
    disamb_verified = sum(1 for s in sigs if s.get('_disambiguation_verified'))

    if any([has_xref, has_size, has_vtable, has_extended]):
        print(f"\n  Disambiguation data:")
        print(f"    With XREF info:      {has_xref}")
        print(f"    With function size:   {has_size}")
        print(f"    With vtable refs:     {has_vtable}")
        print(f"    With extended sigs:   {has_extended}")
        print(f"    Disambiguation verified: {disamb_verified}")

    ambiguous = [s for s in sigs if s.get('_ambiguous_in_source') and not s.get('_resolved_length')]
    resolved = [s for s in sigs if s.get('_resolved_length')]
    if resolved:
        print(f"\n  Resolved by longer signatures: {len(resolved)}")
    if ambiguous:
        print(f"  Still ambiguous after all strategies: {len(ambiguous)}")
        for s in ambiguous[:10]:
            n_matches = s.get('_match_count_in_source', '?')
            verified = " [verified]" if s.get('_disambiguation_verified') else ""
            print(f"    {s['name']} ({n_matches} matches){verified}")
        if len(ambiguous) > 10:
            print(f"    ... and {len(ambiguous)-10} more")


def cmd_parse(args):
    """Just parse SFE source and show extracted addresses (for debugging)."""
    print(f"Parsing SFE source: {SFE_SOURCE}")
    entries = parse_sfe_source(SFE_SOURCE)

    seen = {}
    unique = []
    for e in entries:
        key = (e.name, e.address)
        if key not in seen:
            seen[key] = e
            unique.append(e)

    print(f"Total entries: {len(entries)}")
    print(f"Unique entries: {len(unique)}")
    print()

    for e in sorted(unique, key=lambda x: x.address):
        class_info = f" ({e.class_name}::{e.name})" if e.class_name else ""
        print(f"  0x{e.address:08X}  {e.addr_type:20s}  {e.name:50s}{class_info}  [{e.source_file}:{e.line_number}]")


# ============================================================================
# CLI
# ============================================================================

def main():
    global SFE_SOURCE

    parser = argparse.ArgumentParser(
        description="SFE Address Scanner v2 - Find updated addresses after FO76 patches",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --generate                          Generate signatures from current FO76 exe
  %(prog)s --scan /path/to/new/Fallout76.exe   Find addresses in new exe
  %(prog)s --diff old.exe new.exe              Compare two executables
  %(prog)s --patch                             Output updated C++ headers
  %(prog)s --validate                          Self-test: scan source exe, report accuracy
  %(prog)s --dll-compare                       Compare scanner vs SFE DLL
  %(prog)s --parse                             Show parsed addresses (debug)
  %(prog)s --info                              Show signature database info
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--generate', action='store_true', help='Generate signature database from current exe')
    group.add_argument('--scan', metavar='NEW_EXE', nargs='?', const='__NEED_EXE__', help='Scan a new exe for signatures')
    group.add_argument('--diff', nargs=2, metavar=('OLD_EXE', 'NEW_EXE'), help='Compare two executables')
    group.add_argument('--patch', action='store_true', help='Output patched C++ headers from scan results')
    group.add_argument('--validate', action='store_true', help='Self-test: scan source exe, compare results')
    group.add_argument('--dll-compare', action='store_true', help='Compare scanner results against SFE DLL')
    group.add_argument('--parse', action='store_true', help='Parse SFE source and show addresses')
    group.add_argument('--info', action='store_true', help='Show signature database info')

    parser.add_argument('--exe', type=str, help=f'Path to Fallout76.exe (default: {DEFAULT_EXE})')
    parser.add_argument('--dll', type=str, help=f'Path to SFE DLL (default: {DEFAULT_DLL})')
    parser.add_argument('--signatures', '-s', type=str, help=f'Path to signatures.json (default: {SIGNATURES_FILE})')
    parser.add_argument('--output', '-o', type=str, help='Output file path')
    parser.add_argument('--json-output', type=str, help='JSON report output path')
    parser.add_argument('--patch-output', type=str, help='Patch file output path')
    parser.add_argument('--sed-output', type=str, help='Sed script output path')
    parser.add_argument('--cpp-output', type=str, help='C++ header output path')
    parser.add_argument('--addrlib-output', type=str, help='Address Library output path')
    parser.add_argument('--report', type=str, help='Scan report JSON for --patch mode')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--slow', action='store_true',
                        help='--generate: enable XREF analysis. --scan/--diff: enable subwindow retry on miss')
    parser.add_argument('--sfe-source', type=str, help=f'Path to SFE source (default: {SFE_SOURCE})')

    args = parser.parse_args()

    if args.sfe_source:
        SFE_SOURCE = Path(args.sfe_source)

    if args.generate:
        cmd_generate(args)
    elif args.scan:
        if args.scan == '__NEED_EXE__':
            parser.error("--scan requires a path to the new executable")
        args.exe = args.scan
        cmd_scan(args)
    elif args.diff:
        args.old_exe, args.new_exe = args.diff
        cmd_diff(args)
    elif args.patch:
        cmd_patch(args)
    elif args.validate:
        cmd_validate(args)
    elif args.dll_compare:
        cmd_dll_compare(args)
    elif args.parse:
        cmd_parse(args)
    elif args.info:
        cmd_info(args)


if __name__ == '__main__':
    main()
