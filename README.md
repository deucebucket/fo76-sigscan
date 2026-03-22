# FO76 Signature Scanner

Byte pattern scanner for Fallout 76 on Linux (Proton/Wine). Finds function addresses across game updates without hardcoded offsets.

Reads the game's `.text` section directly from `/proc/PID/mem` — no DLL injection, no debugger, completely invisible to the game.

## Quick Start

```bash
# 1. Launch Fallout 76 through Steam (Proton)
# 2. Wait until you're fully loaded into the game world

# 3. Clone this repo
git clone https://github.com/deucebucket/fo76-sigscan.git
cd fo76-sigscan

# 4. Run the scanner
python3 scanner.py

# 5. Results print to terminal and cache to scan_cache.json
```

## What It Does

Every time Bethesda patches Fallout 76, all memory addresses shift. Mods and tools that use hardcoded offsets break instantly. This scanner uses **byte patterns** (signatures) to find functions by their unique instruction sequences, which stay the same across patches.

Think of it like finding a person by their fingerprint instead of their home address — the fingerprint doesn't change when they move.

## How It Works

1. Finds the FO76 process via `pgrep`
2. Reads `/proc/PID/maps` to locate the PE image sections
3. Verifies the image base by checking for the MZ/PE headers
4. Reads the `.text` section (executable code, ~63MB)
5. Scans for byte patterns using wildcard masks
6. Calculates RVAs (Relative Virtual Addresses) from the image base
7. Caches results keyed by SHA-256 of the binary's first 4096 bytes

## Example Output

```
F76 Address Scanner
==================================================
Found FO76 PID: 349049
Image base: 0x140000000

Scanning 63.1 MB of .text section...

Results (4/36 patterns matched):
  VirtualMachine::FindBoundObject     RVA: 0x065AA40   ✓
  VirtualMachine::DispatchMethodCall  RVA: 0x2DB9D30   ✓
  ObjectInterface::AttachMovie        RVA: 0x0ED1720   ✓
  ObjectInterface::InvokeClosure      RVA: 0x272F500   ✓

Scan completed in 18.2 seconds
Results cached to scan_cache.json
```

## Pattern Format

Patterns use bytes + mask. `x` = must match exactly, `?` = wildcard (any byte):

```python
PATTERNS = {
    "FunctionName": SigPattern(
        bytes=b"\x48\x83\x7C\x24\x40\x00\x74\x00\x48\x8B",
        mask= "xxxxxx?x??",
        description="What this function does"
    ),
}
```

## Adding New Patterns

1. Find a function in the binary using a disassembler (Ghidra, IDA, x64dbg)
2. Copy the first 10-20 bytes of unique instructions
3. Mark variable bytes (addresses, offsets) as `?` in the mask
4. Add to the `PATTERNS` dict in `scanner.py`
5. Test by running the scanner

**Tips:**
- Use bytes from the function prologue (most stable across versions)
- Avoid bytes that contain relocatable addresses (they change)
- Include enough bytes to be unique (10+ is usually good)
- Test against multiple game versions if possible

## Included Patterns (36 total)

The scanner ships with patterns for:

**Scaleform/UI:**
- `ObjectInterface::AttachMovie` — SWF movie loading
- `ObjectInterface::InvokeClosure` — ActionScript callbacks
- `ObjectInterface::HasMember` — Property checking

**Papyrus VM:**
- `VirtualMachine::FindBoundObject` — Script object lookup
- `VirtualMachine::DispatchMethodCallImpl` — Method dispatch

**Game References:**
- Various internal functions for object lookup and management

**Confirmed on FO76 version 1.7.23.39 ("The Backwoods" patch, March 2026):**
4 out of 36 patterns verified on the live binary.

## Also Included: g_player Finder

`find_g_player.py` locates the player character pointer by:
1. Scanning `.text` for RIP-relative `mov` instructions referencing `.data`
2. Following pointer chains from `.data` to heap objects
3. Validating via RTTI (Run-Time Type Information) vtable chain
4. Confirming the `LocalPlayerCharacter` class via type descriptor string

## Compatibility

- **Fallout 76** — primary target
- **Fallout 4** — same engine, many patterns should work (untested)
- **Skyrim SE** — similar engine architecture (patterns need adaptation)

## Requirements

- Python 3.6+
- Linux with Fallout 76 running under Proton/Wine
- Same user as the game process (for `/proc/PID/mem` access)
- No root/sudo needed (unless `ptrace_scope` is restricted)

## Troubleshooting

**"No Fallout76 process found"**
- Make sure the game is fully loaded (past the login screen, in the world)
- The scanner looks for processes with >1GB RSS to find the main game process

**"Permission denied on /proc/PID/mem"**
- Must run as the same user that launched the game
- Check: `cat /proc/sys/kernel/yama/ptrace_scope` — if it's `1`, you may need `sudo sysctl kernel.yama.ptrace_scope=0`

**"0 patterns matched"**
- Patterns may need updating for a new game version
- The binary changed enough that existing signatures no longer match
- Try updating patterns from a fresh disassembly

**Scan takes too long**
- First scan reads ~63MB of code, takes 15-20 seconds
- Results are cached — subsequent runs are instant until the binary changes

## How We Tested

Developed and tested on:
- Bazzite 43 (Fedora immutable, NVIDIA)
- Proton 10.0
- FO76 version 1.7.23.39 ("The Backwoods")
- AMD Ryzen 7 5800XT, 64GB RAM

The scanner successfully found 4 function addresses on the current binary and was used to locate the `g_localPlayer` global pointer (RVA 0x6051E88) which had shifted from its previous known location after the Backwoods update.

## Contributing

Contributions welcome! Especially:
- New patterns from FO4/Skyrim reverse engineering
- Pattern validation across different game versions
- Windows support (reading process memory via Win32 API)
- Documentation of what each found function does

## License

MIT
