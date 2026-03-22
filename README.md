# fo76-sigscan

Byte pattern signature scanner for Fallout 76 on Linux. Finds function addresses in the running game process by scanning for known byte patterns in the `.text` section -- no DLL injection, no debugger, no game modifications.

Addresses shift with every game update. Signature scanning is version-independent: it matches function prologues instead of hardcoded offsets, so your tools keep working after patches.

## What it does

- **scanner.py** -- Linux scanner. Reads FO76 process memory via `/proc/PID/mem` and scans for 36 known function signatures across 7 categories (Scaleform/Papyrus VM, PlayerCharacter, Actor, TESDataHandler, ProcessLists, TESForm, Inventory/ActorValue). Reports the absolute address and RVA for each match.

- **scanner_windows.py** -- Windows scanner. Same patterns and scanning logic, but uses `kernel32.ReadProcessMemory` via ctypes instead of `/proc/PID/mem`. Discovers module base via `EnumProcessModulesEx` and process PID via `tasklist`. Includes a `--test` mode for verifying the memory reading pipeline against any running process. Zero external dependencies.

- **find_g_player.py** -- Finds the `g_player` global variable (a `PlayerCharacter*` pointer in `.data`) by scanning `.text` for RIP-relative `mov`/`lea` instructions that reference `.data` addresses, then verifying candidates by checking for FormID `0x14` and detecting player movement. Linux only.

All tools are **read-only** -- they never modify game memory.

## How it works

1. Find the Fallout76.exe process running under Proton/Wine
2. Open `/proc/PID/mem` and parse the PE section headers in-process
3. Read the `.text` section in chunks (16 MB default)
4. For each chunk, test every offset against all remaining patterns
5. Patterns use a mask string: `x` = byte must match exactly, `?` = wildcard (skip)
6. When a match is found, calculate the RVA: `address - image_base`
7. Results are cached by binary SHA-256 hash -- subsequent runs are instant until the game updates

Wildcard bytes are essential for patterns that contain RIP-relative displacements, since these change between builds even when the function itself is unchanged.

## Patterns (36 total)

### Scaleform / Papyrus VM (6)
| Pattern | Status |
|---------|--------|
| VirtualMachine::FindBoundObject | Confirmed 1.7.23.39 |
| VirtualMachine::DispatchMethodCallImpl | Confirmed 1.7.23.39 |
| ObjectInterface::AttachMovie | Confirmed 1.7.23.39 |
| ObjectInterface::InvokeClosure | Confirmed 1.7.23.39 |
| BSScaleformManager::LoadMovieDef | Untested on live |
| ObjectInterface::CreateEmptyMovieClip | Untested on live |

### Player Character (10)
| Pattern | Dev RVA |
|---------|---------|
| LocalPlayerCharacter::Update | 0x2A2F0EF |
| BasePlayerCharacter::Update | 0x1887AD2 |
| BasePlayerCharacter::SetGodMode | 0x188F61C |
| LocalPlayerCharacter::TeleportPlayer | 0x2A2CE8D |
| LocalPlayerCharacter::GetInventoryEncumbrance | 0x2A2D66D |
| LocalPlayerCharacter::CenterOnCell | 0x2A2DBBA |
| LocalPlayerCharacter::PreNetUpdate | 0x1AFDD75 |
| LocalPlayerCharacter::RequestNetworkAuthorityUpdate | 0x2A46D11 |
| LocalPlayerCharacter::ShouldWaitInLoadScreen | 0x2A53A52 |
| LocalPlayerCharacter::Reset3D | 0x29085B6 |

### Actor (9)
| Pattern | Dev RVA |
|---------|---------|
| Actor::Update | 0x28C8507 |
| Actor::IsDead | 0x28D7A2D |
| Actor::GetCurrentTarget | 0x28CF20A |
| Actor::SetCurrentTarget | 0x28CF3A1 |
| Actor::SetPosition | 0x289BBE8 |
| Actor::SetHeading | 0x28BB9E0 |
| Actor::GetControllingActor | 0x299448F |
| Actor::UpdateMagic | 0x2999839 |
| Actor::UpdateMinimal | 0x28CA6F4 |

### TESDataHandler (3)
| Pattern | Dev RVA |
|---------|---------|
| TESDataHandler::LoadForm | 0xCC265C |
| TESDataHandler::ConstructObject | 0xCD21FF |
| TESDataHandler::UnloadCell | 0xCC90E5 |

### ProcessLists (3)
| Pattern | Dev RVA |
|---------|---------|
| ProcessLists::UpdateClient | 0x2A98484 |
| ProcessLists::UpdateMagicEffects | 0x2AA1912 |
| ProcessLists::QueueActorTransformWithFootIKResults | 0x2AA04F0 |

### TESForm Lookup (2)
| Pattern | Dev RVA |
|---------|---------|
| TESForm::GetFormByEditorID | 0xD154AF |
| TESForm::GetFormByNumericID | 0xD15144 |

### Inventory / ActorValue / ActiveEffect (3)
| Pattern | Dev RVA |
|---------|---------|
| BGSInventoryList::AddEquipmentChange | 0xDA1E62 |
| ActorValuesSnapshotComponent::PostSerializeReadREFRJob | 0x260DF6B |
| ActiveEffectManager::ForEachActiveEffect | 0x24CD85C |

## g_player finder

The `find_g_player.py` tool locates the `g_localPlayer` global variable -- a static pointer in `.data` that holds the address of the local `PlayerCharacter` object. It works by:

1. Scanning `.text` for all RIP-relative `mov reg, [rip+disp32]` and `lea reg, [rip+disp32]` instructions targeting `.data`
2. Grouping targets by reference count (heavily-referenced globals are more interesting)
3. Following each pointer and checking for FormID `0x14` at offset `+0x38` (the player's form ID)
4. Performing a movement verification: read position twice with a 3-second delay while the player walks

The tool also discovers RTTI class name strings embedded in the binary, which helps identify vtable layouts.

## Requirements

- Python 3.8+
- No additional Python packages required (stdlib only)

### Linux (`scanner.py`)
- Reads `/proc/PID/mem` directly
- Fallout 76 running under Proton or Wine

### Windows (`scanner_windows.py`)
- Uses Win32 API (`kernel32.ReadProcessMemory`) via ctypes -- no external dependencies
- Fallout 76 running natively
- May need to run as Administrator for process access
- Includes `--test` mode to verify memory reading against any process (e.g. `explorer.exe`)

## Usage

### Linux

```bash
# Scan for all 36 function signatures
python3 scanner.py

# With verbose logging
python3 scanner.py -v

# Force rescan (ignore cache)
python3 scanner.py --no-cache

# Find g_player pointer (move your character during verification!)
python3 find_g_player.py
```

### Windows

```cmd
:: Scan for all 36 function signatures
python scanner_windows.py

:: With verbose logging
python scanner_windows.py -v

:: Force rescan (ignore cache)
python scanner_windows.py --no-cache

:: Test mode: verify memory reading works (no FO76 needed)
python scanner_windows.py --test
python scanner_windows.py --test notepad.exe
```

## Example output

```
Fallout 76 PID: 28451
Image base: 0x140000000

.text:  0x140001000 - 0x14468E000 (70.6 MB)
Patterns: 36

Address Scan Results:
  Image base: 0x140000000

  [OK] VirtualMachine::FindBoundObject: 0x142B5A3C2 (RVA +0x2B5A3C2)
  [OK] VirtualMachine::DispatchMethodCallImpl: 0x142B4F002 (RVA +0x2B4F002)
  [OK] ObjectInterface::AttachMovie: 0x142AEFB53 (RVA +0x2AEFB53)
  [OK] ObjectInterface::InvokeClosure: 0x142AF0B10 (RVA +0x2AF0B10)
  [OK] Actor::IsDead: 0x142CD7A2D (RVA +0x28D7A2D)
  ...
  [--] Actor::SetPosition: NOT FOUND

Found 32/36 patterns.
```

## How to add new patterns

1. Find your function in a disassembler (IDA, Ghidra, Binary Ninja, x64dbg)
2. Copy the first 16-28 bytes of the function prologue
3. Replace any bytes that encode RIP-relative offsets (typically bytes 3-6 in `lea`/`mov` instructions) with `\x00` and mark them as `?` in the mask
4. Add a `ScanPattern` entry to the `PATTERNS` list:

```python
ScanPattern(
    name="MyClass::MyFunction",
    pattern=b"\x48\x8b\xc4\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8d",
    mask="xxxxxxxxxxxxxxxx",
),
```

Tips:
- Use at least 16 bytes for unique matches in a 70+ MB `.text` section
- Patterns with `push` register sequences (`55 53 56 57 41 54...`) are very common -- add more bytes to disambiguate
- Test with `--no-cache` after adding patterns
- The `offset` field lets you point to the actual function entry if your pattern starts mid-instruction

## Cross-engine compatibility

These patterns are from the Creation Engine 2 (FO76). Since Fallout 4 and Skyrim SE/AE share the same engine lineage, many function signatures are similar or identical. With minor adjustments, this scanner could work for:

- Fallout 4 (Creation Engine 1)
- Skyrim Special Edition / Anniversary Edition
- Starfield (Creation Engine 2)

The Papyrus VM and Scaleform patterns in particular tend to be stable across Creation Engine games.

## How we tested it

Confirmed working on FO76 version 1.7.23.39 (The Backwoods update, March 2026):
- **VirtualMachine::FindBoundObject** -- matched at expected RVA
- **VirtualMachine::DispatchMethodCallImpl** -- matched
- **ObjectInterface::AttachMovie** -- matched
- **ObjectInterface::InvokeClosure** -- matched

The g_player finder successfully located the `g_localPlayer` RVA and verified it via movement detection (position at offset `+0xD0` changed when walking in-game, FormID confirmed as `0x14`).

## License

MIT -- see [LICENSE](LICENSE).
