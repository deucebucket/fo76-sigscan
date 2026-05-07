# Address Auto-Update Pipeline

These tools rebuild a `name → retail_rva` address library against any
post-patch `Fallout76.exe`. They turn a one-time RE effort (the dev build
analysis) into a self-updating mapping that survives Bethesda's patches.

## What's here

| File | Purpose |
|---|---|
| `wildcard_scanner.py` | Multi-strategy byte-signature scanner. Reads `data/dev_build_signatures.json` (5,408 named functions captured from the dev build of FO76) and finds them in current retail via prefix matching, aggressive masks, and interior subsequence matching. |
| `vtable_mapper.py` | RTTI vtable cross-mapper. Loads the dev exe and current retail, matches classes by mangled RTTI name, then maps every vtable slot. Adds ~10,000 `match_type: vtable` entries to the address library. |
| `rtti_resolver.py` | Stand-alone RTTI walker (stdlib only). Enumerates every TypeDescriptor / COL / vtable in any PE; verifies internal consistency via `--selftest`; dumps a complete RTTI map via `--dump-classes`. Useful for verification, manual RE, and as a smoke test for the other two. |
| `sfe_scanner.py` | Legacy 293-entry SFE-specific signature scanner (extended in this version with `0x0F`-prefix / VEX / EVEX mask support). Subsumed by `wildcard_scanner` for general use; kept for SFE-DLL compat. |

## Inputs

| File | What |
|---|---|
| `data/dev_build_signatures.json` | 5,408 named functions with byte signatures, captured from `Project76Profile.exe` (the FO76 dev build leaked Jan 2024). Each entry: `name → {dev_rva, dev_va, signature, sig_length}`. |
| `data/signatures.json` | Smaller 293-entry SFE-specific signatures. |
| `data/address_library.json` | **Output** — `name → retail_rva` for the current build. Regenerate by running the pipeline. |
| `data/address_library_vtable_matches.json` | Vtable-only subset of the library (~10K entries). |

## Pipeline (run after every game patch)

```bash
# 1. Wildcard scanner: 5,408 dev sigs → retail RVAs (prefix/aggressive/interior)
python3 tools/wildcard_scanner.py
# -> updates data/address_library.json

# 2. Vtable mapper: dev classes → retail classes via RTTI, fill vtable slots
python3 tools/vtable_mapper.py
# -> +10K vtable entries merged into data/address_library.json

# 3. (optional) Smoke-test the new exe's RTTI integrity
python3 tools/rtti_resolver.py --selftest
```

End result: `data/address_library.json` with ~10,000+ named functions
resolved to current-retail RVAs. Sample entry:

```json
{
  "Actor::AddPerk": {
    "dev_rva": 38566090,
    "retail_rva": 24698128,
    "match_type": "vtable",
    "class": "Actor"
  }
}
```

## Configuring paths

Each script has hardcoded paths near the top. Edit them for your environment:

```python
RETAIL_EXE = Path("/home/USER/.steam/steam/steamapps/common/Fallout76/Fallout76.exe")
DEV_PATH   = Path("/path/to/Project76Profile.exe")  # optional, vtable_mapper only
```

The dev build (`Project76Profile.exe`) is required for `vtable_mapper.py`
but optional for `wildcard_scanner.py` (which uses pre-extracted
`dev_build_signatures.json`).

## Smoke test results (post-Apr-28 2026 build)

- 28,753 RTTI typedescriptors enumerated in retail
- 100% of resolved vtable slots land in `.text`
- 7/7 `Actor[1..7]` ↔ `TESForm[1..7]` inheritance slots match (consistency check)
- 13,598 RTTI classes matched dev↔retail by mangled name
- 10,743 named functions in `address_library.json` after a full pipeline run

## Why this beats hand-maintained byte signatures

The Linux `scanner.py` in this repo's root has 36 hand-tuned signatures
that reverse-engineered for FO76 v1.7.23.39. Updating them by hand for
every patch is hours of work each time. This pipeline:

- Uses 5,408 signatures derived once from the dev build
- Adds ~10,000 RTTI vtable mappings deterministically (slot indices are stable across patches)
- Fully regenerates the address library in a few minutes
- Validates results via x64 prologue / `.text` containment / inheritance consistency

Combined, they're the actual auto-updater.
