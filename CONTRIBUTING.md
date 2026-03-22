# Contributing

Contributions are welcome, especially new signature patterns from Fallout 4, Skyrim, or Starfield reverse engineering work.

## Adding patterns

The most valuable contributions are new `ScanPattern` entries. Here is how to create one:

### 1. Find the function

Use IDA Pro, Ghidra, Binary Ninja, or x64dbg to locate the function in a Creation Engine binary. Good sources:

- Address Library databases (FO4, Skyrim SE/AE have mature databases)
- F4SE / SKSE / SFSE source code (function signatures are documented)
- Community RE work (Server76, CommonLibF4, CommonLibSSE, CommonLibSF)

### 2. Extract the prologue bytes

Copy the first 16-28 bytes of the function. Function prologues typically start with register saves and stack frame setup:

```
push rbp         ; 55
push rbx         ; 53
push rsi         ; 56
push rdi         ; 57
sub rsp, 30h     ; 48 83 EC 30
```

### 3. Identify variable bytes

Some bytes change between game versions even when the function is otherwise identical:

- **RIP-relative displacements** (4 bytes after `lea`/`mov` with ModR/M byte `0x05`/`0x0D`/etc.)
- **Conditional jump offsets** (can shift when surrounding code changes)
- **Struct member offsets** (may change if the struct layout is modified)

Mark these bytes as wildcards (`?` in the mask, `\x00` in the pattern).

### 4. Test uniqueness

A good pattern should match exactly once in the ~70 MB `.text` section. If your pattern is too short or too generic, it will produce false positives. Guidelines:

- 2-3 byte patterns will match thousands of times (only useful for very rare sequences)
- 16 bytes is usually enough for a unique match
- 28 bytes is needed when the prologue is a common push sequence

### 5. Submit a PR

Add your pattern to the `PATTERNS` list in `scanner.py` with:

- A descriptive `name` (format: `ClassName::FunctionName`)
- The `pattern` bytes
- The `mask` string
- A comment with the known RVA from a reference binary
- Which game(s) you tested it on

## Pattern format reference

```python
ScanPattern(
    name="ClassName::FunctionName",
    # Raw bytes of the function prologue
    pattern=b"\x48\x8b\xc4\x55\x56\x57\x41\x54",
    # x = must match, ? = wildcard
    mask="xxxxxxxx",
    # Optional: offset from match to actual function start
    offset=0,
),
```

## Code style

- Python 3.8+ compatible (no walrus operator, etc.)
- No external dependencies (stdlib only)
- Type hints where practical
- Descriptive variable names

## Testing

Before submitting, run the scanner against a live game process to verify your patterns match (or at least do not cause errors):

```bash
python3 scanner.py --no-cache -v
```

## Scope

This project is a **read-only analysis tool**. Contributions that add memory writing, process injection, or game modification capabilities will not be accepted.
