---
name: nuitka-dump
description: >-
  Dump and statically reverse-engineer Nuitka-compiled PE files (Windows .exe/.dll).
  Use when asked to unpack/dump/analyze a Nuitka binary, extract its constants blob,
  recover per-module constants/strings, or do static RE of a Nuitka backend in IDA —
  including the mod_consts[] indirection trick that maps a constant string to the C
  function that uses it. Covers onefile and backend, MinGW and MSVC, resource-ID-3,
  in-section linked blobs, and KAY-magic onefile payloads.
---

# Nuitka dump & static reversing

Toolset (text-only skill; the scripts live in a Git repo, this just drives them):

- **Repo (canonical):** https://github.com/IsoumaNaN/nuitka_tools_clean
- **Local checkout on this machine:** `D:\XData\Python\nuitka_tools_clean`
- Entry points: `nuitka_auto_export.py` (one-click), `dump.py` (blob only), `read_constant_blob.py` (parse a blob file)
- Deps: `pip install pefile zstandard`
- Run scripts **from the repo dir** (`nuitka_auto_export.py` imports `dump.py` + `read_constant_blob.py` from alongside it).

**Locate the repo before running:** if the local checkout above exists, use it. Otherwise clone it into a scratch dir and use that:

```
git clone https://github.com/IsoumaNaN/nuitka_tools_clean
pip install -r nuitka_tools_clean/requirements.txt
```

Then `cd` into the checkout (or call scripts with its full path) for all commands below.

## Core mental model (read this first)

Nuitka **compiles Python to C**, then to a native PE. Consequences that trip up reversers:

1. There is usually **no Python bytecode** to decompile. Functions are generated C functions. `.pyc`/marshal recovery mostly yields nothing — don't expect uncompyle6 to work.
2. All Python **constants** (strings, tuples, dict keys, names) are stored as a serialized **constants blob**, deserialized at startup into a per-module pointer array `mod_consts[]` in `.bss`/`.data`.
3. The compiled code references `mod_consts[index]`, **never the `.rdata` bytes directly**. So a naive "xref this string" in IDA lands on the blob *unpacker*, not the function that uses it. Resolving `index → slot → function` is the key technique (below).
4. The blob is **plaintext** — string/IOC scanning finds everything; the value-add of dumping is the **per-module structure + constant indices**, not just the raw strings.

## Step 1 — one-click dump

```
python nuitka_auto_export.py <target.exe|target.dll> -o <outdir>
```

This auto-detects and handles all of:
- onefile wrapper with `RT_RCDATA` ID 27 payload
- onefile wrapper with in-section **`KAY`+zstd** payload (no resource, no overlay)
- backend PE with `RT_RCDATA` ID 3 constant blob
- backend PE with the blob **linked into `.rdata`** (modern MinGW builds; anchored by the `.bytecode` top-level section, generic fallback otherwise)
- rejects non-Nuitka PEs in the payload (validates a carve actually parses as constants)

Useful flags: `--blob-format auto|fixed|legacy` (try `auto` first; old samples need `legacy`), `--onefile-only`, `--no-redact`.

Read the run summary: `Mode` (onefile/backend), `Blob format`, `Backends` (should be **1** real backend), `Modules` (count of parsed module sections). If `Backends` is large or `Modules` is 0, something's wrong — see Troubleshooting.

## Step 2 — read the output

In `<outdir>`:

- `modules/<module>.constants.txt` — **the prize**: each module's constants in original order, prefixed by 4-digit index. The app module is usually `__main__` (⚠ the exporter's `safe_name()` strips leading/trailing `_`, so `__main__` is written as **`main.constants.txt`**).
- `strings_by_section.json` — deduped strings per module (fast IOC sweep, scoped by module).
- `code_objects.json` — recovered code-object metadata (names, line, kind).
- `blob_summary.json` / `export_manifest.json` — section table, sizes, `constant_blob_method` (`resource_id3` vs `rdata_section_carve`), parse errors.
- `payload/extracted/` — for onefile: the unpacked files (the real backend is typically `main.dll`).
- `ida/ida_nuitka_helper.py` — generated string→xref helper (limited by the indirection; prefer Step 3).

To find where a constant lives: `grep` the module's `.constants.txt` for the string; the **4-digit prefix is its `mod_consts` index**.

## Step 3 — static reversing in IDA: resolve `constant index → function`

This is the technique that actually answers "which function builds/uses string X". Because of the indirection, you map: module-name C-string → module init function → `lea mod_consts` base → `slot = base + index*8` → code xrefs to that slot.

Run this in IDA (Alt+F7 → Script file), or drive it over the IDA-MCP if available. Set `MODULE` and `TARGET_INDEX` (the 4-digit index from `modules/<module>.constants.txt`):

```python
# IDAPython — find the function(s) that use mod_consts[TARGET_INDEX] of MODULE
import idaapi, idautils, idc, ida_bytes, ida_funcs, ida_segment
MODULE, TARGET_INDEX, PTR = "__main__", 413, 8   # PTR=8 for PE32+

def find_cstrings(text):
    pat = text.encode() + b"\x00"
    lo, hi = idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea()
    blob = ida_bytes.get_bytes(lo, hi - lo) or b""
    out, i = [], 0
    while True:
        i = blob.find(pat, i)
        if i < 0: break
        if i == 0 or blob[i-1] == 0: out.append(lo + i)
        i += 1
    return out

def func_of(ea):
    f = ida_funcs.get_func(ea); return f.start_ea if f else idaapi.BADADDR

def lea_targets(fea):
    f = ida_funcs.get_func(fea); t = []
    if f:
        for h in idautils.Heads(f.start_ea, f.end_ea):
            if idc.print_insn_mnem(h) == "lea":
                op = idc.get_operand_value(h, 1)
                if op and op != idaapi.BADADDR: t.append(op)
    return t

def writable(addr):
    for nm in (".bss", ".data"):
        s = ida_segment.get_segm_by_name(nm)
        if s and s.start_ea <= addr < s.end_ea: return True
    return False

inits = set()
for nea in find_cstrings(MODULE):
    for xr in idautils.XrefsTo(nea, 0):
        ff = func_of(xr.frm)
        if ff != idaapi.BADADDR: inits.add(ff)

for fea in inits:
    for base in sorted(set(lea_targets(fea))):
        if not writable(base): continue
        slot = base + TARGET_INDEX * PTR
        users = {}
        for xr in idautils.XrefsTo(slot, 0):
            users.setdefault(func_of(xr.frm), []).append(xr.frm)
        if users:
            print("mod_consts base 0x%x  slot[%d]=0x%x (init 0x%x)" % (base, TARGET_INDEX, slot, fea))
            for uf, sites in users.items():
                print("  USED BY %s 0x%x at %s" % (idc.get_func_name(uf), uf, [hex(s) for s in sites]))
```

If the init heuristic finds no slot xref, fall back: brute-scan every `.bss` pointer-array base, compute `base+TARGET_INDEX*8`, and keep the base whose users also touch other known app strings.

## Troubleshooting / gotchas

- **`Modules: 0` but `Backends: 1`** → the carve grabbed a non-app blob (often a onefile bootstrapper's own constants). Confirm `Mode` is `onefile` not `backend`; if the input is a onefile but ran as backend, the payload wasn't detected — check for `KAY` (compressed) or `KAX` (uncompressed) signature manually.
- **`Backends` large (dozens)** → false-positive carves on non-Nuitka PEs. The current tool validates carves; if you see this, the validation threshold may need raising — only the real backend (large blob, dozens of module sections) is genuine.
- **Parse errors / wrong values** → try `--blob-format legacy` (and `fixed`). `auto` picks the format with fewest errors but can be fooled.
- **No `.pyc`/marshal output** → expected; Nuitka compiled to C. The `.bytecode` top-level section is the only marshal region and usually just loader stubs.
- **Uncompressed onefile with no resource ID 27** → `KAX`-magic in-section payloads are not auto-located yet (KAX is collision-prone); extract manually by finding the `KAX` header and parsing `utf16-name / u64-size / [crc] / data` entries.
- **HWID/license `hexdigest`** is for device hashing, not request signing — don't confuse it with body signing.

## Scope

Static analysis / artifact extraction / IOC + structure recovery for defensive RE. This is **not** for reconstructing a runnable client from a dumped network-abuse tool — dump, document, and map; do not assemble the operational payload/sender.
