---
name: nuitka-reverse
description: >-
  Reverse-engineer and reconstruct readable Python source from a Nuitka-compiled PE
  (Windows .exe/.dll) after it has been dumped. Use when asked to "restructure/rebuild/
  reconstruct a Nuitka tool back to Python", map a stripped C function (sub_XXXX) to its
  Python function/method, ground reconstructed logic against the binary via IDA Pro (Hex-Rays
  over the IDA-MCP), recover per-function signatures/control-flow, identify vendored
  open-source packages, or test a reconstructed app. Companion to the `nuitka-dump` skill
  (which extracts the constants blob); this skill is the dump -> source workflow, including
  the module-string-xref + source-order-cluster recipe that maps a constant to the C
  function that implements it.
---

# Nuitka reverse & reconstruct (dump → runnable Python)

`nuitka-dump` gets you the **constants** (`modules/<m>.constants.txt`). This skill turns
those into **faithful, runnable Python**, and grounds the uncertain parts against the binary
in IDA. Read `nuitka-dump`'s SKILL.md first if you haven't dumped yet.

Bundled tooling (in `scripts/` next to this file): `ida.py` (IDA-MCP client), `dc.py`
(decompile + auto-fetch truncated bodies), `map_module.py` (IDAPython function mapper).

## Mental model (what survives compilation)

Nuitka compiles Python → C → native PE. Consequences:

1. **App modules have NO bytecode** — they are generated C functions, stripped to `sub_XXXX`.
   You cannot decompile them back to Python with uncompyle/pycdc.
2. **The bundled CPython stdlib usually DOES survive as real bytecode** (`.pyc`, marshal). In a
   dump these are generically named (`bytecode_NNNN_module.pyc`) — check `co_filename`; they're
   `Lib/` (`_pyrepl`, `_pydecimal`, …), **not the app**. The pyc magic tells you the Python
   version (e.g. `a7 0d 0d 0a` = 3.11) — match your test interpreter to it.
3. **All app constants live in a per-module `mod_consts[]`** array, deserialized at startup.
   Compiled code reads `mod_consts[i]`, never the `.rdata` bytes directly — so a naive
   "xref this string" lands on the unpacker, not the user.

### The constant stream is far more than strings — it's the reconstruction blueprint

`modules/<m>.constants.txt` is emitted **in source order** for generated code (class bodies,
setup functions). Each entry is `INDEX  TYPE  VALUE`. It encodes, verbatim:

- module docstring, imports (module names + `tuple` import lists), class names & bases
- every method/function **qualname** (`URLParser.detect_platform`) → the full def inventory
- **type-annotation descriptors** as `dict` consts (`{'return':{'type':'builtin_named','name':'str'}}`)
- default values, and all string/number/dict/tuple/set/slice literals
- **per-function local-variable name tuples** near the end — the *first* names are the
  parameters (self/cls + args), the rest are locals **in allocation order**. This pins down
  signatures AND strongly constrains the body (which names get built, in what order).

Because of all this, a from-constants reconstruction is usually **correct on
literals/signatures/structure/UI and highly constrained on logic** — IDA mostly *confirms* it.

## Step 1 — reconstruct from constants

For each module, read the whole `.constants.txt`, then write the `.py`:
- docstring, imports, classes (with bases) and decorators (infer `property`/`<name>.setter`/
  `classmethod`/`staticmethod` from qualname siblings).
- each function: signature from its local-var tuple + annotation dicts + default consts;
  body reconstructed from the strings/calls/attrs in const order (linear code — UI setup,
  config I/O, dict building, dataclasses — is near-verbatim).
- **Match names, literals, regexes, SQL, docstrings EXACTLY.** Only the control-flow glue
  (if/for/try nesting, branch order, clamp bounds) is inferred — mark genuinely ambiguous
  spots with a short `# inferred` comment, don't scatter TODOs.

Fan out across modules with subagents when the app is large — give each the rubric above, the
target constant files, and 2–3 finished modules as a style reference. **Watch for cross-module
naming drift** (one agent calls a method `add_log`, another calls it `add_entry`) — Step 4 and
testing catch these.

### Identify vendored open-source packages
Bilingual docstrings, recognizable class names, or a familiar tree often mean a third-party
package was vendored in. Match it to upstream (git clone) and copy the real source instead of
reconstructing it — then reconstruct only the app's *additions* (diff the dumped module list
against upstream). Pin dep versions to the era of the build (see Step 5).

## Step 2 — ground the logic in IDA (the core recipe)

Load the binary in IDA Pro with the IDA-MCP plugin (serves `http://127.0.0.1:13337/mcp`).
Confirm: `python scripts/ida.py server_health '{}'` → `hexrays_ready: true`.

**Map a Python function → its C address** (functions are stripped, so use the layout):

1. Edit `MODULE_STR` in `scripts/map_module.py`, then run it in IDA:
   `python scripts/ida.py py_exec_file '{"file_path":".../scripts/map_module.py"}'`
2. It finds the **module body** (the one function holding an xref to the module-name C-string),
   lists the `.text` functions around it in **address = source order**, and flags:
   - uniform ~272-byte functions = **runtime global-lookup stubs** (skip them), and
   - the **unpacker** = the function calling one shared `.text` target ≥3× (Nuitka's
     "make-compiled-function" helper, one fixed address per build, e.g. `sub_143B4E2B0`).
3. The non-stub impls between the unpacker and the module body map **1:1, in order**, to the
   method/function qualnames in `constants.txt`. (e.g. `URLParser`'s 18 methods were the 18
   functions `0x141769a20…0x141773b50` in qualname order.)
4. Decompile each: `python scripts/dc.py 0x<addr>` — it follows the `_download_url` for large
   functions (the MCP truncates >~1KB) and writes the full body to `dc_out.txt`; Read/Grep that
   file for specific line ranges (avoids Windows shell `|`/`()` quoting pain).

**Reading Nuitka's decompiled C** — landmarks that cut through the runtime soup:
- `sub_…30300(obj, "oooo", a, b, c, d)` — a build/format helper; the `"oooo"` arg-shape string
  literally counts the object args (4 here). A 5-part fingerprint join shows as `"ooooo"`.
- `if (*v >= 0) { v8 = (*v)-- == 1; if (v8) (**(...+48))(v); }` everywhere = refcount DECREF;
  ignore it. The version-cached `mov / cmp dword_X / sub_…326F0` pattern = a module-dict lookup.
- Integer literals you care about (clamps, sizes) appear as plain immediates — e.g. `v=12`
  next to a `sha256`/exception block confirmed `max(12, min(length, 32))`.
- The local-var allocation order from `constants.txt` tells you what each `vN` *is*; match the
  sequence (e.g. `…payload_bytes, app_id_tok, pub_b64, sig, token_dev, exp_utc_dt` = parse →
  signature → device-check → expiry order).

Ground the functions where **inference could be wrong AND it matters** (crypto/license/auth,
orchestration, parsing). UI-construction code is already exact from const order — don't waste
decompiler time confirming it. Apply real corrections (e.g. a constant that's a function-local,
not a module global).

## Step 3 — test the reconstruction (finds the real bugs)

1. Use the interpreter matching the pyc magic (Step 0). `pip install -r requirements.txt`.
2. **Import smoke test**: walk the tree, `importlib.import_module` each, print failures. Catches
   missing module-level names (cross-module drift), missing vendored files, dep gaps.
3. **Launch harness** for a GUI: monkeypatch the blocking gate (login dialog, etc.) to return a
   fake-valid result, construct the main window, `app.update()`, assert it built (tab count…),
   then `after(800, destroy)` + `mainloop()`. On Windows set
   `sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")` or
   emoji UI text raises `UnicodeEncodeError` in the harness (not an app bug).

**Dependency-era gotchas:** vendored deps were frozen at build time. Classic break:
`httpx.AsyncClient(proxies=...)` was removed in httpx ≥ 0.28 → pin `httpx==0.27.2`. If a crawler
loads a `config.yaml` at import and the app added a sub-package, create the matching config.

## Tooling reference (scripts/)

| script | runs where | does |
|---|---|---|
| `ida.py <tool> '<json>'` | host shell | one IDA-MCP JSON-RPC call; unwraps SSE/structuredContent |
| `dc.py <addr> [regex]` | host shell | decompile, auto-fetch truncated body → `dc_out.txt`, optional grep |
| `map_module.py` | inside IDA (`py_exec_file`) | module body + source-order impl cluster, flags stubs/unpacker |

Useful MCP tools: `server_health`, `decompile {addr}`, `disasm {addr}`, `lookup_funcs {queries:[…]}`,
`xrefs_to`, `get_bytes`, `get_string`, `py_exec_file {file_path}` (forward-slash paths).

## Gotchas

- **`lookup_funcs` needs `queries` (plural).** Stripped binaries have no Nuitka names — don't
  expect `detect_platform` to resolve; map via the layout recipe.
- **Base pointers are runtime-filled (0 in the file)** — don't validate a `mod_consts` base by
  its pointed-to value; identify functions by the layout, not by dereferencing slots statically.
- **Module body can sit in the middle of its cluster**, and unpackers may split MAKE_FUNCTION
  calls across helpers — use `map_module.py`'s window + flags, then sanity-check the count
  against the qualname count in `constants.txt`.
- **Windows shell mangles `python -c`, inline `|`/`()` in args, and JSON** — write IDAPython to a
  `.py` and run via `py_exec_file`; Read/Grep `dc_out.txt` instead of piping decompiler output.
- **Only N label/string constants for M>N widgets** = the app reuses them; exact reuse may be
  under-determined by constants (decompile the setup fn if it matters; usually cosmetic).

## Scope
Static RE / source reconstruction / artifact recovery for analysis of a tool you may run. Same
boundary as `nuitka-dump`: reconstruct and document; do not assemble a runnable operational
payload/sender out of a dumped network-abuse tool.
