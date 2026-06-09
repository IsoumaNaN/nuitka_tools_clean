# IDAPython — map a Nuitka module's functions to source order.
# Run via:  python ida.py py_exec_file '{"file_path":"C:/.../map_module.py"}'
# Edit MODULE_STR below to the module name (e.g. "gui.utils.url_parser").
#
# How it works (the Nuitka layout, MinGW/MSVC, PE32+):
#   * Each Python function compiles to its own C function (stripped -> sub_XXXX).
#   * The module-name C-string is xref'd from exactly one function = the MODULE BODY.
#   * The function impls live in one .text cluster next to the module body, laid out
#     in SOURCE ORDER (== the qualname order in modules/<m>.constants.txt).
#   * Uniform ~272-byte functions interleaved are runtime global-lookup stubs (version-
#     cached module-dict lookups) — NOT Python functions; excluded here.
#   * The "make compiled function" helper (one shared addr, e.g. sub_143B4E2B0) is called
#     once per top-level def by the unpacker; this script flags the likely unpacker.
import idaapi, idautils, idc, ida_bytes, ida_funcs, ida_segment

MODULE_STR = "gui.utils.url_parser"   # <-- EDIT ME
SPAN       = 0x8000                    # search window around the module body
STUB_SIZE  = 272                       # runtime lookup-helper size (sample-dependent; verify)

def find_cstrings(text):
    pat = text.encode() + b"\x00"
    lo, hi = idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea()
    res, ea = [], lo
    while ea < hi:
        f = ida_bytes.find_bytes(pat, ea)
        if f == idaapi.BADADDR:
            break
        if f == 0 or ida_bytes.get_byte(f - 1) == 0:
            res.append(f)
        ea = f + 1
    return res

def fstart(ea):
    fn = ida_funcs.get_func(ea)
    return fn.start_ea if fn else None

# 1) module body = function holding an xref to the module-name C-string
anchors = set()
for sea in find_cstrings(MODULE_STR):
    for xr in idautils.XrefsTo(sea, 0):
        s = fstart(xr.frm)
        if s:
            anchors.add(s)
if not anchors:
    print("NO anchor for %r — check the exact module name string." % MODULE_STR)
else:
    body = max(anchors)
    print("MODULE BODY: 0x%x   (anchors: %s)" % (body, [hex(a) for a in anchors]))

    # 2) gather functions in a window around the body, in address (source) order
    LO, HI = body - SPAN, body + SPAN
    ea, rows = LO, []
    while ea < HI:
        fn = ida_funcs.get_func(ea)
        if fn:
            if not rows or rows[-1][0] != fn.start_ea:
                rows.append((fn.start_ea, fn.end_ea - fn.start_ea))
            ea = fn.end_ea
        else:
            ea = idc.next_head(ea, HI)

    # 3) flag the unpacker: the function that calls one shared .text target >=3 times
    def shared_call_target(fa):
        f = ida_funcs.get_func(fa)
        if not f:
            return (None, 0)
        cnt = {}
        for h in idautils.Heads(f.start_ea, f.end_ea):
            if idc.print_insn_mnem(h) == "call":
                t = idc.get_operand_value(h, 0)
                s = ida_segment.getseg(t)
                if s and ida_segment.get_segm_name(s) == ".text":
                    cnt[t] = cnt.get(t, 0) + 1
        if not cnt:
            return (None, 0)
        best = max(cnt, key=cnt.get)
        return (best, cnt[best])

    print("functions in window (source order; stubs & unpacker flagged):")
    for a, sz in rows:
        tag = ""
        if a == body:
            tag = "  <= MODULE BODY"
        elif sz == STUB_SIZE:
            tag = "  (runtime lookup stub)"
        else:
            tgt, n = shared_call_target(a)
            if n >= 3:
                tag = "  <= UNPACKER? (calls 0x%x x%d = MAKE_FUNCTION helper)" % (tgt, n)
        print("  0x%x  size=%-6d%s" % (a, sz, tag))

    print("\nNext: the non-stub impls between the unpacker and the module body map 1:1,")
    print("in order, to the method/function qualnames in modules/<module>.constants.txt.")
    print("Decompile each with:  python dc.py 0x<addr>")
