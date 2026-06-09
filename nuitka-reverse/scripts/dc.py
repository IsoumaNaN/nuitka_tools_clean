#!/usr/bin/env python3
"""Decompile a function via the IDA-MCP and optionally filter lines.

Usage:  python dc.py <addr> [regex]
  python dc.py 0x141769a20                 # full decompile -> dc_out.txt + stdout
  python dc.py 0x141769a20 "sha256|join"   # only matching lines (Windows: avoid | in cmd,
                                           #   quote it, or grep dc_out.txt instead)

Handles the MCP's truncation: large functions return a _download_url, which this
follows automatically to fetch the full body. Writes full code to dc_out.txt so you
can Read/Grep specific line ranges without shell-pipe quoting headaches.
"""
import sys, subprocess, json, re, os, urllib.request

here = os.path.dirname(os.path.abspath(__file__))

def ida(tool, args):
    p = subprocess.run([sys.executable, os.path.join(here, "ida.py"), tool, json.dumps(args)],
                       capture_output=True, text=True)
    try:
        return json.loads(p.stdout)
    except Exception:
        return {"_raw": p.stdout, "_err": p.stderr}

def main():
    addr = sys.argv[1]
    pat = sys.argv[2] if len(sys.argv) > 2 else None
    d = ida("decompile", {"addr": addr})
    code = d.get("code", "")
    if d.get("_output_truncated") or d.get("_download_url"):
        url = d.get("_download_url")
        if url:
            raw = urllib.request.urlopen(url, timeout=60).read().decode("utf-8", "replace")
            try:
                full = json.loads(raw)
                code = full.get("code") or full.get("content") or full.get("text") or code
            except Exception:
                code = raw
    out = os.path.join(os.getcwd(), "dc_out.txt")
    open(out, "w", encoding="utf-8").write(code)
    lines = code.splitlines()
    print("addr %s  total_lines=%d  (full -> %s)" % (addr, len(lines), out))
    if pat:
        rx = re.compile(pat, re.I)
        for i, l in enumerate(lines):
            if rx.search(l):
                print("%4d: %s" % (i, l.strip()))

if __name__ == "__main__":
    main()
