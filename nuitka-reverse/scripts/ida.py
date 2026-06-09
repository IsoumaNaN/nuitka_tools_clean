#!/usr/bin/env python3
"""Tiny IDA-MCP JSON-RPC client.

Usage:  python ida.py <tool> '<json-args>'
Example: python ida.py server_health '{}'
         python ida.py decompile '{"addr":"0x141769a20"}'
         python ida.py py_exec_file '{"file_path":"C:/tmp/script.py"}'

The IDA Pro MCP plugin serves JSON-RPC at http://127.0.0.1:13337/mcp (default).
Responses may be SSE-framed; large outputs are truncated with a _download_url.
Pass file paths with forward slashes to avoid Windows backslash mangling.
"""
import json, sys, urllib.request

URL = "http://127.0.0.1:13337/mcp"

def call(tool, args):
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": tool, "arguments": args}}
    req = urllib.request.Request(
        URL, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"})
    raw = urllib.request.urlopen(req, timeout=120).read().decode("utf-8", "replace")
    if raw.lstrip().startswith("event:") or "\ndata:" in raw:
        for line in raw.splitlines():
            if line.startswith("data:"):
                raw = line[5:].strip()
                break
    try:
        obj = json.loads(raw)
    except Exception:
        return raw
    res = obj.get("result", obj)
    if isinstance(res, dict):
        if "structuredContent" in res:
            return res["structuredContent"]
        c = res.get("content")
        if isinstance(c, list):
            texts = [b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text"]
            joined = "\n".join(texts)
            try:
                return json.loads(joined)
            except Exception:
                return joined
    return res

if __name__ == "__main__":
    tool = sys.argv[1]
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    out = call(tool, args)
    print(json.dumps(out, indent=2, ensure_ascii=False) if not isinstance(out, str) else out)
