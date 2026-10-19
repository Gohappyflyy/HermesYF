#!/usr/bin/env python3
"""Build a minimal importable Clash config from verified-working nodes.

Usage:
    python3 build_clash_yaml.py <sub_url> <verified.json> [--out working_nodes.yaml]

<verified.json> is the --out of validate_clash_sub.py (uses e2e_working)
or a bare list of {"server": "ip:port"} entries.
"""
import argparse, json, ssl, urllib.request

import yaml

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def fetch_sub(u):
    req = urllib.request.Request(u, headers={"User-Agent": "clash-verge/1.6.0"})
    with urllib.request.urlopen(req, timeout=25, context=CTX) as r:
        return yaml.safe_load(r.read(4_000_000))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("verified")
    ap.add_argument("--out", default="working_nodes.yaml")
    a = ap.parse_args()

    data = json.load(open(a.verified))
    rows = data.get("e2e_working", data) if isinstance(data, dict) else data
    wanted = {r["server"] for r in rows if isinstance(r, dict) and r.get("server")}

    cfg = fetch_sub(a.url)
    keep = []
    for p in cfg.get("proxies") or []:
        if not isinstance(p, dict):
            continue
        if f"{p.get('server')}:{p.get('port')}" in wanted:
            keep.append({k: v for k, v in p.items() if k != "region"})

    if not keep:
        raise SystemExit("no verified node matched the subscription")

    names = [p["name"] for p in keep]
    out = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": keep,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": names},
            {"name": "AUTO", "type": "url-test", "proxies": names,
             "url": "http://www.gstatic.com/generate_204", "interval": 300},
        ],
        "rules": ["MATCH,PROXY"],
    }
    yaml.safe_dump(out, open(a.out, "w"), allow_unicode=True, sort_keys=False)
    print(f"wrote {a.out} nodes={len(keep)}")


if __name__ == "__main__":
    main()
