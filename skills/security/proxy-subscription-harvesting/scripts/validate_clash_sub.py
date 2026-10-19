#!/usr/bin/env python3
"""Fetch a Clash subscription, TCP-screen every node, then end-to-end test
socks5/http nodes by actually proxying a request through them.

Usage:
    python3 validate_clash_sub.py <sub_url> [--workers 30] [--out result.json]
"""
import argparse, json, socket, ssl, subprocess, sys, urllib.request
from concurrent.futures import ThreadPoolExecutor

import yaml

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = "clash-verge/1.6.0"


def fetch(url, timeout=25, limit=4_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
        return r.read(limit)


def parse_sub(body):
    cfg = yaml.safe_load(body)
    if not isinstance(cfg, dict):
        return []
    return [p for p in (cfg.get("proxies") or [])
            if isinstance(p, dict) and p.get("server") and p.get("port")]


def tcp_probe(p, timeout=3):
    try:
        with socket.create_connection((str(p["server"]), int(p["port"])), timeout=timeout):
            return True
    except Exception:
        return False


def e2e_probe(p, timeout=8):
    """Only for socks5/http nodes: real request through the proxy."""
    t = p.get("type")
    if t not in ("socks5", "http"):
        return None
    host, port = str(p["server"]), int(p["port"])
    user = p.get("username") or p.get("user") or ""
    pw = p.get("password") or ""
    auth = f"{user}:{pw}@" if user else ""
    # socks5h => DNS resolved by the proxy, not locally
    proxy = (f"socks5h://{auth}{host}:{port}" if t == "socks5"
             else f"http://{auth}{host}:{port}")
    cmd = ["curl", "-sS", "--max-time", str(timeout), "--proxy", proxy,
           "https://api.ipify.org?format=json"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 4)
        if r.returncode == 0 and r.stdout.strip().startswith("{"):
            return json.loads(r.stdout.strip())
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--workers", type=int, default=30)
    ap.add_argument("--out", default="sub_validation.json")
    a = ap.parse_args()

    proxies = parse_sub(fetch(a.url))
    if not proxies:
        print("NOT A SUBSCRIPTION: no proxies list parsed", file=sys.stderr)
        sys.exit(2)

    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        alive = list(ex.map(tcp_probe, proxies))

    socks_http = [p for p, ok in zip(proxies, alive) if ok and p.get("type") in ("socks5", "http")]
    print(f"nodes={len(proxies)} tcp_alive={sum(alive)} testable={len(socks_http)}")

    working = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        for p, res in zip(socks_http, ex.map(e2e_probe, socks_http)):
            if res:
                working.append({"type": p["type"],
                                "server": f"{p['server']}:{p['port']}",
                                "name": p.get("name"), "exit": res})
                print("OK", p["type"], p["server"], p["port"], "->", res)

    summary = {"url": a.url, "nodes": len(proxies), "tcp_alive": sum(alive),
               "e2e_tested": len(socks_http), "e2e_working": working}
    json.dump(summary, open(a.out, "w"), ensure_ascii=False, indent=1)
    print(f"working={len(working)} -> {a.out}")


if __name__ == "__main__":
    main()
