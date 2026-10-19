#!/usr/bin/env python3
"""End-to-end test vless/vmess/trojan nodes from a Clash subscription via xray-core.

Download once:
    curl -L -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
    unzip -o xray.zip -d xray && chmod +x xray/xray

Usage:
    python3 xray_node_test.py <sub_url> [--limit 10] [--xray ./xray/xray] [--out ok.json]
"""
import argparse, json, ssl, subprocess, time, urllib.request

import yaml

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def fetch_sub(u, timeout=25):
    req = urllib.request.Request(u, headers={"User-Agent": "clash-verge/1.6.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
        return yaml.safe_load(r.read(4_000_000))


def stream(p):
    net = p.get("network") or "tcp"
    # trojan is TLS by definition: Clash omits tls:true for trojan nodes.
    tls = bool(p.get("tls")) or p.get("type") == "trojan"
    sni = p.get("servername") or p.get("sni") or p.get("server")
    ss = {"network": net, "security": "none"}
    if tls:
        ss["security"] = "tls"
        ss["tlsSettings"] = {"serverName": sni, "allowInsecure": True,
                             "fingerprint": p.get("client-fingerprint") or "chrome"}
    ro = p.get("reality-opts") or {}
    if ro.get("public-key"):
        ss["security"] = "reality"
        ss["realitySettings"] = {"serverName": sni, "publicKey": ro["public-key"],
                                 "shortId": ro.get("short-id", ""),
                                 "fingerprint": "chrome", "allowInsecure": True}
    if net == "ws":
        wo = p.get("ws-opts") or {}
        ss["wsSettings"] = {"path": wo.get("path", "/"), "headers": wo.get("headers") or {}}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": (p.get("grpc-opts") or {}).get("grpc-service-name", "")}
    return ss


def outbound(p):
    t = p.get("type")
    if t == "vless":
        return {"protocol": "vless", "settings": {"vnext": [{
            "address": p["server"], "port": int(p["port"]),
            "users": [{"id": p["uuid"], "encryption": "none", "flow": p.get("flow", "")}]}]},
            "streamSettings": stream(p)}
    if t == "vmess":
        return {"protocol": "vmess", "settings": {"vnext": [{
            "address": p["server"], "port": int(p["port"]),
            "users": [{"id": p["uuid"], "alterId": int(p.get("alterId", 0)),
                       "security": p.get("cipher") or "auto"}]}]},
            "streamSettings": stream(p)}
    if t == "trojan":
        return {"protocol": "trojan", "settings": {"servers": [{
            "address": p["server"], "port": int(p["port"]), "password": p["password"]}]},
            "streamSettings": stream(p)}
    return None


def test_node(p, idx, xray, timeout=8):
    ob = outbound(p)
    if not ob:
        return None
    port = 20000 + idx
    cfg = {"log": {"loglevel": "error"},
           "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                         "settings": {"udp": False}}],
           "outbounds": [ob]}
    path = f"/tmp/xr_{idx}.json"
    json.dump(cfg, open(path, "w"))
    proc = subprocess.Popen([xray, "run", "-c", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        r = subprocess.run(["curl", "-sS", "--max-time", str(timeout), "--proxy",
                            f"socks5h://127.0.0.1:{port}",
                            "https://api.ipify.org?format=json"],
                           capture_output=True, text=True, timeout=timeout + 4)
        if r.returncode == 0 and r.stdout.strip().startswith("{"):
            return {"type": p.get("type"), "net": p.get("network"),
                    "server": f"{p['server']}:{p['port']}", "name": p.get("name"),
                    "exit": json.loads(r.stdout.strip())}
    except Exception:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(3)
        except Exception:
            proc.kill()
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--xray", default="./xray/xray")
    ap.add_argument("--out", default="xray_ok.json")
    a = ap.parse_args()

    cfg = fetch_sub(a.url)
    nodes = [p for p in (cfg.get("proxies") or []) if isinstance(p, dict)]
    cands = [p for p in nodes if p.get("type") in ("vless", "vmess", "trojan")][: a.limit]
    print(f"nodes={len(nodes)} testing={len(cands)}")

    ok = []
    for i, p in enumerate(cands):
        r = test_node(p, i, a.xray)
        if r:
            ok.append(r)
            print("OK", r["type"], r["net"], r["server"], r["exit"], "|", str(r["name"])[:40])
        else:
            print("..", p.get("type"), p.get("network"),
                  f"{p.get('server')}:{p.get('port')}", "|", str(p.get("name"))[:40])

    json.dump(ok, open(a.out, "w"), ensure_ascii=False, indent=1)
    print(f"working={len(ok)}/{len(cands)} -> {a.out}")


if __name__ == "__main__":
    main()
