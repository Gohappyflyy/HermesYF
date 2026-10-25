#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""集群巡检：一条命令看所有节点是否还在干活。

背景：批量扫描/撞库分发到多台后，"进程还在不在、产物有没有在涨" 靠人反复问，
一问就断，一断就白跑。这个脚本把巡检变成一条命令。

用法
  python3 fleet_watch.py                          # 单次快照（进程 + 产物 + 负载）
  python3 fleet_watch.py -p masscan               # 只看跑 masscan 的节点
  python3 fleet_watch.py -p python3 -d /root/out  # 盯 python3 + 产物目录
  python3 fleet_watch.py --watch 300              # 每 300 秒采一次，判增长，异常才打印
  python3 fleet_watch.py --json                   # 机读

退出码：0 正常；1 有异常节点（可直接给 cronjob 当告警条件）
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

FLEET = Path("/root/pentest/fleet2/fleet.csv")


def load_nodes() -> list[dict]:
    if not FLEET.is_file():
        return []
    rows = []
    lines = FLEET.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        return []
    head = lines[0].split(",")
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split(",")
        parts += [""] * (len(head) - len(parts))
        row = dict(zip(head, parts))
        if row.get("status", "").strip() not in ("", "ready"):
            continue
        rows.append(row)
    return rows


REMOTE = r"""
echo "LOAD $(cut -d' ' -f1-3 /proc/loadavg)"
echo "UPTIME $(cut -d' ' -f1 /proc/uptime)"
if [ -n "{pattern}" ]; then echo "PROCS $(pgrep -fc '{pattern}' 2>/dev/null || echo 0)"; else echo "PROCS -"; fi
if [ -n "{dir}" ] && [ -d "{dir}" ]; then
  echo "FILES $(find {dir} -type f 2>/dev/null | wc -l)"
  echo "BYTES $(du -sb {dir} 2>/dev/null | cut -f1)"
else
  echo "FILES -"; echo "BYTES -"
fi
echo "DISK $(df -P / | awk 'NR==2{print $5}')"
"""


def probe(node: dict, pattern: str, outdir: str) -> dict:
    ip = node.get("ip", "")
    res = {"ip": ip, "region": node.get("region", ""), "ok": False}
    if not ip:
        return res
    # 只有密钥机可以自动巡检；密码机没有本地凭据，跳过而不是报异常
    if (node.get("auth") or "").strip() == "password":
        res["skip"] = "无密钥（auth=password），需手工 sshpass"
        return res
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6",
           "-o", "StrictHostKeyChecking=no", f"root@{ip}",
           REMOTE.replace("{pattern}", pattern or "").replace("{dir}", outdir or "")]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if p.returncode != 0:
            res["error"] = (p.stderr or "").strip().splitlines()[-1][:80] if p.stderr else "ssh failed"
            return res
        for line in p.stdout.splitlines():
            key, _, val = line.partition(" ")
            if key == "LOAD":
                res["load"] = val.strip()
            elif key == "PROCS":
                res["procs"] = int(val) if val.strip().isdigit() else -1
            elif key == "FILES":
                res["files"] = -1 if val.strip() == "-" else int(val)
            elif key == "BYTES":
                res["bytes"] = -1 if val.strip() == "-" else int(val)
            elif key == "DISK":
                res["disk"] = val.strip()
        res["ok"] = True
    except subprocess.TimeoutExpired:
        res["error"] = "timeout 20s"
    except Exception as exc:
        res["error"] = f"{type(exc).__name__}"
    return res


def verdict(r: dict, pattern: str, outdir: str) -> list[str]:
    bad = []
    if r.get("skip"):
        return []
    if not r.get("ok"):
        bad.append(f"连接失败({r.get('error')})")
        return bad
    load1 = float((r.get("load") or "0 0 0").split()[0] or 0)
    cores = int(r.get("_cores") or 0)
    if cores and load1 > cores * 1.5:
        bad.append(f"负载 {load1:.1f} > {cores}核×1.5")
    if pattern and r.get("procs") == 0:
        bad.append(f"没有 '{pattern}' 进程")
    if outdir and r.get("files") == 0:
        bad.append("产物目录为空")
    try:
        if int((r.get("disk") or "0%").rstrip("%")) >= 92:
            bad.append(f"磁盘 {r['disk']}")
    except ValueError:
        pass
    return bad


def fmt(r: dict) -> str:
    if r.get("skip"):
        return f"{r['ip']:<16} – {r['skip']}"
    if not r.get("ok"):
        return f"{r['ip']:<16} ✗ {r.get('error', '')}"
    return (f"{r['ip']:<16} load {r.get('load','-'):<14} procs {r.get('procs','-'):<4} "
            f"files {r.get('files','-'):<6} size {r.get('bytes',0):>12,}  disk {r.get('disk','-')}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--pattern", default="", help="要盯的进程名（pgrep -f）")
    ap.add_argument("-d", "--dir", default="", help="产物目录（看文件数和总字节）")
    ap.add_argument("--watch", type=int, default=0, help="每 N 秒采一次，判断增长，只在异常或变化时打印")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    nodes = load_nodes()
    if not nodes:
        print(f"没有节点清单: {FLEET}")
        return 1
    for n in nodes:
        try:
            n["_cores"] = int(n.get("cores") or 0)
        except ValueError:
            n["_cores"] = 0

    if not args.watch:
        rows = [probe(n, args.pattern, args.dir) for n in nodes]
        for r in rows:
            bad = verdict(r, args.pattern, args.dir)
            line = fmt(r)
            print(line + (("   ⚠ " + "; ".join(bad)) if bad else ""))
        abnormal = [r for r in rows if verdict(r, args.pattern, args.dir)]
        if args.json:
            print(json.dumps({"rows": rows, "abnormal": [r["ip"] for r in abnormal]},
                             ensure_ascii=False, indent=1))
        else:
            print(f"\n{len(rows)-len(abnormal)}/{len(rows)} 正常"
                  + (f"，异常: {', '.join(r['ip'] for r in abnormal)}" if abnormal else ""))
        return 1 if abnormal else 0

    # 周期巡检：只报异常和产物停滞
    prev: dict[str, int] = {}
    print(f"巡检每 {args.watch}s 一次（Ctrl-C 结束）")
    while True:
        rows = [probe(n, args.pattern, args.dir) for n in nodes]
        alerts = []
        for r, n in zip(rows, nodes):
            bad = verdict(r, args.pattern, args.dir)
            cur = r.get("bytes")
            if n["ip"] in prev and isinstance(cur, int) and cur >= 0 and prev[n["ip"]] >= 0:
                if cur == prev[n["ip"]] and args.dir:
                    bad.append(f"产物 {args.watch}s 无增长")
            if isinstance(cur, int) and cur >= 0:
                prev[n["ip"]] = cur
            if bad:
                alerts.append(f"  {r['ip']:<16} ⚠ " + "; ".join(bad))
        stamp = time.strftime("%H:%M:%S")
        if alerts:
            print(f"[{stamp}] 异常 {len(alerts)} 台")
            print("\n".join(alerts))
        else:
            print(f"[{stamp}] 全部正常")
        sys.stdout.flush()
        time.sleep(args.watch)


if __name__ == "__main__":
    raise SystemExit(main())
