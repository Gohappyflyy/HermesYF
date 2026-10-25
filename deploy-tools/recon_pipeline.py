#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""信息收集流水线：一条命令跑完 子域 → 存活 → 指纹 → 端口。

为什么要有这个：以前"先收集信息"是一句提示，模型每次凭记忆拼命令，顺序和参数都不稳定，
产物散在各处，下次还要重新拼。这里把顺序、去重、归档、契约登记全部钉死。

用法
  python3 recon_pipeline.py -d example.com                          # 子域+存活+指纹
  python3 recon_pipeline.py -d example.com --ports                  # 再加端口扫描（top100）
  python3 recon_pipeline.py -d example.com --contract <契约.json>    # 产物自动登记进任务契约
  python3 recon_pipeline.py -d example.com --skip-sub   # 已经有一批子域时跳过 subfinder

产物（默认 /root/apks/recon/<domain>/）
  subs.txt       subfinder 原始输出
  hosts.txt      去重后的全部主机（含主域）
  live.jsonl     httpx 逐行 JSON（状态码/标题/技术栈/CDN）
  live.txt       存活 URL 清单
  tech.txt       技术栈汇总（出现次数排序）
  ports.txt      端口（--ports 时）
  summary.json   统计 + 生成时间 + 工具版本

全部走 mihomo（默认 127.0.0.1:7890），可用 --proxy 覆盖，--no-proxy 关掉。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

GOBIN = Path("/root/go/bin")


def tool(name: str) -> str | None:
    p = shutil.which(name) or (str(GOBIN / name) if (GOBIN / name).exists() else None)
    return p


def run(cmd: list[str], timeout: int, env: dict | None = None, quiet: bool = True) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, **(env or {})})
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout {timeout}s"
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-d", "--domain", required=True)
    ap.add_argument("-o", "--out", default="")
    ap.add_argument("--contract", default="")
    ap.add_argument("--ports", action="store_true", help="跑 naabu top100")
    ap.add_argument("--skip-sub", action="store_true", help="跳过 subfinder（已有 subs.txt 时）")
    ap.add_argument("--proxy", default="http://127.0.0.1:7890")
    ap.add_argument("--socks5", default="", help="naabu 专用 socks5（如 socks5://127.0.0.1:7891）；不给则 --ports 拒绝执行")
    ap.add_argument("--no-proxy", action="store_true")
    ap.add_argument("--timeout", type=int, default=600, help="单步超时秒")
    args = ap.parse_args()

    domain = args.domain.strip().rstrip(".")
    outdir = Path(args.out or f"/root/apks/recon/{domain}")
    outdir.mkdir(parents=True, exist_ok=True)
    proxy = "" if args.no_proxy else args.proxy

    summary: dict = {"domain": domain, "started": datetime.now().isoformat(timespec="seconds"),
                     "steps": {}, "tools": {}, "errors": []}
    errors: list[str] = summary["errors"]

    def fail(msg: str) -> None:
        errors.append(msg)
        print(f"  !! {msg}")

    def note(step: str, **kw):
        summary["steps"][step] = kw
        print(f"  [{step}] " + "  ".join(f"{k}={v}" for k, v in kw.items()))

    print(f"=== recon {domain} → {outdir} ===")

    # 1. 子域
    subs: list[str] = []
    subs_file = outdir / "subs.txt"
    if not args.skip_sub:
        sf = tool("subfinder")
        if not sf:
            fail("subfinder 缺失，跳过子域枚举（后续只有主域）")
            note("subdomains", count=0, error="subfinder missing")
        else:
            env = {"HTTPS_PROXY": proxy, "HTTP_PROXY": proxy} if proxy else {}
            rc, so, se = run([sf, "-d", domain, "-all", "-silent", "-timeout", "10"], args.timeout, env)
            subs = sorted({l.strip().lower() for l in so.splitlines() if l.strip()})
            subs_file.write_text("\n".join(subs) + ("\n" if subs else ""), encoding="utf-8")
            if rc != 0:
                fail(f"subfinder 退出码 {rc}: {se.strip().splitlines()[-1][:80] if se.strip() else ''}")
            note("subdomains", count=len(subs), rc=rc, err=se.strip().splitlines()[-1][:80] if se.strip() else "")
    elif subs_file.is_file():
        subs = [l.strip() for l in subs_file.read_text(encoding="utf-8").splitlines() if l.strip()]
        note("subdomains", count=len(subs), source="cached")

    hosts = sorted(set(subs) | {domain})
    (outdir / "hosts.txt").write_text("\n".join(hosts) + "\n", encoding="utf-8")
    note("hosts", total=len(hosts))

    # 2/3. 存活 + 指纹
    hx = tool("httpx")
    live: list[dict] = []
    if not hx:
        fail("httpx 缺失，无法做存活探测")
        note("live", count=0, error="httpx missing")
    else:
        cmd = [hx, "-l", str(outdir / "hosts.txt"), "-silent", "-json",
               "-status-code", "-title", "-tech-detect", "-ip", "-cname",
               "-threads", "50", "-timeout", "8", "-retries", "1"]
        if proxy:
            cmd += ["-http-proxy", proxy]
        rc, so, se = run(cmd, args.timeout)
        for line in so.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                live.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        (outdir / "live.jsonl").write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in live),
                                           encoding="utf-8")
        urls = sorted({x.get("url") or x.get("input", "") for x in live if x.get("url") or x.get("input")})
        (outdir / "live.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
        tech = Counter()
        for x in live:
            for t in (x.get("tech") or []):
                tech[t] += 1
        (outdir / "tech.txt").write_text(
            "\n".join(f"{t}\t{n}" for t, n in tech.most_common()) + ("\n" if tech else ""), encoding="utf-8")
        codes = Counter(str(x.get("status_code")) for x in live)
        if rc != 0:
            fail(f"httpx 退出码 {rc}: {se.strip().splitlines()[-1][:80] if se.strip() else ''}")
        elif not live:
            fail("httpx 没有任何存活结果（0 行）—— 可能全站挂了，也可能参数/代理不对")
        note("live", count=len(live), codes=dict(codes.most_common(6)),
             techs=len(tech), rc=rc,
             err=se.strip().splitlines()[-1][:80] if se.strip() else "")

    # 4. 端口（可选）
    if args.ports:
        nb = tool("naabu")
        if not nb:
            fail("naabu 缺失，跳过端口扫描")
            note("ports", error="naabu missing")
        elif not args.socks5:
            # 以前把 http://…:7890 硬替换成 socks5://…:7891，纯靠猜端口：
            # 自定义代理时映射错、7891 没监听时 naabu 可能裸连。
            fail("--ports 需要显式 --socks5（不猜端口映射），已跳过端口扫描")
            note("ports", error="socks5 not specified")
        else:
            cmd = [nb, "-list", str(outdir / "hosts.txt"), "-top-ports", "100", "-silent",
                   "-rate", "500", "-timeout", "1500"]
            cmd += ["-proxy", args.socks5]
            rc, so, se = run(cmd, args.timeout)
            (outdir / "ports.txt").write_text(so, encoding="utf-8")
            note("ports", lines=len(so.splitlines()), rc=rc,
                 err=se.strip().splitlines()[-1][:80] if se.strip() else "")

    # 5. 收尾
    summary["finished"] = datetime.now().isoformat(timespec="seconds")
    for t in ("subfinder", "httpx", "nuclei", "naabu"):
        p = tool(t)
        if p:
            rc, so, _ = run([p, "-version"], 10)
            summary["tools"][t] = (so.splitlines()[0][:60] if so else "installed")
    (outdir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"\n产物目录 {outdir}")
    for f in sorted(outdir.iterdir()):
        print(f"  {f.name:<14} {f.stat().st_size:>10,} B")
    if errors:
        print(f"\n!! {len(errors)} 个错误（侦察不完整，不要当成已完成）")
        for e in errors:
            print("   -", e)

    # 6. 登记进任务契约（可选）
    if args.contract:
        repo = os.environ.get("HERMESYF_REPO", "/root/HermesYF")
        registered, failed_reg = 0, []
        for f in ("live.jsonl", "live.txt", "tech.txt", "hosts.txt", "summary.json"):
            fp = outdir / f
            if not fp.is_file():
                continue
            pr = subprocess.run([sys.executable, "-m", "yf_tools.task_contract", "evidence",
                                 args.contract, "--path", str(fp), "--kind", "recon"],
                                cwd=repo, capture_output=True, text=True, timeout=30)
            if pr.returncode == 0:
                registered += 1
            else:
                failed_reg.append(f"{f}: {(pr.stderr or '').strip()[:80]}")
        if failed_reg:
            fail("契约登记失败: " + "; ".join(failed_reg))
            print(f"登记 {registered} 个，失败 {len(failed_reg)} 个")
        else:
            print(f"已登记进契约（{registered} 个文件）: {args.contract}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
