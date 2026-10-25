#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""任务收尾：审计本次任务的全部产物，关键归档、中间压缩、废弃清理。

风哥确认任务完成后跑这个。默认 dry-run，看清清单再 --apply。

分类规则（可改下面的表）
  KEEP     报告 / 订阅 / 账号本 / PoC 与提取脚本 —— 原样归档，永不自动删
  ARCHIVE  中间产物（原始 jsonl、列表 txt、扫描输出）—— 归档并压缩
  DROP     空文件 / 日志 / 临时 / 缓存 / 备份 —— 清理

产物去向
  /root/apks/archive/<目标>/<YYYY-MM-DD>/
      ├── keep/           关键产物（保留原名）
      ├── raw.tar.gz      中间产物打包
      └── closeout.json   本次收尾清单（含 sha256）

用法
  python3 task_closeout.py --contract <契约.json> --workdir /root/apks/recon/<目标>
  python3 task_closeout.py --workdir <目录> --apply          # 真删（确认清单后）
  python3 task_closeout.py --workdir <目录> --target x.com --apply

安全
  - 默认 dry-run，只打印不移动不删除
  - DROP 必须命中规则；没命中规则的未知文件一律保留并提示
  - 归档用复制 + 哈希核对，核对通过才动原文件
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import shutil
import tarfile
import time
from pathlib import Path

ARCHIVE_ROOT = Path("/root/apks/archive")

KEEP_PATTERNS = [
    "*.md", "*.pdf", "*.html", "*.htm",            # 报告
    "*.yml", "*.yaml",                              # 订阅 / 配置
    "*access*.mp4",                                 # 截图录像（如有）
]
KEEP_NAME_HINTS = [
    "report", "报告", "account", "accounts", "hits", "hits_", "subs",
    "poc", "exploit", "extract", "spider", "payload", "index",
]
ARCHIVE_PATTERNS = ["*.jsonl", "*.ndjson", "*.csv", "*.txt", "*.xml", "*.json", "*.db"]
DROP_PATTERNS = [
    "*.log", "*.tmp", "*.temp", "*.bak", "*.swp", "*.pyc", "*.pyo", "*.err",
    "*.retry", "*.lock", ".DS_Store", "Thumbs.db",
]
DROP_DIRS = ["__pycache__", ".pytest_cache", ".mypy_cache", "node_modules"]


def sha256(p: Path, limit: int = 64 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
            if limit and h.digest_size and fh.tell() > limit:
                break
    return h.hexdigest()


def classify(p: Path) -> str:
    name = p.name
    low = name.lower()
    if p.is_dir():
        return "DROP" if name in DROP_DIRS else "KEEP"
    try:
        if p.stat().st_size == 0:
            return "DROP"
    except OSError:
        return "KEEP"
    if any(fnmatch.fnmatch(low, pat) for pat in DROP_PATTERNS):
        return "DROP"
    if any(h in low for h in KEEP_NAME_HINTS):
        return "KEEP"
    if any(fnmatch.fnmatch(low, pat) for pat in KEEP_PATTERNS):
        return "KEEP"
    if any(fnmatch.fnmatch(low, pat) for pat in ARCHIVE_PATTERNS):
        return "ARCHIVE"
    return "UNKNOWN"          # 不认识就保留，别自作聪明删


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", action="append", required=True, help="任务产物目录，可多次给")
    ap.add_argument("--contract", default="", help="任务契约（会把归档后的路径写回去）")
    ap.add_argument("--target", default="", help="归档子目录名，默认取契约 target 或工作目录名")
    ap.add_argument("--apply", action="store_true", help="真的归档/删除（默认只打印）")
    args = ap.parse_args()

    contract = None
    if args.contract:
        try:
            contract = json.loads(Path(args.contract).read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"契约读不了: {exc}")
            return 2
        target = args.target or contract.get("target") or "unknown"
    else:
        target = args.target or Path(args.workdir[0]).name

    stamp = time.strftime("%Y-%m-%d")
    dest = ARCHIVE_ROOT / target.replace("/", "_") / stamp

    buckets: dict[str, list[Path]] = {"KEEP": [], "ARCHIVE": [], "DROP": [], "UNKNOWN": []}
    for wd in args.workdir:
        root = Path(wd)
        if not root.exists():
            print(f"跳过不存在的目录: {root}")
            continue
        for p in sorted(root.rglob("*")):
            if p.is_dir() and p.name not in DROP_DIRS:
                continue
            # 缓存目录整体按目录处理，内部的单个文件不再单独记一次
            if any(part in DROP_DIRS for part in p.parts):
                if p.is_dir() and p.name in DROP_DIRS:
                    buckets["DROP"].append(p)
                continue
            buckets[classify(p)].append(p)

    size = {k: sum(f.stat().st_size for f in v if f.is_file()) for k, v in buckets.items()}

    print(f"=== 收尾审计 target={target} ===")
    for k in ("KEEP", "ARCHIVE", "DROP", "UNKNOWN"):
        print(f"  {k:<8} {len(buckets[k]):>4} 个  {human(size[k]):>9}")
    print(f"\n归档目录: {dest}")
    print(f"模式: {'APPLY（会移动+删除）' if args.apply else 'DRY-RUN（只打印）'}")

    for k in ("KEEP", "ARCHIVE", "DROP", "UNKNOWN"):
        if not buckets[k]:
            continue
        print(f"\n--- {k} ---")
        for f in buckets[k][:25]:
            try:
                print(f"  {human(f.stat().st_size):>9}  {f}")
            except OSError:
                print(f"  {'?':>9}  {f}")
        if len(buckets[k]) > 25:
            print(f"  … 另外 {len(buckets[k]) - 25} 个")

    if buckets["UNKNOWN"]:
        print("\n!! 有未识别文件：默认保留，请人工过一眼再决定（改 classify 规则或手动处理）")

    manifest = {
        "target": target, "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "workdirs": args.workdir, "apply": args.apply,
        "counts": {k: len(v) for k, v in buckets.items()},
        "bytes": size,
        "keep": [], "raw": [], "dropped": [], "unknown": [],
    }

    if not args.apply:
        print("\n（dry-run：什么都没动。确认清单后加 --apply 执行）")
        return 0

    dest.mkdir(parents=True, exist_ok=True)
    keep_dir = dest / "keep"
    keep_dir.mkdir(exist_ok=True)

    # 1) KEEP：复制 + 哈希核对后才删原文件
    for f in buckets["KEEP"]:
        if not f.is_file():
            continue
        src_hash = sha256(f)
        out = keep_dir / f.name
        n = 1
        while out.exists() and sha256(out) != src_hash:
            out = keep_dir / f"{f.stem}_{n}{f.suffix}"
            n += 1
        shutil.copy2(f, out)
        if sha256(out) == src_hash:
            manifest["keep"].append({"name": out.name, "sha256": src_hash, "bytes": f.stat().st_size,
                                     "from": str(f)})
            f.unlink()
        else:
            print(f"  !! 哈希不符，原文件保留: {f}")

    # 2) ARCHIVE：打 tar.gz
    if buckets["ARCHIVE"]:
        tar_path = dest / "raw.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            for f in buckets["ARCHIVE"]:
                if f.is_file():
                    tf.add(f, arcname=f.name)
        manifest["raw"].append({"name": tar_path.name, "sha256": sha256(tar_path),
                                "bytes": tar_path.stat().st_size,
                                "files": len(buckets["ARCHIVE"])})
        for f in buckets["ARCHIVE"]:
            if f.is_file():
                f.unlink()

    # 3) DROP：删除
    for f in buckets["DROP"]:
        try:
            if f.is_dir():
                shutil.rmtree(f, ignore_errors=True)
            else:
                f.unlink()
            manifest["dropped"].append(str(f))
        except FileNotFoundError:
            pass                      # 父目录已经连同删掉了
        except OSError as exc:
            print(f"  !! 删不掉 {f}: {exc}")

    manifest["unknown"] = [str(f) for f in buckets["UNKNOWN"]]
    (dest / "closeout.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1),
                                        encoding="utf-8")

    # 4) 契约里指向旧路径的证据，改到归档位置
    if contract and args.contract:
        moved = {Path(e["from"]).as_posix(): keep_dir / e["name"] for e in manifest["keep"]}
        changed = 0
        for ev in contract.get("evidence", []):
            newp = moved.get(Path(ev.get("path", "")).as_posix())
            if newp and newp.is_file():
                ev["path"] = str(newp)
                ev["sha256"] = sha256(newp)
                changed += 1
        if changed:
            Path(args.contract).write_text(json.dumps(contract, ensure_ascii=False, indent=1),
                                           encoding="utf-8")
        print(f"\n契约更新: {changed} 条证据路径改到归档目录")

    print(f"\n完成。归档 {len(manifest['keep'])} 个关键产物 + raw.tar.gz，"
          f"清理 {len(manifest['dropped'])} 个废弃项")
    print(f"清单: {dest/'closeout.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
