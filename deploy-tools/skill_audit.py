#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
技能审计器
==========
对导入的技能包做三件事：
  1. 说教扫描  —— 找出法律/边界/底线/授权/免责/伦理类措辞（带上下文，便于人工判定）
  2. 重叠检测  —— 跟现有技能库比名称、描述、正文相似度
  3. 质量评分  —— frontmatter 完整性、体积、结构、可执行性

用法：
  python3 skill_audit.py <待审计目录>              # 全量报告
  python3 skill_audit.py <目录> --only preach      # 只看说教
  python3 skill_audit.py <目录> --only dup         # 只看重叠
  python3 skill_audit.py <目录> --json out.json    # 出机器可读结果

注意：说教扫描是粗筛，`authorization: Bearer` 这类 HTTP 头会被标为技术白名单，
不参与判定。最终删改由人复核。
"""
import argparse
import json
import os
import re
import sys
from difflib import SequenceMatcher

SKILLS_HOME = "/root/.hermes/skills"

# ---------------------------------------------------------------- 说教词表
# 每个词条：pattern, 类别, 说明
PREACH_PATTERNS = [
    # 法律
    (r"法律责任|法律后果|违反法律|触犯法律|违法行[为径]|非法行[为径]", "法律", "法律后果"),
    (r"刑事责任|民事赔偿|司法机[关构]|起诉|判刑|坐牢|入狱", "法律", "刑罚"),
    (r"合法合规|合规性|遵守.{0,6}法律|符合.{0,6}法规|法律允许", "法律", "合规"),
    (r"《[^》]{2,20}法》|刑法第|网络安全法|数据安全法|个人信息保护法", "法律", "援引法条"),
    # 边界
    (r"授权范围|工作范围|测试边界|不要越界|越界行[为径]|超出范围", "边界", "范围限制"),
    (r"in-scope|out-of-scope|scope\s+creep|仅限授权|限于授权", "边界", "scope 限制"),
    # 「未授权访问/未授权接口/未授权反序列化」是漏洞术语，不算说教；
    # 只有「未授权的测试/攻击/行动」这类才是指授权要求
    (r"(?:未|未经|无)授权(?:的)?(?:测试|攻击|渗透|扫描|评估|行[为径]|目标|活动|演练)", "边界", "授权要求"),
    (r"授权书|书面授权|授权文件|授权凭证", "边界", "授权凭据"),
    # 底线
    (r"底线|红线|原则问题|职业操守|行业自律", "底线", "底线表述"),
    # 授权/许可
    (r"确保.{0,8}授权|获得.{0,8}许可|取得.{0,8}同意|事先.{0,6}批准", "授权", "前置许可"),
    (r"permission\s+from|with\s+authorization|authorized\s+by|consent\s+from", "授权", "英文授权"),
    # 免责
    (r"免责|风险自负|自行承担|后果自负|不承担.{0,8}责任|at\s+your\s+own\s+risk", "免责", "免责声明"),
    (r"仅供.{0,8}学习|仅用于.{0,8}教育|educational\s+purpose|for\s+learning\s+only", "免责", "教育免责"),
    (r"请勿.{0,10}非法|禁止.{0,8}滥用|do\s+not\s+misuse", "免责", "禁止滥用"),
    # 伦理
    (r"伦理|道德|ethic|responsible\s+disclosure|负责任.{0,4}披露", "伦理", "伦理"),
    (r"善意|good\s+faith|正当理由|合理用途", "伦理", "动机"),
    # 说教口吻
    (r"请注意|务必注意|请确保|应当遵守|必须遵守|切记|谨记", "说教口吻", "训导"),
    (r"作为\s*AI|我是一个\s*AI|我建议|建议您|建议你", "说教口吻", "AI 腔"),
    (r"重要提示|免责声明|disclaimer|免责条款", "说教口吻", "提示块"),
    (r"如果你没有.{0,10}请.{0,6}停止|请立即停止|立即中止", "说教口吻", "叫停"),
]

# 技术白名单：这些上下文里出现的关键词是技术术语，不算说教
TECH_WHITELIST = [
    r"authorization\s*:",          # HTTP 头
    r"Authorization:\s*Bearer",
    r"authorized_keys",            # SSH
    r"scope",                      # OAuth scope / nmap script scope
    r"OAuth|OIDC|JWT|token",
    r"permission\s+denied",        # 系统报错
    r"403|401",
]

COMPILED = [(re.compile(p, re.I), cat, note) for p, cat, note in PREACH_PATTERNS]
WL = [re.compile(p, re.I) for p in TECH_WHITELIST]


def load_skill(path):
    try:
        return open(path, encoding="utf-8", errors="ignore").read()
    except Exception:
        return ""


def frontmatter(body):
    """返回 (name, description, 正文)"""
    name = desc = ""
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", body, re.S)
    if m:
        fm = m.group(1)
        n = re.search(r"^name:\s*(.+)$", fm, re.M)
        d = re.search(r"^description:\s*(.+)$", fm, re.M)
        name = (n.group(1).strip().strip('"').strip("'") if n else "")
        desc = (d.group(1).strip().strip('"').strip("'") if d else "")
        return name, desc, body[m.end():]
    return name, desc, body


def scan_preach(body):
    """返回命中列表 [(行号, 类别, 说明, 上下文)]"""
    hits = []
    lines = body.split("\n")
    for i, line in enumerate(lines, 1):
        # 技术白名单行跳过
        if any(w.search(line) for w in WL):
            # 仍然检查是否同时含明显说教词
            if not re.search(r"法律责任|免责|伦理|道德|底线|红线|请注意|请确保|务必", line, re.I):
                continue
        for rx, cat, note in COMPILED:
            m = rx.search(line)
            if m:
                hits.append({
                    "line": i,
                    "cat": cat,
                    "note": note,
                    "match": m.group(0)[:40],
                    "text": line.strip()[:160],
                })
    return hits


def existing_skills():
    """索引现有技能"""
    idx = {}
    for root, dirs, files in os.walk(SKILLS_HOME):
        if "SKILL.md" not in files:
            continue
        p = os.path.join(root, "SKILL.md")
        body = load_skill(p)
        name, desc, main = frontmatter(body)
        key = name or os.path.basename(root)
        idx[key] = {"path": p, "desc": desc, "body": main, "size": len(body)}
    return idx


def similarity(a, b):
    return SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def find_dup(new_name, new_desc, new_body, existing):
    """返回 [(技能名, 分数, 依据)]"""
    out = []
    for name, info in existing.items():
        score = 0
        why = []
        if new_name and (new_name.lower() == name.lower()):
            score += 100
            why.append("同名")
        else:
            r = SequenceMatcher(None, new_name.lower(), name.lower()).ratio()
            if r > 0.75:
                score += int(r * 40)
                why.append("名称像%.0f%%" % (r * 100))
        if new_desc and info["desc"]:
            r = SequenceMatcher(None, new_desc.lower()[:300], info["desc"].lower()[:300]).ratio()
            if r > 0.6:
                score += int(r * 30)
                why.append("描述像%.0f%%" % (r * 100))
        # 正文前 4000 字相似度
        if len(new_body) > 200 and len(info["body"]) > 200:
            r = similarity(new_body, info["body"])
            if r > 0.55:
                score += int(r * 30)
                why.append("正文像%.0f%%" % (r * 100))
        if score >= 45:
            out.append((name, score, ", ".join(why), info["size"]))
    return sorted(out, key=lambda x: -x[1])


def quality(body, name, desc):
    """打分 0-100"""
    s = 0
    if name:
        s += 15
    if desc:
        s += 15
    n = len(body)
    if n > 1500:
        s += 20
    elif n > 600:
        s += 12
    elif n > 200:
        s += 5
    # 结构
    if re.search(r"^##\s", body, re.M):
        s += 15
    if re.search(r"```", body):
        s += 15          # 有可执行片段
    if re.search(r"(curl|nmap|python|bash|http|POST|GET)", body, re.I):
        s += 10
    if re.search(r"^#\s", body, re.M):
        s += 10
    return min(s, 100)


def main():
    ap = argparse.ArgumentParser(description="技能审计")
    ap.add_argument("target", help="待审计的目录")
    ap.add_argument("--only", choices=["preach", "dup", "quality"], help="只跑某一项")
    ap.add_argument("--json", help="结果写到 JSON")
    args = ap.parse_args()

    if not os.path.isdir(args.target):
        sys.exit("目录不存在: %s" % args.target)

    existing = existing_skills()
    print("现有技能库: %d 个" % len(existing))

    results = []
    for root, dirs, files in os.walk(args.target):
        if "SKILL.md" not in files:
            continue
        p = os.path.join(root, "SKILL.md")
        body = load_skill(p)
        name, desc, main = frontmatter(body)
        name = name or os.path.basename(root)
        preach = scan_preach(body)
        dup = find_dup(name, desc, main, existing)
        q = quality(body, name, desc)
        results.append({
            "name": name,
            "dir": root,
            "path": p,
            "desc": desc,
            "size": len(body),
            "quality": q,
            "preach_count": len(preach),
            "preach": preach,
            "dup": [{"name": d[0], "score": d[1], "why": d[2], "size": d[3]} for d in dup[:3]],
        })

    results.sort(key=lambda x: (-x["preach_count"], -x["quality"]))

    if args.only in (None, "preach"):
        print("\n" + "=" * 78)
        print("说教命中排行")
        print("=" * 78)
        for r in results:
            if not r["preach_count"]:
                continue
            print("\n▌ %s  (%d 处, 质量 %d, %d B)" % (r["name"], r["preach_count"], r["quality"], r["size"]))
            cats = {}
            for h in r["preach"]:
                cats[h["cat"]] = cats.get(h["cat"], 0) + 1
            print("   类别: " + ", ".join("%s×%d" % (k, v) for k, v in cats.items()))
            for h in r["preach"][:6]:
                print("   L%-4d [%s] %s" % (h["line"], h["cat"], h["text"][:110]))
            if len(r["preach"]) > 6:
                print("   ... 还有 %d 处" % (len(r["preach"]) - 6))

    if args.only in (None, "dup"):
        print("\n" + "=" * 78)
        print("重叠检测")
        print("=" * 78)
        for r in results:
            if not r["dup"]:
                continue
            print("\n▌ %s  (质量 %d, %d B)" % (r["name"], r["quality"], r["size"]))
            for d in r["dup"]:
                verdict = "→ 保新的" if r["quality"] > 70 and r["size"] < d["size"] * 0.7 else "→ 比对合并"
                print("   vs %-40s %3d分  %s  (对方 %d B)  %s"
                      % (d["name"][:40], d["score"], d["why"], d["size"], verdict))

    if args.only in (None, "quality"):
        print("\n" + "=" * 78)
        print("质量分布")
        print("=" * 78)
        buckets = {"强(≥80)": 0, "中(60-79)": 0, "弱(40-59)": 0, "渣(<40)": 0}
        for r in results:
            q = r["quality"]
            if q >= 80:
                buckets["强(≥80)"] += 1
            elif q >= 60:
                buckets["中(60-79)"] += 1
            elif q >= 40:
                buckets["弱(40-59)"] += 1
            else:
                buckets["渣(<40)"] += 1
        for k, v in buckets.items():
            print("  %-12s %d" % (k, v))

    print("\n" + "=" * 78)
    print("总计 %d 个技能，说教命中 %d 个，有重叠 %d 个"
          % (len(results), sum(1 for r in results if r["preach_count"]),
             sum(1 for r in results if r["dup"])))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=1)
        print("JSON → %s" % args.json)


if __name__ == "__main__":
    main()
