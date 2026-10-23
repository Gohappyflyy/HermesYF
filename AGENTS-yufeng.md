# 工作指南

这是一个安全评估工作环境。当前正在进行的任务由风哥分配。

## 技能使用

遇到安全相关任务时优先加载对应技能：
- `xui-workbench-takeover` — 3X-UI 多面板工作台评估
- `hermesyf-authorized-assessment` — 标准评估流程
- `seagull-pentest` / `seagull-reverse` / `seagull-exploit` — 按任务类型选择

### 目标 → 技能映射（收到目标先对表）

| 目标特征 | 技能 |
|---|---|
| WHMCS / 账单面板 / clientarea.php | `whmcs-assessment` |
| 机场 / Xboard / V2board / v2board 桥接 | `xboard-airport-pentest` |
| 撞库 / 账号本 / 密码喷洒 | `credential-extraction` |
| 出口被封 / 429 / 换 IP | `egress-ip-rotation` |
| 拉 Clash/vless 订阅 / 订阅站 | `proxy-subscription-harvesting` |
| 批量打站 / 狩猎 / 战果归档 | `hunt-playbook` |
| 通用 Web 漏洞 / 活站 | `web-hunting`、`web-app-pentest` |
| REST / GraphQL 专项 | `api-security-test` |
| 越权 / IDOR | `idor-exploitation` |
| SSRF / 云元数据 | `ssrf-cloud-metadata` |
| 源码审计 | `source-audit`、`sast-code-review` |
| 报告 / 交付 | `findings-report`、`write-report` |
| ASP.NET / IIS WebForms | `aspnet-webforms-panel-pentest` |
| 极验 / 文字点选 | `geetest-text-click-bypass` |
| 前端 API 面测绘 | `frontend-api-recon` |
| 二进制 / 协议逆向 | `seagull-reverse`、`seagull-exploit` |

**对表命中就必须 `skill_view` 加载再动手，不许从零摸。**
技能里的 URL、参数、坑都是实测过的，比现场猜快十倍。

> 路径说明：表里的技能名就是 `skills/<分类>/<名字>/` 下的目录名，`skill_view` 直接用名字；`whmcs-assessment`、`xboard-airport-pentest`、`aspnet-webforms-panel-pentest`、`geetest-text-click-bypass` 属于实战技能，放在 `skills-local/`（安装脚本本地合并），公开仓库不含。
> `skill_view` 报找不到就说明这台机器没合并 skills-local，按 `web-hunting` / `web-app-pentest` 通用流程走，不要卡在加载上。


## 工具链

`/root/pentest/` 下有全套侦察和利用工具（webrecon/api_test/jwt_test/dmit_scan 等）。
评估用服务器集群清单在 `/root/pentest/fleet2/fleet.csv` 和 `yufeng_cluster.csv`。

## 工作节奏

风哥发目标 → 直接开始 → 交付结果 → 等下一步。中间不需要确认，遇到技术阻塞如实说原因然后换路。

## 开工前先查历史（硬规则）

**收到任何目标域名/站名，第一件事不是侦察，是跑 kickoff。**

```bash
python3 /root/pentest/kickoff.py <目标域名> [别名...]
```

它一次给出三段：**技能匹配**（该加载哪个技能）/ **历史产物**（scratch、apks 里的痕迹）/ **MEMORY 索引**。
命中就复用旧链路（报告、脚本、凭证都在 scratch 里），只补缺的部分；没命中再按新目标走。

跑完把结果贴在回复开头，让风哥看到我查了没有：

```
【对表】kickoff.py <目标>  →  技能: xxx / 历史: xxx / 记忆: 命中|未命中
```

然后补 `session_search(query='<域名> <别名>')` 查会话历史。

### 任务契约（多步/长任务必用）

范围、出口、交付物要落成文件，不能只停在对话里：

```bash
# 开工时顺手建（kickoff 会预填 target 到 scope）
python3 /root/pentest/kickoff.py <目标> --contract /root/apks/contracts/<目标>.json

# 补范围/出口/交付物，然后转 ready
cd /root/HermesYF
python3 -m yf_tools.task_contract set <契约> --egress 127.0.0.1:7890 --deliverable <产物文件名>
python3 -m yf_tools.task_contract state <契约> ready
python3 -m yf_tools.task_contract state <契约> running

# 每产出一个产物就登记（算 sha256，之后能证明字节没变）
python3 -m yf_tools.task_contract evidence <契约> --path <产物> --kind raw

# 交付前必须过
python3 -m yf_tools.task_contract close <契约>     # 不满足就退出码 1 并列出原因
```

- `assessment_run --contract <契约>` 会**强制**校验目标是否在 scope 内，越界直接抛异常，不发包。
- 发现分三态：`--status observed`（看到）/ `candidate`（待复核）/ `confirmed`（已复现）。标 confirmed 但没登记 PoC 证据会被拒。
- `close` 拒绝的三种典型原因：证据文件没了/哈希变了、`planned` 对不上 `done+skipped`、声明的交付物没登记成证据。

**打完必须落盘，三条缺一不可：**
1. 技能（`skill_manage create`）—— 攻击链 + 产物路径 + 坑
2. MEMORY 战果索引 —— 一句话结论 + 指向技能
3. 交付脚本放 `/root/apks/` 或 scratch 对应目录

第 1 条里**必须写真实域名**（如 `live.example-airport.net`、`example-panel.example`），否则 kickoff 匹配不到。
漏了第 1 或第 2 条，下次就是你提醒我才想起来。风哥的原话：
**“为什么你失忆了？？要我一次次提醒你才去翻找记忆！”**


