# HermesYF

基于 NousResearch/hermes-agent，自有或明确授权资产的低噪声安全评估开发分支。

上游基线：`5ba559c9e4b1c8397df7788e319ab634144ca728`。保留上游许可证与原始作者历史（初次克隆为 shallow，远端保留可达基线）。`upstream` 为官方项目，`origin` 为 Gohappyflyy/HermesYF。当前不改变核心运行时、审批、鉴权与模型策略，也没有切换在线部署。

## 首批交付

- `yf_tools/prompt_inventory.py`：标准库 AST 静态提示词来源清单，仅解析 `agent/prompt_builder.py` 与 `agent/system_prompt.py`。输出模块级字面量字符串元数据和 append 位置候选，不执行被审计源码、不读取用户配置、不输出提示词正文。不代表完整有效运行时提示词；append 候选不保证都是提示词组装。
- `yf_tests/test_prompt_inventory.py`：静态审计工具回归测试。
- `yf_tools/tool_inventory.py`：8 个 CLI 的本地版本探测，明确区分缺失、超时、探测失败和同名软件身份未验证；不安装软件、不发起目标扫描。运行 `python3 -m yf_tools.tool_inventory`。版本命令仍会执行 PATH 中的本地程序，仅用于可信安装环境。新增 6 项测试，与原有测试合计 20 项。
- `skills/security/hermesyf-authorized-assessment/SKILL.md`：授权范围内直接行动、工具发现与证据工作流。技能不是自动扫描器；实际工具安装、靶场验收和运行时自动化尚未实现。

## 授权策略与离线任务规划

`python3 -m yf_tools.assessment_plan --policy yf_examples/assessment-policy.json --target https://example.test`

支持精确域名、IP、CIDR、排除项优先和测试类型声明。子域不隐式授权。策略示例只含保留的演示地址，须按真实授权记录创建独立策略。当前仅离线生成任务，不解析 DNS、不连接目标、不证明授权真实性；不是可直接部署的执行期安全边界。策略尚未包含端口、路径、时间窗口或单项测试参数，实际执行器必须补齐这些字段并重新验证地址/重定向。新增 8 项测试，全部 YF 工具测试合计 28 项。

## 候选扫描结果报告

`python3 -m yf_tools.scan_report --input /path/to/nuclei.jsonl`

离线读取 Nuclei JSONL：按目标 URL、模板 ID 与严重度去重、统计次数，所有命中保持 `unverified`，附输入 SHA-256。只接受 HTTP(S) URL，不收录请求/响应正文、查询串或片段，拒绝带用户名密码的 URL。非 HTTP 模板需后续专用解析器。路径和模板 ID 仍可能包含敏感信息，分享前人工复核；查询去除可能合并不同端点。无结果不代表安全，摘要不证明覆盖率。新增 6 项测试，总计 37 项。

## HTTP 实际执行器（初版）

`python3 -m yf_tools.http_baseline --policy /path/to/policy.json --target http://APPROVED_IP:PORT/`

策略须包含 `http_baseline` 与显式 `http_ports` 数组。仅支持字面量 IP，一次 HEAD 请求，10 秒超时，不跟随重定向、不使用环境代理；HTTPS 保持证书验证。输出状态码和安全响应头存在标记，不输出原始头值、Cookie、Location 或正文。URL 查询串、片段与内嵌凭据不接受。返回传输错误不等于目标安全，缺少响应头不直接确认为漏洞。

仅本地 HTTP 靶场已回归，域名 DNS 固定、批准路径、窗口、全局速率调度、TLS 靶场以及 Agent 循环接入尚未实现；不是完整批量公网执行器。当前每次调用只发一次请求，不提供跨调用限速保证。新增 6 项测试（含本地真实 HEAD、302 不跟随、范围/端口阻断），总计 43 项。

## 批量 HTTP 运行与技能接入

`python3 -m yf_tools.assessment_run --policy /private/policy.json --targets /private/targets.json`

目标文件为 URL JSON 数组。当前只执行 `http_baseline`；策略补充精确路径 `http_paths`、数量上限 `max_targets`、带时区的 `window_start`/`window_end`。先校验全批次，串行限速（仅单进程，不保证多个进程共享限速），每次请求前重验窗口，429/503 暂停。无自动重试，无其他类型静默降级执行。传输错误仍会使单项失败，批次 `completed` 不是全部检测成功。请求可能跨窗口结束，最长受单项 socket 超时限制；不是强制终止的总墙钟预算。技能已有这些 CLI 的 `terminal` 调用入口，未验证真实模型自主调用。

新增 8 项检查，包括真实本地 HTTP 批次执行。YF 测试总计 51 项；上游完整测试和公网扫描尚未验收。前文“未有执行器”描述仅适用于 Nuclei 等未接入类型，HTTP 执行能力以此节为准。

## 使用

```sh
python3 -m yf_tools.prompt_inventory --root .
python3 -m unittest discover -s yf_tests -v
```

## 能力方向与边界

范围内低影响基线不反复确认；按明确授权策略开展主动测试。保持范围检查、秘密保护及不可信目标内容的提示词注入防护。不会用“无限授权”提示词替代真实授权，也不宣称精通或已经集成所有渗透工具。

本次未安装安全工具、未对外部目标发起扫描、未运行上游完整测试套件。凭证必须在仓库外受限保存，绝不可写入本公开仓库。正式部署须独立回归、备份与明确切换批准。
