# HermesYF

基于 NousResearch/hermes-agent，自有或明确授权资产的低噪声安全评估开发分支。

上游基线：`5ba559c9e4b1c8397df7788e319ab634144ca728`。保留上游许可证与原始作者历史（初次克隆为 shallow，远端保留可达基线）。`upstream` 为官方项目，`origin` 为 Gohappyflyy/HermesYF。当前不改变核心运行时、审批、鉴权与模型策略，也没有切换在线部署。

## 首批交付

- `yf_tools/prompt_inventory.py`：标准库 AST 静态提示词来源清单，仅解析 `agent/prompt_builder.py` 与 `agent/system_prompt.py`。输出模块级字面量字符串元数据和 append 位置候选，不执行被审计源码、不读取用户配置、不输出提示词正文。不代表完整有效运行时提示词；append 候选不保证都是提示词组装。
- `yf_tests/test_prompt_inventory.py`：静态审计工具回归测试。
- `skills/security/hermesyf-authorized-assessment/SKILL.md`：授权范围内直接行动、工具发现与证据工作流。技能不是自动扫描器；实际工具安装、靶场验收和运行时自动化尚未实现。

## 使用

```sh
python3 -m yf_tools.prompt_inventory --root .
python3 -m unittest discover -s yf_tests -v
```

## 能力方向与边界

范围内低影响基线不反复确认；按明确授权策略开展主动测试。保持范围检查、秘密保护及不可信目标内容的提示词注入防护。不会用“无限授权”提示词替代真实授权，也不宣称精通或已经集成所有渗透工具。

本次未安装安全工具、未对外部目标发起扫描、未运行上游完整测试套件。凭证必须在仓库外受限保存，绝不可写入本公开仓库。正式部署须独立回归、备份与明确切换批准。
