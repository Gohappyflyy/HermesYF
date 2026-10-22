# 记忆系统：容量、多后端、"memory 为空"排查

内置记忆是**纯文本文件 + 字符上限 + 注入 system prompt**，不是数据库召回。理解这三点才能解释全部症状。

## 1. 两套体系并存

```
内置（永远在）
  tools/memory_tool_store.MemoryStore
  → $HERMES_HOME/memories/MEMORY.md（agent 笔记）
  → $HERMES_HOME/memories/USER.md（用户画像）

外部 provider（可选，8 个插件各带一个同名类）
  holographic / retaindb / byterover / honcho / hindsight / supermemory / mem0 / openviking
  → 各自存储（holographic 是 SQLite + 向量/HRR）
  → plugins/memory/load_memory_provider(name)
```

**关键：两者不是二选一替换**。`agent_init` 里 `_memory_store`（内置）和 `_memory_manager`（外部）是两个属性，配了 provider 之后内置 MEMORY.md 照样写。所以看到"两个 MemoryStore 类"不是重复代码，别去合并它们。

`memory.provider` 为空 = 只用内置。

## 2. 容量：改哪里才算改全

配置键：`memory.memory_char_limit`（默认 2200）、`memory.user_char_limit`（默认 1375）。换算按 ~2.75 chars/token。

```bash
hermes config set memory.memory_char_limit 11000
hermes config get memory.memory_char_limit   # 验证
```

**默认值散落在 4 处**，只改 config 不改代码的话，全新部署（或 config 缺这个键）还是回落到旧值：

```
hermes_cli/config_defaults.py     "memory_char_limit": 2200     ← 默认值源头
cli-config.yaml.example           memory_char_limit: 2200       ← 新部署直接复制这个文件
tools/memory_tool.py              .get("memory_char_limit", 2200) ← 无 live agent 的 fallback
tools/memory_tool_store.py        def __init__(..., = 2200)      ← 构造函数默认
agent/agent_init.py               .get("memory_char_limit", 2200) ← agent 初始化
```

改的时候一起改，并**给 `agent_init` 那一处补 `int()`**：原代码 `mem_config.get("memory_char_limit", 2200)` 没有类型转换，config 里写成带引号的字符串会让上限变成 `str`，后面 `len(entries) > limit` 直接 TypeError。

**改完不会立刻生效**：`MemoryStore` 只在 agent 初始化时读配置，当前会话仍用旧上限（写入回执里的 `x/2,200` 就是证据）。开新会话即可，不需要重启 gateway。

## 3. "memory 一直为空"的三个原因

按概率排，**一般不是 bug**：

1. **部署层** — 安装脚本只 `mkdir -p $HERMES_HOME/memories`，不生成 MEMORY.md / USER.md。全新机器一开机就是空目录，没有任何初始上下文。
2. **行为层** — 内置记忆只有两个写入时机：模型主动调 memory 工具，或 `nudge_interval`（默认 10 轮）触发的后台 review。模型不主动写就一直空。
3. **静默层** — 空记忆不报错、不提醒，表现为"一切正常但每次开机都失忆"。

`memory_enabled: True` + `write_approval: False` 时写入不需要审批，所以"写不进去"通常不是权限问题，先查上面三条。

**修复部署层**：安装脚本里加一段幂等初始化（`[ ! -s file ]` 才写，非空绝不覆盖），内容写环境事实 + 用户画像 + 交付约定。已验证的写法见仓库 `install-yufeng.sh` 第 6 步。

**修复已有机器**：脚本里加迁移段，`hermes config get` 读回旧默认值才升级，用户自定义过的值不覆盖：

```bash
CUR="$(hermes config get memory.memory_char_limit 2>/dev/null || true)"
if [ "$CUR" = "2200" ]; then hermes config set memory.memory_char_limit 11000; fi
```

## 4. 排查顺序（用户说"记忆有问题/失忆"时）

```bash
ls -la $HERMES_HOME/memories/            # 目录空 = 从没写过；只有 .lock 没 .md 同理
hermes config get memory.memory_char_limit
hermes config get memory.provider        # 非空说明开了外部 provider
```

然后区分两种失忆：

- **跨会话完全没有** → 第 3 节三条，重点是部署不初始化。
- **写过但内容丢了** → 看是不是超过上限被 consolidation 合并掉了（`_MAX_CONSOLIDATION_FAILURES_PER_TURN = 3`，超限的写入会被跳过而不是报错）。

## 5. 写入策略：什么该进哪一层

```
落盘文件   <工作目录>/           战斗数据、扫描结果、清单——永不丢，最大的那部分
skill     skills/<name>/         流程、命令、教训——按任务加载，不进 system prompt
memory    MEMORY.md / USER.md    全局事实（环境、路径、铁律、身份）——每轮注入，必须小
session   state.db              历史检索，兜底
```

判断标准：**下个任务还需要它吗？需要 → skill 或 memory；只是这次的结果 → 落盘。**

memory 只放"每个会话都要知道"的：环境路径、代理端口、用户身份与铁律。流程和坑放 skill——那里可以写长，且只在相关任务时加载。反过来把流程塞进 memory 会挤掉真正每轮都要用的东西。

## 6. 安全注意

- 记忆注入 system prompt，写入内容会过 `threat_patterns` 扫描；被拦的条目加载时替换成 `[BLOCKED: ...]` 占位（文件里保留原文，方便人工删）。
- 用户在聊天里贴的 token / 密码会进入 `state.db`（会话记录）。提醒他们用完 revoke，不要当成"只在聊天里"就安全。
