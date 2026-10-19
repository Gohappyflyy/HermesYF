#!/bin/bash
# HermesYF 御风人格 + 海鸥技能一键部署（修复原版所有安装路径错误）
set -e
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"

echo "=== 御风部署 ==="
# 1. 插件（hook 修复版）
mkdir -p "$HERMES_HOME/plugins"
cp -r "$(dirname "$0")/plugins/yufeng-armor" "$HERMES_HOME/plugins/"
echo "✓ 插件 yufeng-armor"

# 2. SOUL.md（Hermes 主目录）
cp "$(dirname "$0")/SOUL-yufeng.md" "$HERMES_HOME/SOUL.md"
echo "✓ SOUL.md"

# 3. AGENTS.md —— 关键修复：必须放 gateway 工作目录（cwd），不是 ~/.hermes
cp "$(dirname "$0")/AGENTS-yufeng.md" "$HOME/AGENTS.md"
echo "✓ AGENTS.md → ~/（gateway cwd）"

# 4. 海鸥技能包（带 frontmatter 修复版）
mkdir -p "$HERMES_HOME/skills"
cp -r "$(dirname "$0")/skills/security/seagull-skills/"* "$HERMES_HOME/skills/"
echo "✓ 5 个海鸥技能（frontmatter 已修复）"

# 5. 清理旧版海鸥插件（hook 不合法的）
if [ -d "$HERMES_HOME/plugins/seagull-armor-break" ]; then
  rm -rf "$HERMES_HOME/plugins/seagull-armor-break"
  echo "✓ 移除旧版 seagull-armor-break（hook 无效）"
fi

echo
echo "=== 完成。重启 gateway 生效 ==="
echo "hermes gateway restart"
