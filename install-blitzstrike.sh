#!/bin/bash
# Blitz Strike MCP 一键部署
# 关键：代码走 main 分支，绝不拉 tag/release —— GitHub Release 长期停在 v1.0.0，
#       实际发版走 npm（2.4.x），main 分支 HEAD 与 npm publish 同步。
set -e

# setup-hermes.sh 把 hermes 发布到 ~/.local/bin 但只写进 .bashrc，
# 非登录 shell 的 PATH 里没有 —— 显式补上，否则 hermes mcp add 找不到命令。
export PATH="$HOME/.local/bin:$HOME/.bun/bin:$PATH"

INSTALL_DIR="${BLITZ_DIR:-/opt/blitzstrike}"
REPO="https://github.com/shinthink/blitzstrike.git"

echo "=== Blitz Strike MCP 部署 ==="

# 1. bun（blitzstrike 运行时）
BUN="$HOME/.bun/bin/bun"
if ! command -v bun >/dev/null 2>&1 && [ ! -x "$BUN" ]; then
    echo "→ 安装 bun..."
    # 固定版本才可复现；不设 BUN_VERSION 时跟随上游 latest（记录到安装清单里，事后能查）
    if [ -n "${BUN_VERSION:-}" ]; then
        curl -fsSL https://bun.sh/install | bash -s "bun-v${BUN_VERSION}"
    else
        curl -fsSL https://bun.sh/install | bash
    fi
    BUN="$HOME/.bun/bin/bun"
fi
if [ ! -x "$BUN" ]; then
    BUN="$(command -v bun)"
fi
[ -x "$BUN" ] || { echo "✗ bun 安装失败，跳过 Blitz Strike"; exit 1; }
echo "✓ bun: $BUN"

# 2. clone / 更新 main 分支
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "→ 更新 blitzstrike（git pull main）..."
    git -C "$INSTALL_DIR" pull --ff-only origin main 2>/dev/null || \
        echo "  （拉取失败，沿用现有代码）"
else
    echo "→ 克隆 blitzstrike ${BLITZSTRIKE_REF:-main}..."
    rm -rf "$INSTALL_DIR"
    git clone --depth 1 --branch "${BLITZSTRIKE_REF:-main}" "$REPO" "$INSTALL_DIR"
fi

# 安装清单：记下实际拿到的提交和 bun 版本，事后可复现/比对
{
  echo "blitzstrike $(git -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null) ref=${BLITZSTRIKE_REF:-main} at=$(date -Iseconds)"
  echo "bun $("$BUN" --version 2>/dev/null)"
} >> "${HERMES_HOME:-$HOME/.hermes}/mcp-install-manifest.txt" 2>/dev/null || true

# 3. 依赖 + build
cd "$INSTALL_DIR"
"$BUN" install
"$BUN" build src/index.ts --outdir dist --target node --format esm --external playwright-core

# 4. 注册 MCP（已存在则跳过）
if hermes mcp list 2>/dev/null | grep -q "blitzstrike"; then
    echo "✓ blitzstrike MCP 已注册，跳过"
else
    printf 'Y\n' | hermes mcp add blitzstrike --command "$BUN" --args "$INSTALL_DIR/dist/index.js" serve --mcp
    echo "✓ blitzstrike MCP 已注册（188 工具）"
fi

echo
echo "=== Blitz Strike 部署完成 ==="
echo "重启 gateway 后生效: hermes gateway restart"
