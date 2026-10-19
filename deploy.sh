#!/usr/bin/env bash
# ============================================================================
# HermesYF 一键部署脚本 — 干净机器上一条命令完成安装
# ============================================================================
# 用法（在目标机上，root 用户）:
#   curl -fsSL https://raw.githubusercontent.com/Gohappyflyy/HermesYF/main/deploy.sh | bash
# 或先 clone 再本地跑:
#   bash deploy.sh
#
# 流程: 装 git/curl → clone 仓库到 /root/HermesYF → setup-hermes.sh
# ============================================================================
set -e

REPO_URL="https://github.com/Gohappyflyy/HermesYF.git"
INSTALL_DIR="/root/HermesYF"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${CYAN}☤ HermesYF 一键部署${NC}"
echo ""

# 1. 依赖工具
missing=""
command -v git  >/dev/null 2>&1 || missing="git $missing"
command -v curl >/dev/null 2>&1 || missing="curl $missing"
command -v unzip >/dev/null 2>&1 || missing="unzip $missing"
command -v ca-certificates >/dev/null 2>&1 || true  # 包名检测从略，随 apt 一起装

if [ -n "$missing" ]; then
    echo -e "${CYAN}→${NC} 安装缺失工具: $missing"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq $missing ca-certificates
fi

# 2. 拉取仓库
if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "${GREEN}✓${NC} 仓库已存在，拉取最新..."
    cd "$INSTALL_DIR"
    git fetch origin 2>/dev/null
    git reset --hard origin/main 2>/dev/null
    git pull --ff-only origin main 2>/dev/null || true
else
    echo -e "${CYAN}→${NC} clone 仓库到 $INSTALL_DIR ..."
    rm -rf "$INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

# 3. 部署
cd "$INSTALL_DIR"
echo -e "${CYAN}→${NC} 运行 setup-hermes.sh（首次 1-5 分钟）..."
bash setup-hermes.sh

echo ""
echo -e "${GREEN}✓ 部署完成！${NC}"
echo ""
echo "后续:"
echo "  source /root/HermesYF/activate   # 激活环境"
echo "  hermes setup                      # 配置 API keys"
echo "  hermes gateway run                # 启动网关"
