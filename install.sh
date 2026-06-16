#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────
# cf-ip-scanner 一键安装脚本
# 用法: curl -fsSL <raw_url> | bash
# ──────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
BOLD='\033[1m'

logo() {
    echo -e "${CYAN}${BOLD}"
    echo "   ╔══════════════════════════════╗"
    echo "   ║     cf-ip-scanner           ║"
    echo "   ║  ASN → masscan → CF 反代    ║"
    echo "   ╚══════════════════════════════╝"
    echo -e "${NC}"
}

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${RED}[!]${NC} $*"; }

logo

# ── 0. 检查系统 ──
OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
    warn "当前仅支持 Linux (masscan 依赖)"
    exit 1
fi

if [ "$(id -u)" = "0" ]; then
    SUDO=""
else
    SUDO="sudo"
fi

# ── 1. 安装系统依赖 ──
info "检查系统依赖..."

install_pkg() {
    local pkg=$1
    if command -v "$pkg" &>/dev/null || dpkg -l "$pkg" &>/dev/null 2>&1 || rpm -q "$pkg" &>/dev/null 2>&1; then
        return 0
    fi
    warn "安装 $pkg ..."
    if command -v apt &>/dev/null; then
        $SUDO apt update -qq && $SUDO apt install -y -qq "$pkg"
    elif command -v yum &>/dev/null; then
        $SUDO yum install -y -q "$pkg"
    elif command -v dnf &>/dev/null; then
        $SUDO dnf install -y -q "$pkg"
    else
        warn "未检测到包管理器，请手动安装: $pkg"
    fi
}

install_pkg masscan
install_pkg prips
install_pkg python3
install_pkg git

# ── 2. 检查/安装 Go ──
info "检查 Go..."
if command -v go &>/dev/null; then
    GO_VERSION=$(go version | grep -oP 'go\K[0-9.]+')
    info "Go $GO_VERSION 已安装"
else
    GO_VER="1.22.2"
    GO_ARCH="linux-amd64"
    warn "安装 Go $GO_VER ..."
    curl -fsSL "https://go.dev/dl/go${GO_VER}.${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
    $SUDO tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:$PATH"
    info "Go $GO_VER 安装完成"
fi

# ── 3. 克隆项目 ──
PROJECT_DIR="$HOME/cf-ip-scanner"
REPO_URL="https://github.com/e13815332/subyd.git"
BRANCH="main"

if [ -d "$PROJECT_DIR/.git" ]; then
    info "项目已存在，更新中..."
    cd "$PROJECT_DIR"
    git pull origin "$BRANCH" --ff-only
else
    info "克隆项目..."
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$PROJECT_DIR.tmp"
    # 只取 cf-ip-scanner 子目录
    if [ -d "$PROJECT_DIR.tmp/cf-ip-scanner" ]; then
        cp -r "$PROJECT_DIR.tmp/cf-ip-scanner" "$PROJECT_DIR"
        rm -rf "$PROJECT_DIR.tmp"
    else
        warn "cf-ip-scanner 目录不存在，请确认仓库结构"
        exit 1
    fi
fi

# ── 4. 编译 cf-scanner ──
info "编译 cf-scanner..."
cd "$PROJECT_DIR/cf-scanner"

# AVX2 检测：不支持则用 v2
if grep -q avx2 /proc/cpuinfo 2>/dev/null; then
    GOAMD=""
else
    GOAMD="GOAMD64=v2"
fi

env $GOAMD go build -o "$PROJECT_DIR/cf-scanner" main.go
info "cf-scanner 编译完成 → $PROJECT_DIR/cf-scanner"

# ── 5. 完成 ──
echo ""
echo -e "${GREEN}${BOLD}✅ 安装完成！${NC}"
echo ""
echo -e "  ${CYAN}项目目录:${NC} $PROJECT_DIR"
echo -e "  ${CYAN}编辑端口:${NC} vim $PROJECT_DIR/ports.txt"
echo -e "  ${CYAN}运行扫描:${NC}  cd $PROJECT_DIR && python3 run.py AS209242"
echo ""
