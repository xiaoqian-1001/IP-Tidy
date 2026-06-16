#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────
# ASNIPtest 一键安装 / 更新 / 卸载
# 用法:
#   curl -fsSL <raw_url> | bash                  # 安装
#   curl -fsSL <raw_url> | bash -s -- update     # 更新
#   curl -fsSL <raw_url> | bash -s -- uninstall  # 卸载
# ──────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; NC='\033[0m'
BOLD='\033[1m'

VERSION="v1.0.0"

logo() {
    echo -e "${CYAN}${BOLD}"
    echo "   ╔══════════════════════════════╗"
    echo "   ║       ASNIPtest  ${VERSION}        ║"
    echo "   ║  ASN → masscan → CF 节点    ║"
    echo "   ╚══════════════════════════════╝"
    echo -e "${NC}"
}

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${RED}[!]${NC} $*"; }

ACTION="${1:-install}"

# ── 卸载 ──
if [ "$ACTION" = "uninstall" ]; then
    echo ""
    for d in "$HOME/ASNIPtest" "$HOME/cf-ip-scanner" "$HOME/cf-ip-scanner.tmp"; do
        if [ -d "$d" ]; then
            rm -rf "$d"
            info "已删除 $d"
        fi
    done
    echo ""
    echo -e "${GREEN}✅ 卸载完成${NC}"
    exit 0
fi

# ── 更新 ──
if [ "$ACTION" = "update" ]; then
    PROJECT_DIR="$HOME/ASNIPtest"
    if [ ! -d "$PROJECT_DIR/.git" ]; then
        warn "项目未安装，请先运行: bash install.sh"
        exit 1
    fi
    OLD_VER=$(cat "$PROJECT_DIR/VERSION" 2>/dev/null || echo "未知")
    info "当前版本: $OLD_VER → 检查更新..."
    cd "$PROJECT_DIR"
    git pull origin main --ff-only
    NEW_VER=$(cat "$PROJECT_DIR/VERSION" 2>/dev/null || echo "未知")
    if [ "$OLD_VER" = "$NEW_VER" ]; then
        info "已是最新版本 $NEW_VER"
    else
        info "${YELLOW}$OLD_VER → $NEW_VER${NC} 已更新"
        info "重新编译 cf-scanner..."
        cd "$PROJECT_DIR/cf-scanner"
        if grep -q avx2 /proc/cpuinfo 2>/dev/null; then GOAMD=""; else GOAMD="GOAMD64=v2"; fi
        env $GOAMD go build -o "$PROJECT_DIR/cf-scanner" main.go
    fi
    echo ""
    echo -e "${GREEN}✅ 版本 $NEW_VER${NC}"
    exit 0
fi

# ── 以下为安装流程 ──
logo

# ── 0. 检查系统 ──
if [ "$(uname -s)" != "Linux" ]; then
    warn "当前仅支持 Linux"
    exit 1
fi
[ "$(id -u)" = "0" ] && SUDO="" || SUDO="sudo"

# ── 清理旧版本 ──
for d in "$HOME/cf-ip-scanner" "$HOME/cf-ip-scanner.tmp"; do
    if [ -d "$d" ]; then
        warn "清理旧版本: $d"
        rm -rf "$d"
    fi
done

# ── 1. 系统依赖 ──
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

# ── 2. Go ──
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
PROJECT_DIR="$HOME/ASNIPtest"
REPO_URL="https://github.com/e13815332/ASNIPtest.git"

if [ -d "$PROJECT_DIR/.git" ]; then
    info "项目已存在，更新中..."
    cd "$PROJECT_DIR"
    git pull origin main --ff-only
else
    info "克隆项目..."
    git clone --depth 1 --branch main "$REPO_URL" "$PROJECT_DIR"
fi

# ── 4. 编译 cf-scanner ──
info "编译 cf-scanner..."
cd "$PROJECT_DIR/cf-scanner"
if grep -q avx2 /proc/cpuinfo 2>/dev/null; then GOAMD=""; else GOAMD="GOAMD64=v2"; fi
env $GOAMD go build -o "$PROJECT_DIR/cf-scanner" main.go
info "cf-scanner 编译完成 → $PROJECT_DIR/cf-scanner"

# ── 5. 完成 ──
echo ""
echo -e "${GREEN}${BOLD}✅ 安装完成，开始运行${NC}"
echo ""
echo -e "  ${CYAN}项目目录:${NC} $PROJECT_DIR"
echo -e "  ${CYAN}更新:${NC} bash $PROJECT_DIR/install.sh update"
echo -e "  ${CYAN}卸载:${NC} bash $PROJECT_DIR/install.sh uninstall"
echo ""

exec python3 "$PROJECT_DIR/run.py"
