#!/usr/bin/env bash
set -euo pipefail

# IP-Tidy 一键安装/更新/卸载
#   curl -fsSL <raw_url> | bash
#   bash install.sh update / uninstall

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; NC='\033[0m'
BOLD='\033[1m'

PROJECT_DIR="$HOME/IP-Tidy"
REPO_URL="https://github.com/xiaoqian-1001/IP-Tidy.git"
VERSION_FILE="$PROJECT_DIR/VERSION"

if [ "$(id -u)" = "0" ]; then
    SUDO=""
else
    SUDO="sudo"
fi

read_version() { cat "$VERSION_FILE" 2>/dev/null || echo "unknown"; }

logo() {
    echo -e "${CYAN}${BOLD}"
    echo "   =============================="
    echo "          IP-Tidy  $(read_version)"
    echo "    CIDR/ASN -> masscan -> CF"
    echo "   =============================="
    echo -e "${NC}"
}

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${RED}[!]${NC} $*"; }

# ── Go 版本号从 go.mod 读取 ──
go_required_version() {
    local mod="$PROJECT_DIR/cf-scanner-src/go.mod"
    if [ -f "$mod" ]; then
        grep -oP 'go \K[0-9]+\.[0-9]+(\.[0-9]+)?' "$mod" | head -1
    else
        echo "1.22.2"
    fi
}

# ── 卸载 ──
do_uninstall() {
    echo ""
    echo -e "${YELLOW}确认卸载 IP-Tidy？此操作不可撤销。${NC}"
    read -rp "  输入 yes 确认: " confirm
    if [ "$confirm" != "yes" ]; then
        info "已取消"
        return 0
    fi
    for d in "$PROJECT_DIR" "$HOME/cf-ip-scanner.tmp"; do
        [ -d "$d" ] && rm -rf "$d" && info "已删除 $d"
    done
    local w="/usr/local/bin/xiaoqian"
    [ -f "$w" ] && sudo rm -f "$w" && info "已删除 $w"
    echo ""
    echo -e "${GREEN}[OK] 卸载完成${NC}"
}

# ── 更新 ──
do_update() {
    [ -d "$PROJECT_DIR/.git" ] || { warn "项目未安装"; return 1; }
    local old new
    old=$(read_version)
    info "当前: $old, 检查更新..."
    (cd "$PROJECT_DIR" && git pull origin main --ff-only) || { warn "更新失败"; return 1; }
    new=$(read_version)
    if [ "$old" = "$new" ]; then
        info "已是最新版本 $new"
    else
        info "${YELLOW}$old -> $new${NC}"
        rm -f "$PROJECT_DIR/cf-scanner"
        build_cf_scanner
    fi
    echo -e "${GREEN}[OK] $new${NC}"
}

# ── Go 安装 ──
ensure_go() {
    local go_ver required_ver="${1:-1.22.2}"
    go_ver="$required_ver"
    local go_arch
    go_arch=$(uname -m)
    case "$go_arch" in
        x86_64)  go_arch="linux-amd64" ;;
        aarch64) go_arch="linux-arm64" ;;
        *)       go_arch="linux-amd64" ;;
    esac

    if command -v go &>/dev/null; then
        local cur major minor
        cur=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
        major="${cur%%.*}"; minor="${cur#*.}"
        if [ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge 22 ]; }; then
            info "Go $cur 已安装"
            return 0
        fi
        warn "Go $cur 版本过低"
    fi

    info "安装 Go $go_ver ..."
    local downloaded=false
    local go_tmp
    go_tmp=$(mktemp /tmp/go.XXXXXX.tar.gz)
    for url in \
        "https://golang.google.cn/dl/go${go_ver}.${go_arch}.tar.gz" \
        "https://go.dev/dl/go${go_ver}.${go_arch}.tar.gz"; do
        if curl -fsSL --connect-timeout 10 "$url" -o "$go_tmp" 2>/dev/null; then
            downloaded=true; break
        fi
        warn "  下载失败: $url"
    done
    $downloaded || { warn "Go 下载失败"; exit 1; }

    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "$go_tmp"
    rm -f "$go_tmp"
    export PATH="/usr/local/go/bin:$PATH"
    for rc in "$HOME/.profile" "$HOME/.bashrc"; do
        if [ -f "$rc" ] && ! grep -q '/usr/local/go/bin' "$rc" 2>/dev/null; then
            echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$rc"
        fi
    done
    info "Go $go_ver 完成"
}

# ── 包安装 ──
install_pkgs() {
    local pkgs=("masscan" "dnsutils" "python3" "python3-pip" "git")
    local to_install=()
    for pkg in "${pkgs[@]}"; do
        command -v "$pkg" &>/dev/null && continue
        dpkg -l "$pkg" &>/dev/null 2>&1 && continue
        rpm -q "$pkg" &>/dev/null 2>&1 && continue
        to_install+=("$pkg")
    done
    [ ${#to_install[@]} -eq 0 ] && return 0

    if command -v apt &>/dev/null; then
        $SUDO apt update -qq && $SUDO apt install -y -qq "${to_install[@]}"
    elif command -v yum &>/dev/null; then
        $SUDO yum install -y -q "${to_install[@]}"
    elif command -v dnf &>/dev/null; then
        $SUDO dnf install -y -q "${to_install[@]}"
    else
        warn "未检测到包管理器，请手动安装: ${to_install[*]}"
    fi
}

# ── cf-scanner 编译 ──
build_cf_scanner() {
    local src="$PROJECT_DIR/cf-scanner-src"
    cd "$src"
    local goamd=""
    grep -q avx2 /proc/cpuinfo 2>/dev/null || goamd="GOAMD64=v2"
    env $goamd go build -ldflags="-s -w" -o "$PROJECT_DIR/cf-scanner" main.go
    chmod +x "$PROJECT_DIR/cf-scanner"
    info "cf-scanner 编译完成"
}

# ── 安装 ──
do_install() {
    logo
    [ "$(uname -s)" = "Linux" ] || { warn "仅支持 Linux"; exit 1; }

    for d in "$HOME/cf-ip-scanner.tmp" "$PROJECT_DIR.tmp"; do
        [ -d "$d" ] && { warn "清理: $d"; rm -rf "$d"; }
    done

    info "检查系统依赖..."
    install_pkgs

    info "安装 Python 依赖 (maxminddb)..."
    pip3 install --break-system-packages maxminddb 2>/dev/null || pip3 install maxminddb 2>/dev/null || warn "maxminddb 安装失败，离线 IP 查询不可用"

    local go_ver
    go_ver=$(go_required_version)
    info "Go 版本要求: $go_ver"
    ensure_go "$go_ver"

    if [ -d "$PROJECT_DIR/.git" ]; then
        if [ -f "$PROJECT_DIR/VERSION" ] && [ -f "$PROJECT_DIR/run.py" ]; then
            info "项目已存在，更新中..."
            (cd "$PROJECT_DIR" && git pull origin main --ff-only) || true
        else
            warn "损坏安装，重新克隆..."
            rm -rf "$PROJECT_DIR"
            git clone --depth 1 --branch main "$REPO_URL" "$PROJECT_DIR"
        fi
    elif [ -d "$PROJECT_DIR" ]; then
        warn "旧版残留，重新克隆..."
        rm -rf "$PROJECT_DIR"
        git clone --depth 1 --branch main "$REPO_URL" "$PROJECT_DIR"
    else
        git clone --depth 1 --branch main "$REPO_URL" "$PROJECT_DIR" || {
            warn "克隆失败，请检查网络"; exit 1; }
    fi

    rm -f "$PROJECT_DIR/cf-scanner"
    build_cf_scanner

    local w="/usr/local/bin/qian"
    info "注册快捷命令 -> $w"
    local wrapper
    wrapper=$(mktemp /tmp/qian_wrapper.XXXXXX)
    cat > "$wrapper" << 'WEOF'
#!/usr/bin/env bash
D="$HOME/IP-Tidy"
case "${1:-}" in
    update)    exec bash "$D/install.sh" update ;;
    uninstall) exec bash "$D/install.sh" uninstall ;;
    "")        exec python3 "$D/run.py" ;;
    *)         exec python3 "$D/run.py" "$@" ;;
esac
WEOF
    $SUDO mv "$wrapper" "$w" || {
        warn "无法安装快捷命令到 $w"
        warn "请手动运行: python3 $PROJECT_DIR/run.py"
    }
    $SUDO chmod +x "$w"
    info "命令: qian [ASN/CIDR...] [-p PORTS] [-w] [-s] [-d] [-g]"
    info "       qian -g (下载离线 GeoIP 数据库)"
    info "       qian update / uninstall"

    echo ""
    echo -e "${GREEN}${BOLD}[OK] 安装完成，启动中...${NC}"
    echo ""
    exec python3 "$PROJECT_DIR/run.py"
}

# ── 菜单 ──
show_menu() {
    logo
    echo "  1) 安装/更新"
    echo "  2) 仅更新"
    echo "  3) 卸载"
    read -rp "  选择 [1-3]: " c
    case "$c" in
        1) do_install ;;  2) do_update ;;  3) do_uninstall ;;
        *) warn "无效选择"; exit 1 ;;
    esac
}

# ── Main ──
case "${1:-}" in
    install)   do_install ;;
    update)    do_update ;;
    uninstall) do_uninstall ;;
    "")
        if [ -t 0 ]; then show_menu; else do_install; fi ;;
    *) warn "未知操作: $1 (支持 install/update/uninstall)"; exit 1 ;;
esac
