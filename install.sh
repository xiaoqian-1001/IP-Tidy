#!/usr/bin/env bash
set -euo pipefail

# ASNIPtest 一键安装 / 更新 / 卸载
#   curl -fsSL <raw_url> | bash                  # 一键安装
#   bash install.sh                              # 菜单选择
#   bash install.sh update / uninstall           # 直接执行

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; NC='\033[0m'
BOLD='\033[1m'

PROJECT_DIR="$HOME/ASNIPtest"
REPO_URL="https://github.com/e13815332/ASNIPtest.git"
VERSION_FILE="$PROJECT_DIR/VERSION"

read_version() {
    if [ -f "$VERSION_FILE" ]; then
        cat "$VERSION_FILE"
    else
        echo "v1.1.0"
    fi
}

logo() {
    local ver
    ver=$(read_version)
    echo -e "${CYAN}${BOLD}"
    echo "   =============================="
    echo "         ASNIPtest  ${ver}"
    echo "   ASN -> masscan -> CF 节点"
    echo "   =============================="
    echo -e "${NC}"
}

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${RED}[!]${NC} $*"; }

do_uninstall() {
    echo ""
    for d in "$PROJECT_DIR" "$HOME/cf-ip-scanner.tmp"; do
        if [ -d "$d" ]; then
            rm -rf "$d"
            info "已删除 $d"
        fi
    done
    echo ""
    echo -e "${GREEN}[OK] 卸载完成${NC}"
}

do_update() {
    if [ ! -d "$PROJECT_DIR/.git" ]; then
        warn "项目未安装，请先安装"
        return 1
    fi
    local old_ver new_ver
    old_ver=$(read_version)
    info "当前版本: $old_ver -> 检查更新..."
    (cd "$PROJECT_DIR" && git pull origin main --ff-only)
    new_ver=$(read_version)
    if [ "$old_ver" = "$new_ver" ]; then
        info "已是最新版本 $new_ver"
    else
        info "${YELLOW}$old_ver -> $new_ver${NC} 已更新"
        info "重新编译 cf-scanner..."
        rm -f "$PROJECT_DIR/cf-scanner"
        build_cf_scanner
    fi
    echo ""
    echo -e "${GREEN}[OK] 版本 $new_ver${NC}"
}

ensure_go() {
    local go_ver="1.22.2"
    local go_arch
    go_arch=$(uname -m)
    case "$go_arch" in
        x86_64)  go_arch="linux-amd64" ;;
        aarch64) go_arch="linux-arm64" ;;
        *)       go_arch="linux-amd64" ;;
    esac

    if command -v go &>/dev/null; then
        local go_cur
        go_cur=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
        local go_major="${go_cur%%.*}"
        local go_minor="${go_cur#*.}"
        if [ "$go_major" -gt 1 ] || { [ "$go_major" -eq 1 ] && [ "$go_minor" -ge 22 ]; }; then
            info "Go $go_cur 已安装"
            return 0
        fi
        warn "Go $go_cur 版本过低，需要 >=1.22"
    fi

    warn "安装 Go $go_ver ..."
    local downloaded=false
    for go_url in \
        "https://golang.google.cn/dl/go${go_ver}.${go_arch}.tar.gz" \
        "https://go.dev/dl/go${go_ver}.${go_arch}.tar.gz"; do
        if curl -fsSL --connect-timeout 10 "$go_url" -o /tmp/go.tar.gz 2>/dev/null; then
            downloaded=true
            break
        fi
        warn "  下载失败: $go_url"
    done
    if ! $downloaded; then
        warn "Go 下载失败，请手动安装 Go >=1.22 后重试"
        exit 1
    fi
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:$PATH"
    for rc in "$HOME/.profile" "$HOME/.bashrc"; do
        if ! grep -q '/usr/local/go/bin' "$rc" 2>/dev/null; then
            echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$rc"
        fi
    done
    info "Go $go_ver 安装完成"
}

install_pkgs() {
    local pkgs=("masscan" "libpcap-dev" "prips" "dnsutils" "python3" "git")
    local to_install=()
    for pkg in "${pkgs[@]}"; do
        if command -v "$pkg" &>/dev/null || dpkg -l "$pkg" &>/dev/null 2>&1 || rpm -q "$pkg" &>/dev/null 2>&1; then
            continue
        fi
        to_install+=("$pkg")
    done
    if [ ${#to_install[@]} -eq 0 ]; then
        return 0
    fi

    if command -v apt &>/dev/null; then
        $SUDO apt update -qq
        $SUDO apt install -y -qq "${to_install[@]}"
    elif command -v yum &>/dev/null; then
        $SUDO yum install -y -q "${to_install[@]}"
    elif command -v dnf &>/dev/null; then
        $SUDO dnf install -y -q "${to_install[@]}"
    else
        warn "未检测到包管理器，请手动安装: ${to_install[*]}"
    fi
}

build_cf_scanner() {
    local src_dir="$PROJECT_DIR/cf-scanner-src"
    cd "$src_dir"
    local goamd=""
    if ! grep -q avx2 /proc/cpuinfo 2>/dev/null; then
        goamd="GOAMD64=v2"
    fi
    env $goamd go build -o "$PROJECT_DIR/cf-scanner" main.go
    chmod +x "$PROJECT_DIR/cf-scanner"
    info "cf-scanner 编译完成"
}

do_install() {
    logo

    if [ "$(uname -s)" != "Linux" ]; then
        warn "当前仅支持 Linux"
        exit 1
    fi
    [ "$(id -u)" = "0" ] && SUDO="" || SUDO="sudo"

    for d in "$HOME/cf-ip-scanner.tmp" "$PROJECT_DIR.tmp"; do
        if [ -d "$d" ]; then
            warn "清理旧缓存: $d"
            rm -rf "$d"
        fi
    done

    info "检查系统依赖..."
    install_pkgs
    ensure_go

    if [ -d "$PROJECT_DIR/.git" ]; then
        if [ -f "$PROJECT_DIR/VERSION" ] && [ -f "$PROJECT_DIR/run.py" ]; then
            info "项目已存在 ($(read_version))，更新中..."
            (cd "$PROJECT_DIR" && git pull origin main --ff-only)
        else
            warn "检测到损坏安装，重新安装..."
            rm -rf "$PROJECT_DIR"
            git clone --depth 1 --branch main "$REPO_URL" "$PROJECT_DIR"
        fi
    elif [ -d "$PROJECT_DIR" ]; then
        warn "检测到旧版残留，清理..."
        rm -rf "$PROJECT_DIR"
        info "克隆项目..."
        git clone --depth 1 --branch main "$REPO_URL" "$PROJECT_DIR"
    else
        info "克隆项目..."
        git clone --depth 1 --branch main "$REPO_URL" "$PROJECT_DIR"
    fi

    info "编译 cf-scanner..."
    rm -f "$PROJECT_DIR/cf-scanner"
    build_cf_scanner

    local wrapper="/usr/local/bin/cmtjd"
    info "注册快捷命令 cmtjd -> $wrapper"
    cat > "/tmp/cmtjd_wrapper" << 'WRAPEOF'
#!/usr/bin/env bash
PROJECT_DIR="$HOME/ASNIPtest"
case "${1:-}" in
    update)    exec bash "$PROJECT_DIR/install.sh" update ;;
    uninstall) exec bash "$PROJECT_DIR/install.sh" uninstall ;;
    "")        exec python3 "$PROJECT_DIR/run.py" ;;
    *)         exec python3 "$PROJECT_DIR/run.py" "$@" ;;
esac
WRAPEOF
    $SUDO mv "/tmp/cmtjd_wrapper" "$wrapper"
    $SUDO chmod +x "$wrapper"
    info "快捷命令已就绪: cmtjd                   (输入 ASN 扫描)"
    info "                   cmtjd update            (更新)"
    info "                   cmtjd uninstall         (卸载)"

    echo ""
    echo -e "${GREEN}${BOLD}[OK] 安装完成，开始运行${NC}"
    echo ""
    exec python3 "$PROJECT_DIR/run.py"
}

show_menu() {
    logo
    echo "  请选择:"
    echo "    ${CYAN}1${NC}) 安装 / 更新"
    echo "    ${CYAN}2${NC}) 仅更新"
    echo "    ${CYAN}3${NC}) 卸载"
    echo ""
    read -rp "  输入 [1-3]: " choice
    case "$choice" in
        1) do_install ;;
        2) do_update || exit 1 ;;
        3) do_uninstall ;;
        *) warn "无效选择" ; exit 1 ;;
    esac
}

ACTION="${1:-}"

if [ -n "$ACTION" ]; then
    case "$ACTION" in
        install)   do_install ;;
        update)    do_update || exit 1 ;;
        uninstall) do_uninstall ;;
        *)         warn "未知操作: $ACTION (支持: install / update / uninstall)" ; exit 1 ;;
    esac
elif [ -t 0 ]; then
    show_menu
else
    do_install
fi
