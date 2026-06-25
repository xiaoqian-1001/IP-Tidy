#!/bin/bash
# IP-Tidy WEB 模式启动脚本
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "============================================"
echo "  IP-Tidy WEB 模式"
echo "============================================"
echo ""

# Check dependencies
if ! python3 -c "import flask" 2>/dev/null; then
    echo "[!] 安装 Flask..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3-flask 2>/dev/null || pip3 install --break-system-packages flask
fi

cd "$SCRIPT_DIR"
exec python3 web_server.py --host 0.0.0.0 --port 8899
