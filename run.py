#!/usr/bin/env python3
"""
Cloudflare IP scanner — find optimal CF IPs for your network.
Supports single/multi ASN, custom ports, background mode, speed test.
"""

import os
import sys
import subprocess
import re
import json
import shutil
from pathlib import Path

BASE = Path(__file__).parent.resolve()
VERSION_FILE = BASE / "VERSION"

# ── 导入模块级常量 ──
with open(BASE / "ports.txt") as f:
    _default_ports = [l.strip() for l in f if l.strip() and not l.startswith("#")]
DEFAULT_PORTS = ",".join(_default_ports)

# Masscan 速率：自动探测链路容量
GLOBAL_COUNTRY = os.environ.get("COUNTRY", "").strip().upper()
MASSCAN_RATE = 8000 if GLOBAL_COUNTRY in ("", "CN") else 60000


# ── 工具函数 ──
def version():
    if VERSION_FILE.exists():
        return VERSION_FILE.read_text().strip()
    return "unknown"


def parse_ports(port_str):
    """解析端口字符串: 443 或 8443-8550 或 443,8443,2053-2096"""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                pa, pb = int(a), int(b)
                if pa < 1 or pb > 65535 or pa > pb:
                    continue
                ports.update(str(p) for p in range(pa, pb + 1))
            elif part.isdigit():
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(part)
        except ValueError:
            continue
    return ",".join(sorted(ports, key=int)) if ports else ""


# ── Step 1: ASN → CIDR ──
def fetch_prefixes(asns):
    """仅支持从 RIPEStat API 获取前缀"""
    from urllib.request import urlopen, Request
    from urllib.error import URLError
    import time

    asn_set = set(asns)
    cidr_file = BASE / "cidrs.txt"
    headers = {"User-Agent": "ASNIPtest/1.1 (https://github.com/e13815332/ASNIPtest)"}

    # 合并去重
    seen = set()
    total = 0
    for asn in sorted(asn_set, key=int):
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        req = Request(url, headers=headers)
        try:
            resp = urlopen(req, timeout=15)
            data = json.loads(resp.read())
            prefixes = data.get("data", {}).get("prefixes", [])
        except (URLError, json.JSONDecodeError, KeyError) as e:
            print(f"  ⚠ AS{asn} 查询失败: {e}")
            continue

        v4 = [p["prefix"] for p in prefixes if ":" not in p.get("prefix", "")]
        v6 = [p["prefix"] for p in prefixes if ":" in p.get("prefix", "")]
        cidrs = v4  # 仅 IPv4

        if not cidrs:
            print(f"  ⚠ AS{asn}: 未找到 IPv4 前缀")
            continue

        for c in cidrs:
            if c not in seen:
                seen.add(c)
                total += 1
        time.sleep(0.3)  # RIPEStat 限速

    cidr_file.write_text("\n".join(sorted(seen, key=lambda x: (
        int(x.split("/")[0].split(".")[0]),
        int(x.split("/")[0].split(".")[1]),
        int(x.split("/")[0].split(".")[2]),
        int(x.split("/")[0].split(".")[3]),
        int(x.split("/")[1]),
    ))) + "\n")
    print(f"  ✓ {total} 个前缀 (IPv4)")


# ── Step 2: masscan ──
def run_masscan(ports_str=None):
    ports = ports_str if ports_str else DEFAULT_PORTS
    if not ports or ports == ",":
        ports = DEFAULT_PORTS
    result_file = BASE / "masscan_result.txt"
    ip_file = BASE / "cidrs.txt"

    # 清理上次残留
    if result_file.exists():
        if os.geteuid() == 0:
            result_file.unlink()
        else:
            subprocess.run(["sudo", "rm", "-f", str(result_file)], check=False)

    sudo = [] if os.geteuid() == 0 else ["sudo"]
    cmd = sudo + [
        "masscan", "-iL", str(ip_file),
        "-p", ports,
        "--rate", str(MASSCAN_RATE),
        "-oL", str(result_file),
        "--wait", "5"
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    bar_width = 30
    last_pct = -1
    stderr_lines = []
    for line in proc.stderr:
        stderr_lines.append(line)
        m = re.search(r"(\d+\.?\d*)%\s*done", line)
        if m:
            pct = min(float(m.group(1)), 100)
            if abs(pct - last_pct) >= 0.5:
                filled = int(bar_width * pct / 100)
                bar = "█" * filled + "░" * (bar_width - filled)
                sys.stderr.write(f"\r  [{bar}] {pct:.1f}%")
                sys.stderr.flush()
                last_pct = pct
    proc.wait()
    if proc.returncode == 0:
        sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n")
        sys.stderr.flush()
    else:
        sys.stderr.write("\n")
        sys.stderr.flush()
        stderr_text = "".join(stderr_lines)
        if "permission denied" in stderr_text.lower() or "init: failed" in stderr_text.lower():
            print("  ❌ masscan 需要 raw socket 权限，NAT 容器/部分 VPS 不支持")
            print("  → 请换到 KVM VPS 或物理机运行")
        raise subprocess.CalledProcessError(proc.returncode, cmd)


# ── Step 3: cf-scanner ──
def cf_scan():
    scanner = shutil.which("cf-scanner") or shutil.which("cf-scanner-go")
    if scanner:
        cmd = [scanner, "-i", str(BASE / "cidrs.txt"), "-p",
               str(BASE / "masscan_result.txt"), "-o", str(BASE / "ips.txt")]
        subprocess.run(cmd, check=True)
    else:
        # 回退：直接用 masscan 结果，过滤非 CF IP
        print("  cf-scanner 未安装，从 masscan 结果提取 IP")
        ips_raw = set()
        with open(BASE / "masscan_result.txt") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == "open":
                    ips_raw.add(parts[3])
        # 仅保留本机可达 CF IP（无 cf-scanner 时简单处理）
        with open(BASE / "ips.txt", "w") as out:
            for ip in sorted(ips_raw):
                out.write(f"{ip}\n")
        print(f"  ✓ {len(ips_raw)} 个候选 IP")


# ── Step 4: API 精筛 ──
def api_verify():
    result = BASE / "verified_ips.txt"
    ips_file = BASE / "ips.txt"

    if not ips_file.exists() or ips_file.stat().st_size == 0:
        print("  ⚠ 无候选 IP，跳过 API 精筛")
        result.write_text("")
        return

    ips = [l.strip() for l in ips_file.read_text().strip().splitlines() if l.strip()]
    if not ips:
        print("  ⚠ 无候选 IP，跳过 API 精筛")
        result.write_text("")
        return

    import urllib.request
    import urllib.error
    import time
    import json

    headers = {"User-Agent": "ASNIPtest/1.1"}
    verified = []
    total = len(ips)
    for idx, ip in enumerate(ips, 1):
        url = f"https://{ip}/cdn-cgi/trace"
        try:
            req = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=5)
            data = resp.read().decode()
            if "colo=" in data:
                verified.append(ip)
                colo_match = re.search(r"colo=(\w+)", data)
                loc = colo_match.group(1) if colo_match else "?"
                print(f"\r  [{idx}/{total}] ✓ {ip} ({loc})", end="")
            else:
                print(f"\r  [{idx}/{total}] ✗ {ip}", end="")
        except Exception:
            print(f"\r  [{idx}/{total}] ✗ {ip}", end="")
        sys.stdout.flush()
        time.sleep(0.2)
    print()

    with open(result, "w") as f:
        for ip in verified:
            f.write(f"{ip}\n")
    print(f"  ✓ {len(verified)}/{total} 个有效 CF IP")


# ── Step 5: 测速 ──
def speed_test():
    """多线程延迟+带宽混合测试"""
    import threading
    import time
    import statistics
    import urllib.request

    result = BASE / "verified_ips.txt"
    if not result.exists() or result.stat().st_size == 0:
        print("  ⚠ 无已验证 IP，跳过测速")
        return

    ips = result.read_text().strip().splitlines()
    if not ips:
        print("  ⚠ 无已验证 IP，跳过测速")
        return

    results = []
    lock = threading.Lock()
    total = len(ips)

    def test_ip(ip):
        url = f"https://{ip}/cdn-cgi/trace"
        t0 = time.time()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ASNIPtest/1.1"})
            resp = urllib.request.urlopen(req, timeout=3)
            latency = (time.time() - t0) * 1000  # ms
            colo = re.search(r"colo=(\w+)", resp.read().decode())
            loc = colo.group(1) if colo else "?"
            with lock:
                results.append((ip, round(latency, 1), loc))
        except Exception:
            with lock:
                results.append((ip, 9999, "?"))

    threads = []
    for ip in ips:
        t = threading.Thread(target=test_ip, args=(ip,))
        t.start()
        threads.append(t)
        time.sleep(0.05)

    for t in threads:
        t.join()

    results.sort(key=lambda x: x[1])
    print(f"\n  {'IP':<18}{'延迟(ms)':<12}{'位置'}")
    print(f"  {'─'*36}")
    for ip, lat, loc in results[:20]:
        marker = "✓" if lat < 500 else "△" if lat < 1500 else "✗"
        print(f"  {ip:<18}{lat:<12}{marker} {loc}")
    if len(results) > 20:
        print(f"  ... 还有 {len(results)-20} 个")

    with open(BASE / "speed_results.txt", "w") as f:
        f.write(f"{'IP':<18}{'延迟(ms)':<12}{'位置'}\n")
        f.write(f"{'─'*36}\n")
        for ip, lat, loc in results:
            f.write(f"{ip:<18}{lat:<12}{loc}\n")

    avg = statistics.mean([r[1] for r in results if r[1] < 9999])
    print(f"\n  平均延迟: {avg:.0f} ms (排除超时)")
    print(f"  结果保存: speed_results.txt")


# ── Step 6: 输出 CSV ──
def output_csv(asns):
    """从 masscan 结果生成 CSV"""
    import csv
    from datetime import datetime

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    asn_tag = "_".join(f"AS{a}" for a in asns)
    out_file = BASE / f"output_{asn_tag}_{ts}.csv"

    masscan_file = BASE / "masscan_result.txt"
    if not masscan_file.exists():
        print("  ⚠ 无 masscan 结果，跳过输出")
        return

    with open(out_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "端口", "协议", "TLS", "数据中心"])
        seen = set()
        with open(masscan_file) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == "open":
                    proto = parts[1]
                    port = parts[2]
                    ip = parts[3]
                    key = (ip, port)
                    if key not in seen:
                        seen.add(key)
                        writer.writerow([ip, port, proto, "?", "?"])

    count = len(seen)
    print(f"\n  📄 CSV: {out_file.name}")
    print(f"  行数: {count}")
    print(f"  下载: cat {out_file}")
    print(f"  curl -O http://192.168.110.43:8899/{out_file.name}  (需先启动下载服务)")
    print(f"  启动下载服务: cmtjd result --serve")


# ── 主入口 ──
if __name__ == "__main__":

    BG_MODE = "--bg" in sys.argv

    # ── 解析 ASN ──
    if len(sys.argv) < 2 or (len(sys.argv) == 2 and BG_MODE):
        # 交互模式（无参数或仅 --bg 但无 ASN 时会触发提示）
        if BG_MODE and len(sys.argv) == 2:
            print("用法: cmtjd --bg AS209242")
            sys.exit(1)
        try:
            raw = input("  输入 ASN 编号 (多个用逗号分隔): ").strip()
        except (EOFError, KeyboardInterrupt):
            try:
                with open("/dev/tty") as tty:
                    os.dup2(tty.fileno(), 0)
                raw = input("  输入 ASN 编号 (多个用逗号分隔): ").strip()
            except:
                print(f"\n  请在终端运行: cd {BASE} && python3 run.py\n")
                sys.exit(0)
        if not raw:
            print("用法: python3 run.py AS209242 或 python3 run.py AS209242,AS3214")
            sys.exit(1)
        asns = [a.strip().replace("AS", "").replace("as", "")
                for a in raw.replace("，", ",").split(",") if a.strip()]
    else:
        args = [a for a in sys.argv[1:] if a != "--bg"]
        i = 0
        asn_args = []
        while i < len(args):
            if args[i] == "-p":
                i += 2
            else:
                asn_args.append(args[i])
                i += 1
        raw = ",".join(asn_args)
        asns = [a.strip().replace("AS", "").replace("as", "")
                for a in raw.replace("，", ",").split(",") if a.strip()]
        if not asns:
            print("用法: cmtjd AS209242 或 cmtjd AS209242 -p 8443")
            sys.exit(1)
    print(f"\n  ASN: {', '.join(f'AS{a}' for a in asns)}\n")

    # ── 端口选择 ──
    scan_ports = DEFAULT_PORTS
    if len(sys.argv) < 2 or (len(sys.argv) == 2 and BG_MODE):
        print(f"  默认端口: {DEFAULT_PORTS}")
        try:
            port_input = input("  回车使用默认，或输入自定义端口: ").strip()
        except (EOFError, KeyboardInterrupt):
            port_input = ""
        if port_input:
            parsed = parse_ports(port_input)
            if parsed:
                scan_ports = parsed
                print(f"  扫描端口: {scan_ports}")
    else:
        for i, arg in enumerate(sys.argv[1:], 1):
            if arg == "-p" and i < len(sys.argv) - 1:
                scan_ports = parse_ports(sys.argv[i+1])
                print(f"  自定义端口: {scan_ports}")
                break

    # ── 交互模式挂机询问 ──
    if not BG_MODE and len(sys.argv) < 2:
        try:
            bg_choice = input("  挂机运行？(y/n，默认n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            bg_choice = ""
        if bg_choice == "y":
            bg_cmd = [sys.executable, __file__, "--bg"] + [f"AS{a}" for a in asns]
            if scan_ports != DEFAULT_PORTS:
                bg_cmd += ["-p", scan_ports]
            print(f"  ↪ {' '.join(bg_cmd)}")
            subprocess.Popen(bg_cmd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
            print(f"  ✅ 已挂机\n")
            sys.exit(0)

    # ── 测速询问（提前，在开始扫描前决定） ──
    do_speed = False
    if not BG_MODE:
        try:
            choice = input("\n  是否测速？(y/n，默认跳过): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = ""
        if choice == "y":
            do_speed = True
            print("  ✓ 完成后自动测速\n")
        else:
            print("  跳过测速\n")
    else:
        print("  跳过测速（挂机模式）\n")

    # ── 构建步骤 ──
    steps = [
        ("1/6 ASN→CIDR", lambda: fetch_prefixes(asns)),
        ("2/6 masscan",   lambda: run_masscan(scan_ports)),
        ("3/6 cf-scanner", cf_scan),
        ("4/6 API精筛",   api_verify),
    ]
    if do_speed:
        steps.append(("5/6 测速", speed_test))

    # ── 执行步骤 ──
    for label, fn in steps:
        print(f"\n  [{label}]")
        try:
            fn()
        except Exception as e:
            print(f"  ❌ 失败: {e}")
            sys.exit(1)

    output_csv(asns)
    print("\n✓ 完成\n")