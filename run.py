#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf-ip-scanner — 从 ASN 拉取 IP，masscan 扫描，检测 Cloudflare 反代节点
用法: python3 run.py AS209242 [AS3214 ...]
"""
import sys, os, subprocess, json, urllib.request, multiprocessing, socket
from pathlib import Path
from datetime import datetime

# ── 自适应硬件 ──
def detect_hardware():
    cpu = multiprocessing.cpu_count()
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if "MemAvailable" in line:
                    mem_mb = int(line.split()[1]) // 1024
                    break
    except:
        mem_mb = 512
    return cpu, mem_mb

CPU_CORES, RAM_MB = detect_hardware()
MASSCAN_RATE    = CPU_CORES * 1000
CF_SCANNER_CONC = max(200, min(CPU_CORES * 100, 500))
API_CONCURRENT  = min(CPU_CORES * 16, 32)
API_CHUNK       = 2000 if RAM_MB < 1024 else 5000

print(f"  硬件: {CPU_CORES}核 {RAM_MB}MB → masscan {MASSCAN_RATE}pps cf-scanner {CF_SCANNER_CONC}c API {API_CONCURRENT}c")

# ── 获取公网 IP (NAT/Docker 环境兼容) ──
def get_public_ip():
    """获取公网出口 IP，支持两个 API 互为备用"""
    apis = [
        ("https://api.ipify.org", 5),       # 国际，速度快
        ("https://api-ipv4.ip.sb/ip", 5),   # 国内可用，仅 IPv4
    ]
    for url, timeout in apis:
        try:
            return urllib.request.urlopen(url, timeout=timeout).read().decode("utf-8").strip()
        except Exception:
            continue
    return "127.0.0.1"

BASE      = Path(__file__).parent.resolve()
CF_SCANNER = BASE / "cf-scanner"
VERIFY_PY  = BASE / "verify.py"
API_URL    = "https://api.090227.xyz/check"

# 确保 cf-scanner 有执行权限 (git clone 不保留 +x)
if CF_SCANNER.is_file():
    CF_SCANNER.chmod(0o755)

# ── Step 1: ASN → CIDR ──
def fetch_prefixes(asns):
    cidrs = []
    for asn in asns:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                data = json.loads(resp.read())
                count = 0
                for p in data["data"]["prefixes"]:
                    if ":" not in p["prefix"]:  # IPv4 only
                        cidrs.append(p["prefix"])
                        count += 1
                print(f"  AS{asn} → {count} 个 IPv4 CIDR")
        except Exception as e:
            print(f"  AS{asn} → 失败: {e}")
    cidr_file = BASE / "cidrs.txt"
    cidr_file.write_text("\n".join(cidrs))
    print(f"  共 {len(cidrs)} 个 CIDR")
    return cidrs

# ── Step 2: CIDR → IP ──
def expand_ips():
    ip_file = BASE / "ips.txt"
    total = 0
    with open(ip_file, "w") as out:
        with open(BASE / "cidrs.txt") as f:
            for cidr in f:
                cidr = cidr.strip()
                if not cidr:
                    continue
                proc = subprocess.Popen(["prips", cidr], stdout=subprocess.PIPE, text=True, bufsize=1)
                for ip in proc.stdout:
                    out.write(ip)
                    total += 1
                proc.wait()
    print(f"  展开 {total:,} 个 IP")
    return total

# ── Step 3: masscan 端口扫描 ──
def run_masscan():
    ports = ",".join(line.strip() for line in open(BASE / "ports.txt") if line.strip() and not line.startswith("#"))
    result_file = BASE / "masscan_result.txt"
    ip_file = BASE / "ips.txt"

    # masscan 需要 root 权限
    sudo = [] if os.geteuid() == 0 else ["sudo"]
    cmd = sudo + [
        "masscan", "-iL", str(ip_file),
        "-p", ports,
        "--rate", str(MASSCAN_RATE),
        "-oL", str(result_file),
        "--wait", "5"
    ]
    subprocess.run(cmd, check=True)

    # 转换为 IP:port
    lines = []
    with open(result_file) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0] == "open":
                lines.append(f"{parts[3]}:{parts[2]}")
    result_file.write_text("\n".join(lines) + "\n")
    print(f"  开放端口: {len(lines)}")
    return len(lines)

# ── Step 4: cf-scanner 粗筛 ──
def cf_scan():
    new_file = BASE / "masscan_result.txt"
    hits_file = BASE / "cf_hits.txt"

    if new_file.stat().st_size == 0:
        print("  无开放端口，跳过")
        return 0

    if not os.access(CF_SCANNER, os.X_OK):
        os.chmod(CF_SCANNER, 0o755)
    subprocess.run([str(CF_SCANNER), "-i", str(new_file), "-o", str(hits_file), "-c", str(CF_SCANNER_CONC)], check=True)
    hits = sum(1 for _ in open(hits_file))
    print(f"  CF 节点: {hits}")
    return hits

# ── Step 5: API 精筛 ──
def api_verify():
    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"

    if not hits_file.exists() or hits_file.stat().st_size == 0:
        print("  无 CF 节点，跳过")
        return 0

    subprocess.run([
        "python3", str(VERIFY_PY),
        "--input", str(hits_file),
        "--output", str(verified_file),
        "--api", API_URL,
        "--chunk", str(API_CHUNK),
        "--concurrent", str(API_CONCURRENT)
    ], check=True)
    passed = sum(1 for _ in open(verified_file))
    print(f"  精筛通过: {passed}")
    return passed

# ── Step 6: 输出 + 下载链接 ──
def output_csv(asns):
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无结果")
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    asn_tag = "_".join(asns)
    output = BASE / f"output_{asn_tag}_{ts}.csv"

    lines = []
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("IP地址"):
                continue
            if line.count(",") >= 8:
                lines.append(line)

    with open(output, "w") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for line in lines:
            f.write(line + "\n")

    print(f"\n  结果: {len(lines)} 条 → {output.name}")

    # ── 提供下载链接 (支持 NAT/Docker 环境) ──
    try:
        ip = get_public_ip()
        port = 8899
        print(f"\n  📥 下载链接 (临时, 按回车关闭):")
        print(f"  http://{ip}:{port}/{output.name}")
        print()
        server = subprocess.Popen(
            ["python3", "-m", "http.server", str(port), "--directory", str(BASE)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        input()
        server.terminate()
        server.wait()
    except:
        pass

# ── Main ──
if __name__ == "__main__":
    if len(sys.argv) < 2:
        try:
            raw = input("  输入 ASN 编号 (多个用逗号分隔): ").strip()
        except (EOFError, KeyboardInterrupt):
            # 管道模式, 尝试接管 /dev/tty
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
        asns = [a.strip().replace("AS", "").replace("as", "") for a in raw.replace("，", ",").split(",") if a.strip()]
    else:
        # 支持: python3 run.py AS3214,AS906 或 python3 run.py AS3214 AS906
        raw = ",".join(sys.argv[1:])
        asns = [a.strip().replace("AS", "").replace("as", "") for a in raw.replace("，", ",").split(",") if a.strip()]
    print(f"\n  ASN: {', '.join(f'AS{a}' for a in asns)}\n")

    steps = [
        ("1/5 ASN→CIDR", lambda: fetch_prefixes(asns)),
        ("2/5 CIDR→IP",  expand_ips),
        ("3/5 masscan",   run_masscan),
        ("4/5 cf-scanner", cf_scan),
        ("5/5 API精筛",   api_verify),
    ]

    for label, fn in steps:
        print(f"\n  [{label}]")
        try:
            fn()
        except Exception as e:
            print(f"  ❌ 失败: {e}")
            sys.exit(1)

    output_csv(asns)
    print("\n✓ 完成\n")
