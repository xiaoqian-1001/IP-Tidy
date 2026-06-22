#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf-ip-scanner — 从 ASN 拉取 IP，masscan 扫描，检测 Cloudflare 反代节点
用法: python3 run.py AS209242 [AS3214 ...]
"""
import sys, os, subprocess, json, urllib.request, multiprocessing, socket, time, re
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


# ── 智能 masscan 速率探测 ──
def probe_masscan_rate():
    """实测网卡发包上限，返回最优速率"""
    iface = None
    try:
        r = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"],
                           capture_output=True, text=True, timeout=5)
        m = __import__("re").search(r"dev\s+(\S+)", r.stdout)
        if m:
            iface = m.group(1)
    except Exception:
        pass
    if not iface:
        for name in ["eth0", "ens3", "enp0s3", "enp1s0", "ens5"]:
            if os.path.exists(f"/sys/class/net/{name}/statistics/tx_packets"):
                iface = name
                break
    if not iface:
        cores = multiprocessing.cpu_count()
        return max(1000, min(cores * 1000, 16000))

    cidrs = [a for a in sys.argv[1:] if not a.startswith("--") and "/" in a]
    if not cidrs:
        cidrs = ["1.1.1.0/24", "8.8.8.0/24", "9.9.9.0/24"]
    sample = cidrs[:50]
    tmp_cidr = "/tmp/.masscan_rate_test"
    with open(tmp_cidr, "w") as f:
        f.write("\n".join(sample))

    best_rate = 2000
    test_rate = 1000
    max_test = 200000
    probe_sec = 8

    while test_rate <= max_test:
        try:
            with open(f"/sys/class/net/{iface}/statistics/tx_packets") as f:
                tx_before = int(f.read().strip())
        except Exception:
            break

        proc = subprocess.Popen(
            ["masscan", "-iL", tmp_cidr, "-p", "443",
             "--rate", str(test_rate), "-oX", "/dev/null"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(probe_sec)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            pass

        try:
            with open(f"/sys/class/net/{iface}/statistics/tx_packets") as f:
                tx_after = int(f.read().strip())
        except Exception:
            break

        actual_pps = (tx_after - tx_before) / probe_sec
        ratio = actual_pps / test_rate

        if ratio >= 0.7:
            best_rate = test_rate
            test_rate *= 2
        elif ratio >= 0.3:
            best_rate = max(2000, int(actual_pps * 0.8))
            break
        else:
            break

    try:
        os.remove(tmp_cidr)
    except Exception:
        pass
    return best_rate


CPU_CORES, RAM_MB = detect_hardware()
MASSCAN_RATE    = probe_masscan_rate()
CF_SCANNER_CONC = max(200, min(CPU_CORES * 100, 500))
API_CONCURRENT  = min(CPU_CORES * 16, 32)
API_CHUNK       = 2000 if RAM_MB < 1024 else 5000

print(f"  硬件: {CPU_CORES}核 {RAM_MB}MB → masscan {MASSCAN_RATE}pps cf-scanner {CF_SCANNER_CONC}c API {API_CONCURRENT}c")

# ── 获取公网 IP (NAT/Docker 环境兼容) ──
def get_public_ip():
    """获取公网出口 IP，HTTP API → DNS 多重兜底，局域网也能正确获取"""
    # ── HTTP API（首选，速度快） ──
    apis = [
        ("https://api.ipify.org", 5),          # 国际
        ("https://api-ipv4.ip.sb/ip", 5),      # 国内可用
        ("https://ifconfig.me/ip", 5),          # 备用
        ("https://icanhazip.com", 5),           # 备用
    ]
    for url, timeout in apis:
        try:
            return urllib.request.urlopen(url, timeout=timeout).read().decode("utf-8").strip()
        except Exception:
            continue

    # ── DNS 方式（不依赖 HTTP，局域网 NAT 后也能正确获取公网出口 IP） ──
    dns_queries = [
        (["dig", "+short", "myip.opendns.com", "@resolver1.opendns.com"], 5),
        (["dig", "TXT", "+short", "o-o.myaddr.l.google.com", "@ns1.google.com"], 5),
        (["dig", "+short", "whoami.akamai.net", "@ns1-1.akamaitech.net"], 5),
    ]
    for cmd, timeout in dns_queries:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = r.stdout.strip().strip('"')
            if out and "." in out and out.count(".") == 3:
                parts = out.split(".")
                if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    return out
        except Exception:
            continue

    return "127.0.0.1"

# ── 获取局域网 IP（下载链接用，不走出口 IP） ──
def get_lan_ip():
    """获取本机局域网 IP，用于下载链接；家用宽带出口 IP 无法直连"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    return "127.0.0.1"

# ── 公网 IP + 运营商检测 ──
def detect_isp():
    """检测本机公网 IP 及运营商，返回 (ip, country, isp_name)"""
    ip = get_public_ip()
    print(f"\n  本机公网 IP: {ip}")
    if ip == "127.0.0.1":
        print("  (无法获取公网 IP，请检查网络连接，跳过运营商检测)")
        return ip, "", ""
    try:
        token = None
        token_file = Path("/root/.ipinfo_token")
        if token_file.is_file():
            token = token_file.read_text().strip()
        url = f"https://ipinfo.io/{ip}/json"
        if token:
            url += f"?token={token}"
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
            country = data.get("country", "")
            org = data.get("org", "")
            city = data.get("city", "")
            if country == "CN":
                isp = org.split(" ", 1)[-1] if org else "未知"
                print(f"  地区: {city}, {country}  🇨🇳  运营商: {isp}")
            else:
                isp = org
                print(f"  地区: {city}, {country}  机构: {org}")
            return ip, country, isp
    except Exception as e:
        print(f"  (无法获取详情: {e})")
    return ip, "", ""

GLOBAL_IP, GLOBAL_COUNTRY, GLOBAL_ISP = detect_isp()

# 国内运营商链路限速：网卡能发多少 ≠ 运营商能放多少
# 家宽上行通常 20-50Mbps，但运营商会限速大量 raw SYN 包
# 未知地区也保守限制，避免不慎打满运营商链路
if GLOBAL_COUNTRY in ("CN", "") and MASSCAN_RATE > 8000:
    print(f"  ⚠ 国内运营商链路，masscan 速率从 {MASSCAN_RATE}pps 降至 8000pps")
    MASSCAN_RATE = 8000

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
    """Expand CIDR ranges to individual IPs (obsolete - masscan reads CIDRs directly)"""
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

# ── 端口解析 ──
with open(BASE / "ports.txt") as f:
    _default_ports = [l.strip() for l in f if l.strip() and not l.startswith("#")]
DEFAULT_PORTS = ",".join(_default_ports)

def parse_ports(port_str):
    """解析端口字符串: 443 或 8443-8550 或 443,8443,2053-2096"""
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            if '-' in part:
                a, b = part.split('-', 1)
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
def run_masscan(ports_str=None):
    ports = ports_str if ports_str else DEFAULT_PORTS
    if not ports or ports == ",":
        ports = DEFAULT_PORTS
    result_file = BASE / "masscan_result.txt"
    ip_file = BASE / "cidrs.txt"

    # 清理上次残留（可能 root 所有，普通用户改不了 → sudo rm）
    if result_file.exists():
        if os.geteuid() == 0:
            result_file.unlink()
        else:
            subprocess.run(["sudo", "rm", "-f", str(result_file)], check=False)

    # masscan 需要 root 权限
    sudo = [] if os.geteuid() == 0 else ["sudo"]
    cmd = sudo + [
        "masscan", "-iL", str(ip_file),
        "-p", ports,
        "--rate", str(MASSCAN_RATE),
        "-oL", str(result_file),
        "--wait", "5"
    ]
    # 捕获 stderr 画进度条，不刷屏
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

    # sudo 创建的文件归 root → chown 回当前用户
    if os.geteuid() != 0:
        uid = os.getuid()
        gid = os.getgid()
        subprocess.run(["sudo", "chown", f"{uid}:{gid}", str(result_file)], check=False)

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

    # 捕获 stdout 解析进度画进度条
    proc = subprocess.Popen(
        [str(CF_SCANNER), "-i", str(new_file), "-o", str(hits_file), "-c", str(CF_SCANNER_CONC)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    bar_width = 30
    last_pct = -1
    for line in proc.stdout:
        m = re.search(r"Scanned\s+\d+/(\d+)\s+\((\d+\.?\d*)%\)", line)
        if m:
            pct = min(float(m.group(2)), 100)
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
        raise subprocess.CalledProcessError(proc.returncode, proc.args)

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

# ── Step 6: 测速 ──
def speed_test():
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无节点，跳过")
        return

    lines = []
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("IP地址"):
                lines.append(line)
                continue
            lines.append(line)

    if len(lines) <= 1:
        print("  无节点，跳过")
        return

    header = lines[0]
    entries = lines[1:]
    total = len(entries)
    tested = 0

    print(f"  节点数: {total}")

    with open(verified_file, "w") as f:
        f.write(header + "\n")
        for entry in entries:
            parts = entry.split(",")
            if len(parts) < 9:
                continue
            ip, port = parts[0], parts[1]

            # TCP 延迟
            latency = 0
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                t0 = time.time()
                s.connect((ip, int(port)))
                latency = round((time.time() - t0) * 1000)
                s.close()
            except:
                pass

            # 下载速度 (通过 CF 节点下载 speed.cloudflare.com)，Mbps
            speed_mbps = 0
            if latency > 0:
                try:
                    r = subprocess.run([
                        "curl", "--connect-to", f"speed.cloudflare.com:443:{ip}:{port}",
                        "-o", "/dev/null", "-s", "-w", "%{speed_download}",
                        "--connect-timeout", "5", "--max-time", "20",
                        "https://speed.cloudflare.com/__down?bytes=10485760"
                    ], capture_output=True, text=True, timeout=25)
                    speed_bps = float(r.stdout.strip() or 0)
                    speed_mbps = round(speed_bps * 8 / 1000000, 2)
                except:
                    pass

            parts[6] = str(latency)
            parts[7] = str(speed_mbps)
            f.write(",".join(parts) + "\n")

            tested += 1
            pct = tested / total * 100
            bar_width = 30
            filled = int(bar_width * pct / 100)
            bar = "█" * filled + "░" * (bar_width - filled)
            sys.stderr.write(f"\r  [{bar}] {pct:.1f}% | 延迟 {latency}ms  {speed_mbps}Mbps  {'':20}")
            sys.stderr.flush()

    sys.stderr.write(f"\r  [{'█' * 30}] 100.0% | 测速完成: {total} 个节点{'':20}\n")

# ── 输出 + 下载链接 ──
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

    # ── 提供下载链接（局域网 + 公网双链接） ──
    lan_ip = get_lan_ip()
    port = 8899

    # 端口被占用 → 尝试释放或换端口
    import socket
    def _port_free(p):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(1)
            return sock.connect_ex(('127.0.0.1', p)) != 0
        finally:
            sock.close()

    def _kill_port(p):
        import signal
        try:
            out = subprocess.run(["ss", "-tlnp", f"sport = :{p}"],
                                 capture_output=True, text=True, timeout=5)
            for line in out.stdout.split("\n"):
                if f":{p}" in line and "users:" in line:
                    m = __import__("re").search(r"pid=(\d+)", line)
                    if m:
                        os.kill(int(m.group(1)), signal.SIGTERM)
                        time.sleep(0.5)
                        return True
        except:
            pass
        return False

    if not _port_free(port):
        print(f"  端口 {port} 被占用，尝试释放...")
        if _kill_port(port) and _port_free(port):
            print(f"  已释放端口 {port}")
        else:
            while not _port_free(port) and port < 9900:
                port += 1
            if port >= 9900:
                print(f"\n  ⚠️  找不到可用端口，跳过下载服务")
                print(f"  📄 结果文件: {output}")
                return

    _http_server = None
    try:
        print(f"\n  📥 下载链接 (按回车关闭):")
        print(f"  http://{lan_ip}:{port}/{output.name}  (本机)")
        public_ip = get_public_ip()
        if public_ip != "127.0.0.1" and public_ip != lan_ip:
            print(f"  http://{public_ip}:{port}/{output.name}  (公网)")
        print()
        _http_server = subprocess.Popen(
            ["python3", "-m", "http.server", str(port), "--directory", str(BASE)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        input()
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        if _http_server and _http_server.poll() is None:
            _http_server.terminate()
            _http_server.wait()

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
            print("用法: cmtjd AS209242")
            print("  ssh 断线不杀: screen -S scan → cmtjd AS209242 → Ctrl+A D")
            sys.exit(1)
        asns = [a.strip().replace("AS", "").replace("as", "") for a in raw.replace("，", ",").split(",") if a.strip()]
    else:
        # 支持: python3 run.py AS3214,AS906 或 python3 run.py AS3214 AS906 [-p 端口]
        args = sys.argv[1:]
        # 过滤 -p 及其参数
        i = 0
        asn_args = []
        while i < len(args):
            if args[i] == "-p":
                i += 2  # 跳过 -p 和它的参数
            else:
                asn_args.append(args[i])
                i += 1
        raw = ",".join(asn_args)
        asns = [a.strip().replace("AS", "").replace("as", "") for a in raw.replace("，", ",").split(",") if a.strip()]
        if not asns:
            print("用法: cmtjd AS209242 或 cmtjd AS209242 -p 8443")
            print("  ssh 断线不杀: screen -S scan → cmtjd AS209242 → Ctrl+A D")
            sys.exit(1)
    print(f"\n  ASN: {', '.join(f'AS{a}' for a in asns)}\n")

    # ── 端口选择 ──
    scan_ports = DEFAULT_PORTS
    if len(sys.argv) < 2:
        print(f"  默认端口: {DEFAULT_PORTS}")
        try:
            port_input = input("  回车使用默认，或输入自定义端口 (如 80 或 1-1000 或 80,443,8000-9000): ").strip()
        except (EOFError, KeyboardInterrupt):
            port_input = ""
        if port_input:
            parsed = parse_ports(port_input)
            if parsed:
                scan_ports = parsed
                print(f"  扫描端口: {scan_ports}")
    else:
        # 命令行模式支持 -p 参数
        for i, arg in enumerate(sys.argv[1:], 1):
            if arg == "-p" and i < len(sys.argv) - 1:
                scan_ports = parse_ports(sys.argv[i+1])
                print(f"  自定义端口: {scan_ports}")
                break

    steps = [
        ("1/6 ASN→CIDR", lambda: fetch_prefixes(asns)),
        ("2/6 masscan",   lambda: run_masscan(scan_ports)),
        ("3/6 cf-scanner", cf_scan),
        ("4/6 API精筛",   api_verify),
    ]

    # 测速：让用户选择
    choice = ""
    try:
        choice = input("\n  是否测速？(y/n，默认跳过): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        pass
    if choice == "y":
        steps.append(("6/6 测速", speed_test))
    else:
        print("  跳过测速\n")

    for label, fn in steps:
        print(f"\n  [{label}]")
        try:
            fn()
        except Exception as e:
            print(f"  ❌ 失败: {e}")
            sys.exit(1)

    output_csv(asns)
    print()
    print("  ───")
    print("  SSH 断线不杀: screen -S scan → cmtjd AS209242 → Ctrl+A D")
    print("  恢复: screen -r scan")
    print("\n✓ 完成\n")
