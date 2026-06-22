#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf-ip-scanner -- 从 ASN 拉取 IP，masscan 扫描，检测 Cloudflare 反代节点
用法: python3 run.py AS209242 [AS3214 ...]
"""
import sys
import os
import re
import time
import json
import socket
import urllib.request
import subprocess
import multiprocessing
from pathlib import Path
from datetime import datetime
from typing import Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from lib.utils import (
    write_progress,
    write_progress_done,
    get_public_ip,
    get_lan_ip,
    detect_isp,
    parse_ports,
    port_is_free,
    kill_port_process,
)

BASE = Path(__file__).parent.resolve()
CF_SCANNER = BASE / "cf-scanner"
VERIFY_PY = BASE / "verify.py"
API_URL = "https://api.090227.xyz/check"


def detect_hardware() -> tuple[int, int]:
    """探测 CPU 核数和可用内存 (MB)"""
    cpu = multiprocessing.cpu_count()
    mem_mb = 512
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if "MemAvailable" in line:
                    mem_mb = int(line.split()[1]) // 1024
                    break
    except (FileNotFoundError, OSError):
        pass
    return cpu, mem_mb


def probe_masscan_rate(cidr_samples: list[str] | None = None) -> int:
    """实测网卡发包上限，返回最优 masscan 速率"""
    iface = _detect_network_iface()
    if not iface:
        cores = multiprocessing.cpu_count()
        return max(1000, min(cores * 1000, 16000))

    if not cidr_samples:
        cidr_samples = ["1.1.1.0/24", "8.8.8.0/24", "9.9.9.0/24"]
    sample = cidr_samples[:50]
    tmp_cidr = "/tmp/.masscan_rate_test"
    with open(tmp_cidr, "w") as f:
        f.write("\n".join(sample))

    best_rate = 2000
    test_rate = 1000
    max_test = 200000
    probe_sec = 8
    tx_path = f"/sys/class/net/{iface}/statistics/tx_packets"

    while test_rate <= max_test:
        try:
            with open(tx_path) as f:
                tx_before = int(f.read().strip())
        except (FileNotFoundError, OSError):
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
        except subprocess.TimeoutExpired:
            proc.kill()

        try:
            with open(tx_path) as f:
                tx_after = int(f.read().strip())
        except (FileNotFoundError, OSError):
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
    except OSError:
        pass
    return best_rate


def _detect_network_iface() -> Optional[str]:
    """探测主网卡接口名"""
    try:
        r = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            capture_output=True, text=True, timeout=5
        )
        m = re.search(r"dev\s+(\S+)", r.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    for name in ["eth0", "ens3", "enp0s3", "enp1s0", "ens5"]:
        if os.path.exists(f"/sys/class/net/{name}/statistics/tx_packets"):
            return name
    return None


# ── 惰性初始化的全局变量 ──
CPU_CORES = 1
RAM_MB = 512
MASSCAN_RATE = 2000
CF_SCANNER_CONC = 200
API_CONCURRENT = 8
API_CHUNK = 2000
DEFAULT_PORTS = "443,8443,2053,2083,2087,2096"
GLOBAL_IP = ""
GLOBAL_COUNTRY = ""
GLOBAL_ISP = ""


def _init_runtime() -> None:
    """初始化运行时全局变量（需在执行扫描前调用一次）"""
    global CPU_CORES, RAM_MB, MASSCAN_RATE, CF_SCANNER_CONC
    global API_CONCURRENT, API_CHUNK, DEFAULT_PORTS, GLOBAL_IP, GLOBAL_COUNTRY, GLOBAL_ISP

    CPU_CORES, RAM_MB = detect_hardware()
    MASSCAN_RATE = probe_masscan_rate()
    CF_SCANNER_CONC = max(200, min(CPU_CORES * 100, 500))
    API_CONCURRENT = min(CPU_CORES * 16, 32)
    API_CHUNK = 2000 if RAM_MB < 1024 else 5000

    print(f"  硬件: {CPU_CORES}核 {RAM_MB}MB -> masscan {MASSCAN_RATE}pps "
          f"cf-scanner {CF_SCANNER_CONC}c API {API_CONCURRENT}c")

    GLOBAL_IP, GLOBAL_COUNTRY, GLOBAL_ISP = detect_isp(get_public_ip())

    with open(BASE / "ports.txt") as f:
        _raw_ports = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    DEFAULT_PORTS = ",".join(_raw_ports)


def ensure_cf_scanner_executable() -> None:
    """确保 cf-scanner 有执行权限"""
    if CF_SCANNER.is_file() and not os.access(CF_SCANNER, os.X_OK):
        CF_SCANNER.chmod(0o755)


def fetch_prefixes(asns: list[str]) -> list[str]:
    """Step 1: ASN -> CIDR (RIPEStat API)"""
    cidrs: list[str] = []
    for asn in asns:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                count = 0
                for p in data["data"]["prefixes"]:
                    if ":" not in p["prefix"]:
                        cidrs.append(p["prefix"])
                        count += 1
                print(f"  AS{asn} -> {count} 个 IPv4 CIDR")
        except Exception as e:
            print(f"  AS{asn} -> 失败: {e}")
    cidr_file = BASE / "cidrs.txt"
    cidr_file.write_text("\n".join(cidrs))
    print(f"  共 {len(cidrs)} 个 CIDR")
    return cidrs


def run_masscan(ports_str: Optional[str] = None) -> int:
    """Step 2: masscan 端口扫描"""
    ports = ports_str if ports_str else DEFAULT_PORTS
    if not ports or ports == ",":
        ports = DEFAULT_PORTS

    result_file = BASE / "masscan_result.txt"
    ip_file = BASE / "cidrs.txt"

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

    proc = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        text=True, bufsize=1
    )
    stderr_lines: list[str] = []

    for line in proc.stderr:
        stderr_lines.append(line)
        m = re.search(r"(\d+\.?\d*)%\s*done", line)
        if m:
            pct = min(float(m.group(1)), 100)
            write_progress(pct)
    proc.wait()

    if proc.returncode == 0:
        write_progress_done()
    else:
        sys.stderr.write("\n")
        sys.stderr.flush()
        stderr_text = "".join(stderr_lines)
        if any(kw in stderr_text.lower() for kw in ("permission denied", "init: failed")):
            print("  [FAIL] masscan 需要 raw socket 权限，NAT 容器/部分 VPS 不支持")
            print("  -> 请换到 KVM VPS 或物理机运行")
        raise subprocess.CalledProcessError(proc.returncode, cmd)

    if os.geteuid() != 0:
        uid = os.getuid()
        gid = os.getgid()
        subprocess.run([
            "sudo", "chown", f"{uid}:{gid}", str(result_file)
        ], check=False)

    lines: list[str] = []
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


def cf_scan() -> int:
    """Step 3: cf-scanner 粗筛"""
    new_file = BASE / "masscan_result.txt"
    hits_file = BASE / "cf_hits.txt"

    if new_file.stat().st_size == 0:
        print("  无开放端口，跳过")
        return 0

    ensure_cf_scanner_executable()

    proc = subprocess.Popen(
        [str(CF_SCANNER), "-i", str(new_file), "-o", str(hits_file),
         "-c", str(CF_SCANNER_CONC)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )

    last_pct = -1
    pat_pct = re.compile(r"(\d+\.?\d*)%")
    for line in proc.stdout:
        m = pat_pct.search(line)
        if m:
            pct = min(float(m.group(1)), 100)
            if abs(pct - last_pct) >= 0.5:
                write_progress(pct)
                last_pct = pct
    proc.wait()

    if proc.returncode == 0:
        write_progress_done()
    else:
        sys.stderr.write("\n")
        sys.stderr.flush()
        raise subprocess.CalledProcessError(proc.returncode, proc.args)

    hits = sum(1 for _ in open(hits_file))
    print(f"  CF 节点: {hits}")
    return hits


def api_verify() -> int:
    """Step 4: API 精筛"""
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


def speed_test() -> None:
    """Step 5: 测速 (TCP 延迟 + CF 下载带宽)  -- 并行执行"""
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无节点，跳过")
        return

    lines: list[str] = []
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            lines.append(line)

    if len(lines) <= 1:
        print("  无节点，跳过")
        return

    header = lines[0]
    entries = lines[1:]
    total = len(entries)
    print(f"  节点数: {total}")

    updated: list[str] = [header]

    with ThreadPoolExecutor(max_workers=min(total, API_CONCURRENT)) as ex:
        future_map = {}
        for idx, entry in enumerate(entries):
            parts = entry.split(",")
            if len(parts) < 9:
                continue
            future = ex.submit(_measure_single, parts, idx)
            future_map[future] = (idx, parts)

        completed = 0
        for future in as_completed(future_map):
            idx, parts = future_map[future]
            new_parts, latency, speed_mbps = future.result()
            updated.append((",".join(new_parts), idx))
            completed += 1
            pct = completed / total * 100
            extra = f" | 延迟 {latency}ms  {speed_mbps}Mbps"
            write_progress(pct, extra)

    updated.sort(key=lambda x: x[1])
    with open(verified_file, "w") as f:
        for row in updated:
            if isinstance(row, str):
                f.write(row + "\n")
            else:
                f.write(row[0] + "\n")

    write_progress_done(f" | 测速完成: {total} 个节点")


def _measure_single(parts: list[str], _idx: int) -> tuple[list[str], int, float]:
    """测量单个节点延迟和速度（供线程池调用）"""
    ip, port = parts[0], parts[1]
    latency = _measure_tcp_latency(ip, int(port))
    speed_mbps = _measure_cf_download(ip, port) if latency > 0 else 0
    parts[6] = str(latency)
    parts[7] = str(speed_mbps)
    return parts, latency, speed_mbps


def _measure_tcp_latency(ip: str, port: int) -> int:
    """TCP 连接延迟测量 (ms)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        t0 = time.time()
        s.connect((ip, port))
        latency = round((time.time() - t0) * 1000)
        s.close()
        return latency
    except OSError:
        return 0


def _measure_cf_download(ip: str, port: str) -> float:
    """通过 CF 节点下载 speed.cloudflare.com 测速 (Mbps)"""
    try:
        r = subprocess.run([
            "curl", "--connect-to", f"speed.cloudflare.com:443:{ip}:{port}",
            "-o", "/dev/null", "-s", "-w", "%{speed_download}",
            "--connect-timeout", "5", "--max-time", "20",
            "https://speed.cloudflare.com/__down?bytes=10485760"
        ], capture_output=True, text=True, timeout=25)
        speed_bps = float(r.stdout.strip() or 0)
        return round(speed_bps * 8 / 1000000, 2)
    except (ValueError, subprocess.TimeoutExpired, OSError):
        return 0


def output_csv(asns: list[str]) -> None:
    """输出 CSV 并提供下载链接"""
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无结果")
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    asn_tag = "_".join(asns)
    output = BASE / f"output_{asn_tag}_{ts}.csv"

    parsed_lines: list[str] = []
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("IP地址"):
                continue
            if line.count(",") >= 8:
                parsed_lines.append(line)

    with open(output, "w") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for parsed_line in parsed_lines:
            f.write(parsed_line + "\n")

    print(f"\n  结果: {len(parsed_lines)} 条 -> {output.name}")
    _serve_download(output)


def _serve_download(file_path: Path) -> None:
    """启动临时 HTTP 下载服务"""
    lan_ip = get_lan_ip()
    port = 8899

    if not port_is_free(port):
        print(f"  端口 {port} 被占用，尝试释放...")
        if kill_port_process(port) and port_is_free(port):
            print(f"  已释放端口 {port}")
        else:
            while not port_is_free(port) and port < 9900:
                port += 1
            if port >= 9900:
                print(f"\n  [!] 找不到可用端口，跳过下载服务")
                print(f"  [file] 结果文件: {file_path}")
                return

    http_server: Optional[subprocess.Popen] = None
    try:
        print(f"\n  [download] 下载链接 (按回车关闭):")
        print(f"  http://{lan_ip}:{port}/{file_path.name}  (本机)")
        public_ip = get_public_ip()
        if public_ip not in ("127.0.0.1", lan_ip):
            print(f"  http://{public_ip}:{port}/{file_path.name}  (公网)")
        print()
        http_server = subprocess.Popen(
            ["python3", "-m", "http.server", str(port), "--directory", str(BASE)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        input()
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        if http_server and http_server.poll() is None:
            http_server.terminate()
            http_server.wait()


def _parse_asn_args(args: list[str]) -> list[str]:
    """从命令行参数中提取 ASN 列表"""
    raw = ""
    if len(args) < 1:
        try:
            raw = input("  输入 ASN 编号 (多个用逗号分隔): ").strip()
        except (EOFError, KeyboardInterrupt):
            try:
                with open("/dev/tty") as tty:
                    os.dup2(tty.fileno(), 0)
                raw = input("  输入 ASN 编号 (多个用逗号分隔): ").strip()
            except Exception:
                print(f"\n  请在终端运行: cd {BASE} && python3 run.py\n")
                sys.exit(0)
    else:
        filtered = []
        i = 0
        while i < len(args):
            if args[i] == "-p":
                i += 2
            else:
                filtered.append(args[i])
                i += 1
        raw = ",".join(filtered)
    return _normalize_asns(raw)


def _normalize_asns(raw: str) -> list[str]:
    """标准化 ASN 输入"""
    asns = [
        a.strip().replace("AS", "").replace("as", "")
        for a in raw.replace("，", ",").split(",") if a.strip()
    ]
    return asns


def _parse_port_arg(args: list[str]) -> str:
    """从命令行参数中解析 -p 端口参数"""
    for idx, arg in enumerate(args):
        if arg == "-p" and idx + 1 < len(args):
            parsed = parse_ports(args[idx + 1])
            if parsed:
                print(f"  自定义端口: {parsed}")
                return parsed
            break
    return DEFAULT_PORTS


def main() -> None:
    """主入口"""
    _init_runtime()
    args = sys.argv[1:]
    asns = _parse_asn_args(args)

    if not asns:
        print("用法: python3 run.py AS209242 或 python3 run.py AS209242,AS3214")
        sys.exit(1)

    print(f"\n  ASN: {', '.join(f'AS{a}' for a in asns)}\n")

    scan_ports = DEFAULT_PORTS
    if len(args) < 1:
        print(f"  默认端口: {DEFAULT_PORTS}")
        try:
            port_input = input(
                "  回车使用默认，或输入自定义端口 (如 80 或 1-1000 或 80,443,8000-9000): "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            port_input = ""
        if port_input:
            parsed = parse_ports(port_input)
            if parsed:
                scan_ports = parsed
                print(f"  扫描端口: {scan_ports}")
    else:
        scan_ports = _parse_port_arg(args)

    steps: list[tuple[str, Callable[[], object]]] = [
        ("1/6 ASN->CIDR",    lambda: fetch_prefixes(asns)),
        ("2/6 masscan",       lambda: run_masscan(scan_ports)),
        ("3/6 cf-scanner",    cf_scan),
        ("4/6 API精筛",       api_verify),
    ]

    try:
        choice = input("\n  是否测速？(y/n，默认跳过): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        choice = ""
    if choice == "y":
        steps.append(("6/6 测速", speed_test))
    else:
        print("  跳过测速\n")

    for label, fn in steps:
        print(f"\n  [{label}]")
        try:
            fn()
        except Exception as e:
            print(f"  [FAIL] 失败: {e}")
            sys.exit(1)

    output_csv(asns)
    print("\n[OK] 完成\n")


if __name__ == "__main__":
    main()
