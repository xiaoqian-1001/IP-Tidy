#!/usr/bin/env python3
"""
ASNIPtest -- ASN -> CIDR -> masscan -> CF 反代节点检测 -> CSV 输出
用法: python3 run.py AS209242 [AS3214 ...] [-p PORTS]
"""

import sys
import os
import re
import time
import json
import random
import socket
import argparse
import subprocess
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
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
WIDE_PORTS = "912,22,80,443,8080,8443,2053,2083,2087,2096,10000-65535"
_MASSCAN_BATCH = 5000

# (start, end, weight) — 20000-60000 权重 10 倍
_RANDOM_ZONES: list[tuple[int, int, int]] = [
    (22, 22, 2), (80, 80, 2), (443, 443, 2),
    (912, 912, 2), (2053, 2053, 2),
    (2083, 2087, 2), (8080, 8080, 2), (8443, 8443, 2),
    (10000, 19999, 2),
    (20000, 60000, 10),
    (60001, 65535, 3),
]

_SPEED_TESTS = [
    ("speed.cloudflare.com", "https://speed.cloudflare.com/__down?bytes=1048576",   1,   "1MB"),
    ("speed.cloudflare.com", "https://speed.cloudflare.com/__down?bytes=10485760",  10,  "10MB"),
    ("speed.cloudflare.com", "https://speed.cloudflare.com/__down?bytes=100000000", 100, "100MB"),
    ("cloudflare.cdn.openbsd.org", "https://cloudflare.cdn.openbsd.org/pub/OpenBSD/7.3/src.tar.gz", 0, "CDN"),
]


def _random_ports(n: int = 5) -> str:
    zones = [z[:2] for z in _RANDOM_ZONES]
    weights = [z[2] for z in _RANDOM_ZONES]
    seen: set[int] = set()
    result: list[str] = []
    attempts = 0
    while len(result) < n and attempts < n * 20:
        start, end = random.choices(zones, weights=weights, k=1)[0]
        port = random.randint(start, end)
        if port not in seen:
            seen.add(port)
            result.append(str(port))
        attempts += 1
    random.shuffle(result)
    return ",".join(result)


def _port_count(port_str: str) -> int:
    total = 0
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                pa, pb = int(a), int(b)
                if 1 <= pa <= pb <= 65535:
                    total += pb - pa + 1
            except ValueError:
                pass
        elif part.isdigit():
            p = int(part)
            if 1 <= p <= 65535:
                total += 1
    return total


def _split_port_batches(port_str: str) -> list[str]:
    segments = [s.strip() for s in port_str.split(",") if s.strip()]
    batches: list[str] = []
    current: list[str] = []
    cur = 0
    for seg in segments:
        n = 1
        if "-" in seg:
            try:
                a, b = seg.split("-", 1)
                n = int(b) - int(a) + 1
            except ValueError:
                pass
        if cur + n > _MASSCAN_BATCH and current:
            batches.append(",".join(current))
            current = []
            cur = 0
        current.append(seg)
        cur += n
    if current:
        batches.append(",".join(current))
    return batches if len(batches) > 1 else [port_str]


def _get_system_load() -> tuple[float, int]:
    cpu = 0.0
    try:
        with open("/proc/loadavg") as f:
            cpu = float(f.read().split()[0])
    except Exception:
        pass
    mem = 512
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if "MemAvailable" in line:
                    mem = int(line.split()[1]) // 1024
                    break
    except Exception:
        pass
    return cpu, mem


def _adjust_concurrency(base: int, cores: int) -> int:
    load, mem = _get_system_load()
    if load > cores:
        base = max(50, base // 2)
    if mem < 200:
        base = max(50, base // 2)
    elif mem < 500:
        base = max(50, int(base * 0.7))
    return base

_version = "unknown"
try:
    _vp = BASE / "VERSION"
    if _vp.is_file():
        _version = _vp.read_text().strip()
except OSError:
    pass
VERSION = _version


@dataclass
class ScannerConfig:
    cpu: int = 1
    ram_mb: int = 512
    masscan_rate: int = 2000
    cf_concurrency: int = 200
    api_concurrency: int = 8
    api_chunk: int = 2000
    scan_ports: str = "443,8443,2053,2083,2087,2096"
    global_ip: str = ""
    global_country: str = ""
    global_isp: str = ""


def detect_hardware() -> tuple[int, int]:
    cpu = os.cpu_count() or 1
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


def probe_masscan_rate() -> int:
    iface = _find_iface()
    if not iface:
        cores = os.cpu_count() or 1
        return max(1000, min(cores * 1000, 16000))

    sample_cidrs = ["1.1.1.0/24", "8.8.8.0/24", "9.9.9.0/24"]
    tmp_cidr = "/tmp/.masscan_rate_test"
    tx_path = f"/sys/class/net/{iface}/statistics/tx_packets"

    with open(tmp_cidr, "w") as f:
        f.write("\n".join(sample_cidrs))

    best_rate, test_rate, probe_sec = 2000, 1000, 8
    try:
        while test_rate <= 200000:
            try:
                with open(tx_path) as f:
                    tx_before = int(f.read().strip())
            except (FileNotFoundError, OSError):
                break

            proc = subprocess.Popen(
                ["masscan", "-iL", tmp_cidr, "-p", "443",
                 "--rate", str(test_rate), "-oX", "/dev/null"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(probe_sec)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

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
    finally:
        try:
            os.remove(tmp_cidr)
        except OSError:
            pass
    return best_rate


def _find_iface() -> Optional[str]:
    try:
        r = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            capture_output=True, text=True, timeout=5)
        m = re.search(r"dev\s+(\S+)", r.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    for name in ("eth0", "ens3", "enp0s3", "enp1s0", "ens5"):
        if os.path.exists(f"/sys/class/net/{name}/statistics/tx_packets"):
            return name
    return None


def init_runtime() -> ScannerConfig:
    cfg = ScannerConfig()
    cfg.cpu, cfg.ram_mb = detect_hardware()
    cfg.masscan_rate = probe_masscan_rate()
    cfg.cf_concurrency = max(200, min(cfg.cpu * 100, 500))
    cfg.api_concurrency = min(cfg.cpu * 16, 32)
    cfg.api_chunk = 2000 if cfg.ram_mb < 1024 else 5000

    with open(BASE / "ports.txt") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    cfg.scan_ports = ",".join(lines)

    print(f"  硬件: {cfg.cpu}核 {cfg.ram_mb}MB  "
          f"masscan={cfg.masscan_rate}pps  cf={cfg.cf_concurrency}c  api={cfg.api_concurrency}c")

    cfg.global_ip, cfg.global_country, cfg.global_isp = detect_isp(get_public_ip())
    return cfg


def ensure_cf_scanner() -> None:
    if not CF_SCANNER.is_file():
        print("  [FAIL] cf-scanner 未找到，请先编译: cd cf-scanner-src && go build -o ../cf-scanner main.go")
        sys.exit(1)
    if not os.access(CF_SCANNER, os.X_OK):
        CF_SCANNER.chmod(0o755)


# ── Pipeline Steps ──

def step_fetch_prefixes(cfg: ScannerConfig, asns: list[str]) -> list[str]:
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
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            print(f"  AS{asn} -> 失败: {e}")
    (BASE / "cidrs.txt").write_text("\n".join(cidrs))
    print(f"  共 {len(cidrs)} 个 CIDR")
    if not cidrs:
        print("  [FAIL] 无可用 CIDR，请检查 ASN 是否正确")
        sys.exit(1)
    return cidrs


def step_masscan(cfg: ScannerConfig) -> int:
    ip_file = BASE / "cidrs.txt"
    if not ip_file.exists() or ip_file.stat().st_size == 0:
        print("  [FAIL] cidrs.txt 为空，跳过 masscan")
        return 0

    xml_file = BASE / "masscan_result.xml"
    if xml_file.exists():
        try:
            xml_file.unlink()
        except OSError:
            pass

    batches = _split_port_batches(cfg.scan_ports)
    total_ports = _port_count(cfg.scan_ports)
    if len(batches) > 1:
        print(f"  端口总数 {total_ports} -> {len(batches)} 批次扫描 (~{_MASSCAN_BATCH}/批)")

    all_open: list[str] = []
    batch_total = len(batches)

    for bi, batch_ports in enumerate(batches):
        batch_xml = xml_file if batch_total == 1 else BASE / f"masscan_batch_{bi + 1}.xml"

        sudo = [] if os.geteuid() == 0 else ["sudo"]
        cmd = sudo + [
            "masscan", "-iL", str(ip_file),
            "-p", batch_ports,
            "--rate", str(cfg.masscan_rate),
            "-oX", str(batch_xml),
            "--wait", "5",
        ]

        prefix = f"[{bi + 1}/{batch_total}] " if batch_total > 1 else ""
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        stderr_lines: list[str] = []
        t0 = time.time()
        for line in proc.stderr:
            stderr_lines.append(line)
            m = re.search(r"(\d+\.?\d*)%\s*done", line)
            if m:
                pct = min(float(m.group(1)), 100)
                elapsed = time.time() - t0
                eta = (elapsed / pct * (100 - pct)) if pct > 0 else 0
                extra = f" | ETA {int(eta // 60)}m {int(eta % 60)}s" if pct > 0.5 else ""
                write_progress(pct, prefix + extra)
        proc.wait()

        if proc.returncode != 0:
            sys.stderr.write("\n")
            sys.stderr.flush()
            err = "".join(stderr_lines).lower()
            if "permission denied" in err or "init: failed" in err:
                print("  [FAIL] masscan 需要 raw socket 权限")
            raise subprocess.CalledProcessError(
                proc.returncode, cmd, output=None,
                stderr="".join(stderr_lines))

        write_progress_done(prefix)

        if os.geteuid() != 0:
            subprocess.run(["sudo", "chown",
                            f"{os.getuid()}:{os.getgid()}", str(batch_xml)], check=False)

        # Parse batch XML
        try:
            tree = ET.parse(batch_xml)
            for host in tree.getroot().findall("host"):
                addr = host.find("address")
                if addr is None:
                    continue
                ip = addr.get("addr", "")
                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    if state.get("reason", "") not in ("syn-ack", "synack"):
                        continue
                    portid = port.get("portid", "")
                    if ip and portid:
                        all_open.append(f"{ip}:{portid}")
        except ET.ParseError:
            pass

        # Cleanup batch XML if multi-batch
        if batch_total > 1:
            try:
                batch_xml.unlink()
            except OSError:
                pass

    text_file = BASE / "masscan_result.txt"
    text_file.write_text("\n".join(all_open) + "\n")
    print(f"  开放端口: {len(all_open)} (syn-ack 确认)")
    return len(all_open)


def step_cf_scan(cfg: ScannerConfig) -> int:
    input_file = BASE / "masscan_result.txt"
    hits_file = BASE / "cf_hits.txt"

    if input_file.stat().st_size == 0:
        print("  无开放端口，跳过")
        return 0

    ensure_cf_scanner()

    adj = _adjust_concurrency(cfg.cf_concurrency, cfg.cpu)
    if adj != cfg.cf_concurrency:
        print(f"  cf-scanner 并发: {cfg.cf_concurrency} -> {adj} (系统负载)")
        cfg.cf_concurrency = adj

    proc = subprocess.Popen(
        [str(CF_SCANNER), "-i", str(input_file), "-o", str(hits_file),
         "-c", str(cfg.cf_concurrency)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    pat = re.compile(r"(\d+\.?\d*)%")
    last_pct = -1
    t0 = time.time()
    for line in proc.stdout:
        m = pat.search(line)
        if m:
            pct = min(float(m.group(1)), 100)
            if abs(pct - last_pct) >= 0.5:
                elapsed = time.time() - t0
                eta = (elapsed / pct * (100 - pct)) if pct > 0 else 0
                extra = f" | ETA {int(eta // 60)}m {int(eta % 60)}s" if pct > 0.5 else ""
                write_progress(pct, extra)
                last_pct = pct
    proc.wait()

    if proc.returncode != 0:
        sys.stderr.write("\n"); sys.stderr.flush()
        raise subprocess.CalledProcessError(proc.returncode, proc.args)

    write_progress_done()
    with open(hits_file) as f:
        hits = sum(1 for _ in f)
    print(f"  CF 节点: {hits}")
    return hits


def step_api_verify(cfg: ScannerConfig) -> int:
    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"

    if not hits_file.exists() or hits_file.stat().st_size == 0:
        print("  无 CF 节点，跳过")
        if verified_file.exists():
            verified_file.unlink()
        return 0

    adj = _adjust_concurrency(cfg.api_concurrency, cfg.cpu)
    if adj != cfg.api_concurrency:
        print(f"  API 并发: {cfg.api_concurrency} -> {adj} (系统负载)")
        cfg.api_concurrency = adj

    subprocess.run([
        sys.executable, str(VERIFY_PY),
        "--input", str(hits_file),
        "--output", str(verified_file),
        "--api", API_URL,
        "--chunk", str(cfg.api_chunk),
        "--concurrent", str(cfg.api_concurrency),
    ], check=True)

    with open(verified_file) as f:
        passed = sum(1 for _ in f)
    print(f"  精筛通过: {passed}")
    return passed


def step_speed_test(cfg: ScannerConfig) -> None:
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无节点，跳过")
        return

    adj = _adjust_concurrency(cfg.api_concurrency, cfg.cpu)
    if adj != cfg.api_concurrency:
        print(f"  测速并发: {cfg.api_concurrency} -> {adj} (系统负载)")
        cfg.api_concurrency = adj

    with open(verified_file) as f:
        lines = [l.strip() for l in f
                 if l.strip() and not l.startswith("#")]
    if len(lines) <= 1:
        print("  无节点，跳过")
        return

    header, entries = lines[0], lines[1:]
    total = len(entries)
    print(f"  节点数: {total}")

    results: list[tuple[str, int]] = []
    with ThreadPoolExecutor(max_workers=min(total, cfg.api_concurrency)) as ex:
        fmap = {}
        for idx, entry in enumerate(entries):
            parts = entry.split(",")
            if len(parts) < 9:
                continue
            fmap[ex.submit(_test_one, parts)] = idx

        done = 0
        for future in as_completed(fmap):
            idx = fmap[future]
            line, lat, spd = future.result()
            results.append((line, idx))
            done += 1
            write_progress(done / total * 100,
                           f" | 延迟 {lat}ms  {spd}Mbps")

    results.sort(key=lambda x: x[1])
    with open(verified_file, "w") as f:
        f.write(header + "\n")
        for row, _ in results:
            f.write(row + "\n")
    write_progress_done(f" | 测速完成: {total} 个节点")


def _test_one(parts: list[str]) -> tuple[str, int, float]:
    ip, port = parts[0], parts[1]
    lat = _tcp_latency(ip, int(port))
    spd = _cf_download(ip, port) if lat > 0 else 0.0
    result = parts[:]
    result[6] = str(lat)
    result[7] = str(round(spd, 2))
    return ",".join(result), lat, spd


def _tcp_latency(ip: str, port: int) -> int:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        t0 = time.time()
        s.connect((ip, port))
        lat = round((time.time() - t0) * 1000)
        s.close()
        return lat
    except OSError:
        return 0


def _cf_download(ip: str, port: str) -> float:
    best = 0.0
    for host, url, size_mb, _label in _SPEED_TESTS:
        try:
            timeout = 15 if size_mb < 10 else 30
            r = subprocess.run([
                "curl", "--resolve", f"{host}:443:{ip}",
                "--connect-to", f"{host}:443:{ip}:{port}",
                "-o", "/dev/null", "-s", "-w", "%{speed_download}",
                "--connect-timeout", "5", "--max-time", str(timeout),
                url,
            ], capture_output=True, text=True, timeout=timeout + 5)
            mbps = round(float(r.stdout.strip() or 0) * 8 / 1_000_000, 2)
            if mbps > best:
                best = mbps
        except (ValueError, subprocess.TimeoutExpired, OSError):
            continue
    return best


def output_csv(asns: list[str]) -> None:
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无结果")
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = "_".join(asns)
    csv_path = BASE / f"output_{tag}_{ts}.csv"

    parsed: list[str] = []
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("IP"):
                continue
            if line.count(",") >= 8:
                parsed.append(line)

    with open(csv_path, "w") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for p in parsed:
            f.write(p + "\n")

    print(f"\n  结果: {len(parsed)} 条 -> {csv_path.name}")
    _serve_download(csv_path)


def _serve_download(file_path: Path) -> None:
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
                print("\n  [!] 无可用端口，跳过下载服务")
                print(f"  [file] 结果文件: {file_path}")
                return

    server: Optional[subprocess.Popen] = None
    try:
        print(f"\n  [download] 下载链接 (按回车关闭):")
        print(f"  http://{lan_ip}:{port}/{file_path.name}  (本机)")
        pub = get_public_ip()
        if pub not in ("127.0.0.1", lan_ip):
            print(f"  http://{pub}:{port}/{file_path.name}  (公网)")
        print()
        server = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(port),
             "--directory", str(BASE)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if sys.stdin.isatty():
            input()
        else:
            print("  (非交互终端，按 Ctrl+C 停止服务)")
            try:
                server.wait()
            except KeyboardInterrupt:
                pass
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        if server and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


def _parse_asns(raw_args: list[str]) -> list[str]:
    raw = ""
    if not raw_args:
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
        while i < len(raw_args):
            arg = raw_args[i]
            if arg in ("-p", "-r"):
                i += 2
            elif arg in ("-s", "-w", "-R"):
                i += 1
            else:
                filtered.append(arg)
                i += 1
        raw = ",".join(filtered)

    return [a.strip().replace("AS", "").replace("as", "")
            for a in raw.replace("，", ",").split(",") if a.strip()]


def _parse_custom_port(args: list[str]) -> Optional[str]:
    for i, a in enumerate(args):
        if a == "-p" and i + 1 < len(args):
            ports = parse_ports(args[i + 1])
            if ports:
                print(f"  自定义端口: {ports}")
                return ports
            break
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="xiaoqian",
        description=f"ASNIPtest {VERSION} -- ASN -> masscan -> CF 节点检测",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  xiaoqian AS209242\n"
               "  xiaoqian AS209242 -w -s\n"
               "  xiaoqian AS209242 -p 443,8443\n"
               "  xiaoqian AS209242 -w -r 4000")
    parser.add_argument("asns", nargs="*", help="ASN 编号 (可多个，空格或逗号分隔)")
    parser.add_argument("-p", "--ports", metavar="PORTS",
                        help="自定义扫描端口 (如 443 或 80,443 或 8000-9000)")
    parser.add_argument("-s", "--speed", action="store_true",
                        help="扫描完成后自动测速")
    parser.add_argument("-w", "--wide", action="store_true",
                        help=f"宽端口模式")
    parser.add_argument("-R", "--random", action="store_true",
                        help="随机 5 端口快速探测")
    parser.add_argument("-r", "--rate", metavar="PPS", type=int,
                        help="masscan 发包速率 (默认自动探测)")
    parser.add_argument("-v", "--version", action="version",
                        version=f"ASNIPtest {VERSION}")
    a = parser.parse_args()

    cfg = init_runtime()
    asns = _parse_asns(sys.argv[1:] if not a.asns else a.asns)

    if not asns:
        print("用法: xiaoqian AS209242 [AS3214 ...] [-p PORTS] [-s]")
        sys.exit(1)

    print(f"\n  ASN: {', '.join(f'AS{x}' for x in asns)}\n")

    if a.rate:
        cfg.masscan_rate = max(100, a.rate)
        print(f"  发包速率: {cfg.masscan_rate} pps (手动)")

    if a.ports:
        cfg.scan_ports = parse_ports(a.ports)
        if not cfg.scan_ports:
            print(f"  [FAIL] 无效端口: {a.ports}")
            sys.exit(1)
        print(f"  自定义端口: {cfg.scan_ports}")
    elif a.wide:
        cfg.scan_ports = WIDE_PORTS
        if not a.rate:
            cfg.masscan_rate = max(500, cfg.masscan_rate // 2)
        print(f"  宽端口模式: {_port_count(cfg.scan_ports)} 端口 ({cfg.masscan_rate} pps)")
    elif a.random:
        cfg.scan_ports = _random_ports()
        print(f"  随机端口: {cfg.scan_ports}")
    elif not sys.argv[1:] and not a.asns:
        print(f"  默认端口: {cfg.scan_ports}")
        print(f"  宽端口: {WIDE_PORTS}")
        try:
            inp = input("  回车默认 / w=宽端口 / r=随机5端口 / 自定义: ").strip()
        except (EOFError, KeyboardInterrupt):
            inp = ""
        if inp.lower() == "w":
            cfg.scan_ports = WIDE_PORTS
            cfg.masscan_rate = max(500, cfg.masscan_rate // 2)
            print(f"  宽端口模式: {_port_count(cfg.scan_ports)} 端口 ({cfg.masscan_rate} pps)")
        elif inp.lower() == "r":
            cfg.scan_ports = _random_ports()
            print(f"  随机端口: {cfg.scan_ports}")
        elif inp:
            parsed = parse_ports(inp)
            if parsed:
                cfg.scan_ports = parsed
                print(f"  扫描端口: {cfg.scan_ports}")
    else:
        cp = _parse_custom_port(sys.argv[1:])
        if cp:
            cfg.scan_ports = cp

    total_steps = 4
    do_speed = a.speed
    if not do_speed:
        try:
            ch = input("\n  是否测速？(y/n，默认跳过): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ch = ""
        do_speed = ch == "y"
    if do_speed:
        total_steps += 1
    else:
        print("  跳过测速\n")

    steps: list[tuple[str, Callable[[], object]]] = [
        ("1. ASN->CIDR",   lambda: step_fetch_prefixes(cfg, asns)),
        ("2. masscan",     lambda: step_masscan(cfg)),
        ("3. cf-scanner",  lambda: step_cf_scan(cfg)),
        ("4. API精筛",      lambda: step_api_verify(cfg)),
    ]
    if do_speed:
        steps.append((f"{total_steps}. 测速", lambda: step_speed_test(cfg)))

    # 清理上次运行的中间文件，防止残留数据污染
    for stale in ("cidrs.txt", "masscan_result.txt",
                  "masscan_result.xml", "cf_hits.txt", "verified.txt"):
        p = BASE / stale
        try:
            if p.exists():
                p.unlink()
        except OSError:
            pass
    for p in BASE.glob("masscan_batch_*.xml"):
        try:
            p.unlink()
        except OSError:
            pass

    for label, fn in steps:
        print(f"\n  [{label}]")
        try:
            fn()
        except Exception as e:
            print(f"  [FAIL] {e}")
            sys.exit(1)

    output_csv(asns)
    print("\n[OK] 完成\n")


if __name__ == "__main__":
    main()
