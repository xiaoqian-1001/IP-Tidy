"""IP-Tidy 共享工具层 -- 纯函数，无文件/IO 副作用"""

import os
import re
import sys
import time
import json
import random
import socket
import ipaddress
import threading
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Callable, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = Path(__file__).resolve().parent.parent
CF_SCANNER = BASE / "cf-scanner"
VERIFY_PY = BASE / "verify.py"
API_URL = "https://api.090227.xyz/check"
WIDE_PORTS = "912,22,80,443,8080,8443,2053,2083,2087,2096,10000-65535"
MASSCAN_BIN = "/usr/local/bin/masscan"
_MASSCAN_BATCH = 5000

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

SUBNET_SPLIT = 24
SUBNET_PROBE = 3
SUBNET_THRESHOLD = 20
SUBNET_PORT = 443
SUBNET_TIMEOUT = 3


def merge_cidrs(cidrs: list[str]) -> list[str]:
    nets = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if net.version == 4:
                nets.append(net)
        except ValueError:
            continue
    if not nets:
        return []
    collapsed = list(ipaddress.collapse_addresses(nets))
    collapsed.sort(key=lambda n: (n.prefixlen, int(n.network_address)))
    return [str(n) for n in collapsed]


def cidr_count(cidrs: list[str]) -> int:
    total = 0
    for c in cidrs:
        try:
            total += ipaddress.ip_network(c, strict=False).num_addresses
        except ValueError:
            pass
    return total


def subnet_split(cidr: str) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.prefixlen >= SUBNET_SPLIT:
        return [str(net)]
    return [str(s) for s in net.subnets(new_prefix=SUBNET_SPLIT)]


def quick_probe(ip: str, port: int, timeout: float) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except OSError:
        return False


def sample_ips(subnet: str, n: int) -> list[str]:
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = list(net.hosts())
    if len(hosts) <= n:
        return [str(h) for h in hosts]
    return [str(h) for h in random.sample(hosts, n)]


def random_ports(n: int = 5) -> str:
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


def port_count(port_str: str) -> int:
    total = 0
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
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


def split_port_batches(port_str: str) -> list[str]:
    segments = [s.strip() for s in port_str.split(",") if s.strip()]
    batches: list[str] = []
    current: list[str] = []
    cur = 0
    for seg in segments:
        if "-" in seg:
            try:
                a, b = seg.split("-", 1)
                pa, pb = int(a), int(b)
                n = pb - pa + 1
            except ValueError:
                n = 1
                pa = pb = 0
        else:
            n = 1
        if cur + n > _MASSCAN_BATCH and current:
            batches.append(",".join(current))
            current = []
            cur = 0
        if n > _MASSCAN_BATCH:
            for start in range(pa, pb + 1, _MASSCAN_BATCH):
                end = min(start + _MASSCAN_BATCH - 1, pb)
                batches.append(f"{start}-{end}")
        else:
            current.append(seg)
            cur += n
    if current:
        batches.append(",".join(current))
    return batches


def get_system_load() -> tuple[float, int]:
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


def adjust_concurrency(base: int, cores: int) -> int:
    load, mem = get_system_load()
    if load > cores:
        base = max(50, base // 2)
    if mem < 200:
        base = max(50, base // 2)
    elif mem < 500:
        base = max(50, int(base * 0.7))
    return base


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


def find_iface() -> Optional[str]:
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


def masscan_adapter_ip() -> Optional[str]:
    try:
        r = subprocess.run(["ip", "-4", "addr", "show", "scope", "global"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
            if m:
                ip = m.group(1)
                if not ip.startswith("127.") and not ip.startswith("169.254."):
                    return ip
    except Exception:
        pass
    return None


def masscan_bin() -> str:
    return shutil_which("masscan") or MASSCAN_BIN


def shutil_which(cmd: str) -> Optional[str]:
    try:
        import shutil
        return shutil.which(cmd)
    except Exception:
        return None


def probe_masscan_rate(quiet: bool = False) -> int:
    iface = find_iface()
    if not iface:
        cores = os.cpu_count() or 1
        return max(1000, min(cores * 1000, 16000))
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
    sudo_ok = os.geteuid() == 0
    if not sudo_ok:
        try:
            subprocess.run(["sudo", "-n", "true"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           stdin=subprocess.DEVNULL, timeout=2, check=True)
            sudo_ok = True
        except Exception:
            pass
    if not sudo_ok:
        cores = os.cpu_count() or 1
        return max(1000, min(cores * 1000, 16000))
    if not quiet:
        print("  探测 Masscan 最优扫描速率：", end="", flush=True)
    sample_cidrs = ["1.1.1.0/24", "8.8.8.0/24", "9.9.9.0/24"]
    tmp_cidr = "/tmp/.masscan_rate_test"
    tx_path = f"/sys/class/net/{iface}/statistics/tx_packets"
    with open(tmp_cidr, "w") as f:
        f.write("\n".join(sample_cidrs))
    best_rate, test_rate, probe_sec = 2000, 1000, 4
    try:
        while test_rate <= 200000:
            try:
                with open(tx_path) as f:
                    tx_before = int(f.read().strip())
            except (FileNotFoundError, OSError):
                break
            proc = subprocess.Popen(
                sudo + ["masscan", "-iL", tmp_cidr, "-p", "443",
                        "--rate", str(test_rate), "-oX", "/dev/null"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL)
            alive = True
            for _ in range(probe_sec * 2):
                time.sleep(0.5)
                rc = proc.poll()
                if rc is not None:
                    alive = rc == 0
                    break
            if not alive:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                break
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
    if not quiet:
        print(f"{best_rate} pps")
    return best_rate


def probe_masscan_rate_fast() -> int:
    cores = os.cpu_count() or 1
    return max(1000, min(cores * 1000, 16000))


def tcp_latency(ip: str, port: int, timeout: float = 5) -> int:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        s.connect((ip, port))
        lat = round((time.time() - t0) * 1000)
        s.close()
        return lat
    except OSError:
        return 0


def http_latency(ip: str, port: int = 443, timeout: float = 5) -> int:
    try:
        url = f"http://{ip}:{port}/"
        req = urllib.request.Request(url, method="HEAD")
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = round((time.time() - t0) * 1000)
        return elapsed
    except Exception:
        try:
            url = f"https://{ip}:{port}/"
            req = urllib.request.Request(url, method="HEAD")
            ctx = ssl_create_unverified()
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                elapsed = round((time.time() - t0) * 1000)
            return elapsed
        except Exception:
            return 0


def ssl_create_unverified():
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def cf_download(ip: str, port: str) -> float:
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


def test_one(parts: list[str]) -> tuple[str, int, float]:
    ip, port = parts[0], parts[1]
    lat = tcp_latency(ip, int(port))
    spd = cf_download(ip, port) if lat > 0 else 0.0
    hlat = http_latency(ip, int(port)) if lat > 0 else 0
    result = parts[:]
    result[6] = str(lat)
    result[7] = str(round(spd, 2))
    return ",".join(result), lat, spd


def read_masscan_stderr(proc, prefix: str = "",
                        progress_callback: Optional[Callable] = None) -> list[str]:
    lines: list[str] = []
    t0 = time.time()
    last_progress = t0
    def _reader():
        try:
            for line in proc.stderr:
                lines.append(line)
        except (ValueError, OSError):
            pass
    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    idx = 0
    seen_100 = False
    while True:
        t.join(timeout=0.3)
        while idx < len(lines):
            m = re.search(r"(\d+\.?\d*)%\s*done", lines[idx])
            if m:
                pct = min(float(m.group(1)), 100)
                if pct >= 100:
                    seen_100 = True
                last_progress = time.time()
                elapsed = last_progress - t0
                if progress_callback:
                    progress_callback(pct, "")
            idx += 1
        if not t.is_alive():
            break
        if proc.poll() is not None:
            t.join(timeout=2.0)
            break
        if seen_100 and time.time() - last_progress > 10:
            break
        if time.time() - last_progress > 60:
            proc.kill()
            proc.wait()
            break
    return lines


def read_default_ports(ports_file: Optional[Path] = None) -> str:
    if ports_file is None:
        ports_file = BASE / "ports.txt"
    if ports_file.exists():
        ports = []
        for line in ports_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.isdigit() and 1 <= int(line) <= 65535:
                ports.append(line)
        if ports:
            return ",".join(ports)
    return "443,8443,2053,2083,2087,2096"


def resolve_port_list(port_mode: str, custom_ports: str,
                      ports_file: Optional[Path] = None) -> str:
    if port_mode == "default":
        return read_default_ports(ports_file)
    elif port_mode == "wide":
        return WIDE_PORTS
    elif port_mode == "random":
        return random_ports()
    elif port_mode == "custom":
        parsed = custom_ports.strip()
        if parsed:
            return parsed
        return read_default_ports(ports_file)
    else:
        return read_default_ports(ports_file)


def expand_cidrs(cidrs: list[str], max_ips: int = 5000,
                 sample: bool = False) -> list[str]:
    ips = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            hosts = list(net.hosts())
            if sample and len(hosts) > 3:
                hosts = random.sample(hosts, min(10, len(hosts)))
            for host in hosts:
                ips.append(str(host))
                if len(ips) >= max_ips:
                    return ips
        except ValueError:
            ips.append(cidr.strip())
            if len(ips) >= max_ips:
                return ips
    return ips


def finalize_results(results: list[dict], delay_threshold: int) -> list[dict]:
    filtered = [r for r in results
                if r.get("latency", 0) > 0 and r["latency"] <= delay_threshold]
    if not filtered:
        filtered = [r for r in results if r.get("latency", 0) > 0]
    if not filtered:
        filtered = results
    filtered.sort(key=lambda r: r.get("latency", 9999))
    return filtered


def build_dc_list(results: list[dict]) -> list[dict]:
    dc_map: dict[str, list[dict]] = {}
    for r in results:
        dc = r["colo"] or "Unknown"
        dc_map.setdefault(dc, []).append(r)
    dc_list = []
    for dc, items in dc_map.items():
        lats = [i.get("latency", 9999) for i in items if i.get("latency", 0) > 0]
        min_lat = min(lats) if lats else 0
        dc_list.append({
            "datacenter": dc,
            "city": items[0].get("region", ""),
            "country": items[0].get("country", ""),
            "ip_count": len(items),
            "min_latency": min_lat,
        })
    dc_list.sort(key=lambda d: d["min_latency"])
    return dc_list


def parse_targets(raw_args: list[str]) -> tuple[list[str], list[str], list[str]]:
    raw = ""
    if not raw_args:
        try:
            raw = input("  输入 ASN 或 CIDR (多个用逗号分隔): ").strip()
        except (EOFError, KeyboardInterrupt):
            try:
                with open("/dev/tty") as tty:
                    os.dup2(tty.fileno(), 0)
                raw = input("  输入 ASN 或 CIDR (多个用逗号分隔): ").strip()
            except Exception:
                print(f"\n  请在终端运行: cd {BASE} && python3 run.py\n")
                sys.exit(0)
    else:
        filtered = []
        skip_next = False
        for i, arg in enumerate(raw_args):
            if skip_next:
                skip_next = False
                continue
            if arg in ("-p", "-r"):
                skip_next = True
            elif arg in ("-s", "-w", "-R", "-d", "--smart"):
                pass
            else:
                filtered.append(arg)
        raw = ",".join(filtered)
    asns: list[str] = []
    v4_cidrs: list[str] = []
    for item in raw.replace("，", ",").split(","):
        item = item.strip()
        if not item:
            continue
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
                if net.version == 4:
                    v4_cidrs.append(str(net))
            except ValueError:
                pass
        else:
            asn = item.replace("AS", "").replace("as", "")
            if asn.isdigit():
                asns.append(asn)
    return asns, v4_cidrs
