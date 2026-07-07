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
import urllib.error
import xml.etree.ElementTree as ET
import shutil
from pathlib import Path
from typing import Optional, Callable, Any
import http.client
import ssl as _ssl_mod

BASE = Path(__file__).resolve().parent.parent
CF_SCANNER = BASE / "cf-scanner"
VERIFY_PY = BASE / "verify.py"
API_URL = os.environ.get("IP_TIDY_API_URL", "https://api.090227.xyz/check")
WIDE_PORTS = "912,22,80,443,8080,8443,2053,2083,2087,2096,10000-65535"
MASSCAN_BIN = shutil.which("masscan") or "/usr/local/bin/masscan"
_MASSCAN_BATCH = 5000

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
    seen: set[int] = set()
    result: list[str] = []
    attempts = 0
    while len(result) < n and attempts < n * 20:
        port = random.randint(1, 65535)
        if port not in seen:
            seen.add(port)
            result.append(str(port))
        attempts += 1
    random.shuffle(result)
    return ",".join(result)


def random_probe_ports(n: int, existing_ports: str) -> str:
    existing: set[int] = set()
    for part in existing_ports.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                for p in range(int(a), int(b) + 1):
                    existing.add(p)
            except ValueError:
                pass
        elif part.isdigit():
            existing.add(int(part))
    result: list[str] = []
    attempts = 0
    hi_ranges = [(1, 9999), (10000, 19999), (20000, 60000), (60001, 65535)]
    while len(result) < n and attempts < n * 20:
        lo, hi = hi_ranges[attempts % 4]
        port = random.randint(lo, hi)
        if port not in existing:
            existing.add(port)
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


def parse_masscan_xml(xml_path: Path) -> list[str]:
    results: list[str] = []
    try:
        tree = ET.parse(xml_path)
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
                    results.append(f"{ip}:{portid}")
    except ET.ParseError:
        pass
    return results


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
    except (FileNotFoundError, OSError, ValueError):
        pass
    mem = 512
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if "MemAvailable" in line:
                    mem = int(line.split()[1]) // 1024
                    break
    except (FileNotFoundError, OSError, ValueError):
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
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
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
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass
    return None


def masscan_bin() -> str:
    return MASSCAN_BIN


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
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
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


def tcp_latency(ip: str, port: int, timeout: float = 5) -> int:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        s.connect((ip, port))
        lat = round((time.time() - t0) * 1000)
        s.close()
        return lat
    except (OSError, socket.timeout):
        return 0


def ssl_create_unverified():
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    return ctx


_DOWNLOAD_CAP_BYTES = 10 * 1024 * 1024


def cf_download(ip: str, port: str) -> float:
    best_window = 0.0
    target_port = int(port)
    ctx = ssl_create_unverified()
    for host, url, size_mb, _label in _SPEED_TESTS:
        try:
            path = url.split(host, 1)[1] if host in url else "/"
            timeout = 15 if size_mb < 10 else 30
            sock = socket.create_connection((ip, target_port), timeout=5)
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            ssock.settimeout(timeout)
            conn = http.client.HTTPSConnection(host, target_port)
            conn.sock = ssock
            conn.request("GET", path, headers={"Host": host})
            resp = conn.getresponse()
            if resp.status != 200:
                resp.read()
                resp.close()
                conn.close()
                continue

            window_start = time.time()
            window_bytes = 0
            peak_kbps = 0.0
            total = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                window_bytes += len(chunk)
                now = time.time()
                elapsed = now - window_start
                if elapsed >= 1.0:
                    kbps = (window_bytes / 1024) / elapsed
                    if kbps > peak_kbps:
                        peak_kbps = kbps
                    window_bytes = 0
                    window_start = now
                if total >= _DOWNLOAD_CAP_BYTES:
                    break
            resp.close()
            conn.close()
            if window_bytes > 0:
                leftover = time.time() - window_start
                kbps = (window_bytes / 1024) / leftover
                if kbps > peak_kbps:
                    peak_kbps = kbps
            mbps = round(peak_kbps * 8 / 1024, 2)
            if mbps > best_window:
                best_window = mbps
        except (OSError, socket.timeout, http.client.HTTPException,
                _ssl_mod.SSLError, urllib.error.URLError, ValueError):
            continue
    return best_window


def test_one(parts: list[str]) -> tuple[str, int, float]:
    ip, port = parts[0], parts[1]
    lat = tcp_latency(ip, int(port))
    spd = cf_download(ip, port) if lat > 0 else 0.0
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


def expand_cidrs(cidrs: list[str], max_ips: int = 5000,
                 sample: bool = False) -> list[str]:
    ips = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            if sample:
                hosts = list(net.hosts())
                for host in random.sample(hosts, min(10, len(hosts))):
                    ips.append(str(host))
                    if len(ips) >= max_ips:
                        return ips
            else:
                for host in net.hosts():
                    ips.append(str(host))
                    if len(ips) >= max_ips:
                        return ips
        except ValueError:
            ips.append(cidr.strip())
            if len(ips) >= max_ips:
                return ips
    return ips


def parse_targets(raw_args: list[str]) -> tuple[list[str], list[str], list[str]]:
    raw = ""
    if not raw_args:
        try:
            raw = input("  填写 ASN 编号或 CIDR 网段，多条记录用英文逗号分隔： ").strip()
        except (EOFError, KeyboardInterrupt):
            try:
                with open("/dev/tty") as tty:
                    os.dup2(tty.fileno(), 0)
                raw = input("  填写 ASN 编号或 CIDR 网段，多条记录用英文逗号分隔： ").strip()
            except (EOFError, KeyboardInterrupt, OSError):
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
    for item in raw.replace("，", ",").replace("、", ",").split(","):
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


INCR_DIR = BASE / ".ip-tidy-state"


def _incr_tag(asns: list[str], v4_cidrs: list[str]) -> str:
    if asns:
        return "asn_" + "_".join(sorted(asns))
    cidr_key = "cidr_" + "_".join(re.sub(r"[./]", "_", c) for c in sorted(v4_cidrs))
    return cidr_key[:64]


def load_incremental_state(tag: str) -> tuple[list[str], list[str]]:
    cidr_file = INCR_DIR / f"{tag}_cidrs.txt"
    results_file = INCR_DIR / f"{tag}_results.csv"
    saved_cidrs: list[str] = []
    saved_results: list[str] = []
    if cidr_file.exists():
        saved_cidrs = [l.strip() for l in cidr_file.read_text().splitlines() if l.strip()]
    if results_file.exists():
        saved_results = [l.rstrip("\n") for l in results_file.read_text().splitlines()]
    return saved_cidrs, saved_results


def save_incremental_state(tag: str, cidrs: list[str], results: list[str]) -> None:
    INCR_DIR.mkdir(parents=True, exist_ok=True)
    (INCR_DIR / f"{tag}_cidrs.txt").write_text("\n".join(cidrs) + "\n")
    (INCR_DIR / f"{tag}_results.csv").write_text("\n".join(results) + "\n")


def compute_cidr_diff(current: list[str], saved: list[str]) -> tuple[list[str], list[str]]:
    cur_set = set(current)
    sav_set = set(saved)
    new_cidrs = sorted(cur_set - sav_set)
    removed_cidrs = sorted(sav_set - cur_set)
    return new_cidrs, removed_cidrs
