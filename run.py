#!/usr/bin/env python3
"""
IP-Tidy -- ASN -> CIDR -> masscan -> CF 反代节点检测 -> CSV 输出
用法: python3 run.py AS209242 [...ASN] [-p PORTS]
       python3 run.py 1.2.3.0/24 [...CIDR] [-p PORTS]
"""

import sys
import os
import re
import time
import json
import random
import socket
import ssl
import ipaddress
import threading
import argparse
import subprocess
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Callable, Any
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
    c, C, print_banner, print_step, print_sep,
    print_hardware_info, print_result_header, print_total_time,
)
from lib.geoip import lookup as geo_lookup, is_available as geo_available, geo_update_interactive

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
    global_city: str = ""
    ip_mode: str = "all"  # "v4" | "v6" | "all"
    smart_mode: bool = False


def _split_v4_v6(cidrs: list[str]) -> tuple[list[str], list[str]]:
    """拆分 IPv4/IPv6 CIDR 列表，自动去重和合并"""
    v4, v6 = [], []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            v4.append(net)
        else:
            v6.append(net)

    def _merge(nets):
        if not nets:
            return []
        collapsed = list(ipaddress.collapse_addresses(nets))
        collapsed.sort(key=lambda n: (n.prefixlen, int(n.network_address)))
        return [str(n) for n in collapsed]

    return _merge(v4), _merge(v6)


def _cidr_count(cidrs: list[str]) -> int:
    """计算 CIDR 列表中包含的 IP 总数"""
    total = 0
    for c in cidrs:
        try:
            total += ipaddress.ip_network(c, strict=False).num_addresses
        except ValueError:
            pass
    return total

_SPEED_TESTS = [
    ("speed.cloudflare.com", "https://speed.cloudflare.com/__down?bytes=1048576",   1,   "1MB"),
    ("speed.cloudflare.com", "https://speed.cloudflare.com/__down?bytes=10485760",  10,  "10MB"),
    ("speed.cloudflare.com", "https://speed.cloudflare.com/__down?bytes=100000000", 100, "100MB"),
    ("cloudflare.cdn.openbsd.org", "https://cloudflare.cdn.openbsd.org/pub/OpenBSD/7.3/src.tar.gz", 0, "CDN"),
]

_SUBNET_SPLIT = 24        # CIDR >= /20 拆分到此粒度
_SUBNET_PROBE = 3         # 每子段抽样 IP 数
_SUBNET_THRESHOLD = 20    # 前缀小于此值触发拆分
_SUBNET_PORT = 443        # 探活端口
_SUBNET_TIMEOUT = 3       # 探活超时


def _subnet_split(cidr: str) -> list[str]:
    """将 CIDR 拆分为 /SUBNET_SPLIT 子网"""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.prefixlen >= _SUBNET_SPLIT:
        return [str(net)]
    return [str(s) for s in net.subnets(new_prefix=_SUBNET_SPLIT)]


def _quick_probe(ip: str, port: int, timeout: float) -> bool:
    """快速 TCP 探活，返回是否可达"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except OSError:
        return False


def _sample_ips(subnet: str, n: int) -> list[str]:
    """从子网中随机抽样 n 个 IP"""
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = list(net.hosts())
    if len(hosts) <= n:
        return [str(h) for h in hosts]
    chosen = random.sample(hosts, n)
    return [str(h) for h in chosen]


def step_smart_subnet(cfg: ScannerConfig, v4_cidrs: list[str]) -> list[str]:
    """存活预筛 + 子网分级: 大 CIDR 拆 /24 抽样探活，仅保留活跃子网"""
    step_start = time.time()

    if not v4_cidrs:
        return []

    to_probe: list[str] = []     # 子网列表
    probe_map: dict[str, list[str]] = {}  # 子网 -> 原 CIDR 映射 (用于日志)

    for cidr in v4_cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            to_probe.append(cidr)
            continue
        if net.prefixlen < _SUBNET_THRESHOLD:
            subs = _subnet_split(cidr)
            to_probe.extend(subs)
            for s in subs:
                probe_map[s] = cidr
        else:
            to_probe.append(cidr)
            probe_map[cidr] = cidr

    if len(to_probe) <= 1:
        print(f"  待探子网: {len(to_probe)} 段，跳过")
        return v4_cidrs

    total_subs = len(to_probe)
    total_samples = 0
    alive_subs: set[str] = set()
    dead_subs: list[str] = []

    print(f"  子网分级: {len(v4_cidrs)} CIDR -> {total_subs} 子段 ("
          f"每段抽 {_SUBNET_PROBE} IP 探活端口 {_SUBNET_PORT})")

    with ThreadPoolExecutor(max_workers=min(total_subs, cfg.api_concurrency * 4)) as ex:
        fmap: dict[Any, str] = {}
        for sub in to_probe:
            for ip in _sample_ips(sub, _SUBNET_PROBE):
                total_samples += 1
                fmap[ex.submit(_quick_probe, ip, _SUBNET_PORT, _SUBNET_TIMEOUT)] = sub

        done = 0
        for future in as_completed(fmap):
            sub = fmap[future]
            done += 1
            if done % 50 == 0 or done == total_samples:
                write_progress(done / total_samples * 100,
                               f" | 探活 {done}/{total_samples}")
            try:
                if future.result():
                    alive_subs.add(sub)
            except Exception:
                pass

    write_progress_done(" | 探活完成")

    for sub in to_probe:
        if sub not in alive_subs:
            dead_subs.append(sub)

    alive_cidrs = sorted(alive_subs)
    if dead_subs:
        # 合并回原 CIDR 显示
        dead_origin = set()
        for d in dead_subs:
            origin = probe_map.get(d, d)
            dead_origin.add(origin)
        alive_origin = set()
        for a in alive_cidrs:
            origin = probe_map.get(a, a)
            alive_origin.add(origin)

        saved = len(dead_subs)
        pct = saved / total_subs * 100
        print(f"  存活: {len(alive_origin)} CIDR ({len(alive_cidrs)} 子段)  |  "
              f"过滤死段: {saved} ({pct:.0f}%)")

        if not alive_cidrs:
            print(c("  [WARN] 所有子网均无响应 — 回退全量扫描", C.Y))
            return v4_cidrs
    else:
        print(f"  存活: {len(alive_cidrs)} 子段 (全通)")

    print(c(f"  本步耗时: {int(time.time() - step_start)}s", C.W))
    return alive_cidrs


def step_cert_enum(cfg: ScannerConfig) -> int:
    """TLS 证书反查: 从 CF 节点提取 SAN，解析 IP 后合并入结果"""
    step_start = time.time()
    verified_file = BASE / "verified.txt"

    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无节点，跳过证书反查")
        return 0

    entries: list[list[str]] = []
    header = ""
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("IP"):
                header = line
                continue
            parts = line.split(",")
            if len(parts) >= 9:
                entries.append(parts)

    if not entries:
        print("  无有效节点，跳过")
        return 0

    print(f"  证书反查: {len(entries)} 个节点 (TLS SAN 提取)")

    new_ips: dict[str, str] = {}  # ip -> source_ip

    def _extract_san(ip: str, port: str) -> list[str]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, int(port)), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    sans = []
                    for _, val in cert.get("subjectAltName", []):
                        sans.append(val)
                    return sans
        except Exception:
            return []

    total = len(entries)
    found = 0
    with ThreadPoolExecutor(max_workers=min(total, cfg.api_concurrency)) as ex:
        fmap = {}
        for idx, parts in enumerate(entries):
            fmap[ex.submit(_extract_san, parts[0], parts[1])] = idx

        done = 0
        for future in as_completed(fmap):
            idx = fmap[future]
            done += 1
            if done % 10 == 0:
                write_progress(done / total * 100, f" | 提取 {done}/{total}")
            try:
                sans = future.result()
            except Exception:
                continue
            for san in sans:
                try:
                    resolved = socket.getaddrinfo(san, None, socket.AF_INET,
                                                  socket.SOCK_STREAM)
                    for _, _, _, _, sockaddr in resolved:
                        ip_addr = sockaddr[0]
                        if ip_addr not in new_ips and ip_addr != entries[idx][0]:
                            new_ips[ip_addr] = entries[idx][0]
                            found += 1
                except (OSError, UnicodeError):
                    continue

    write_progress_done(f" | 新发现 IP: {found}")

    if not new_ips:
        print(c(f"  未发现新 IP (本步耗时: {int(time.time() - step_start)}s)", C.W))
        return 0

    print(f"  新发现 IP: {found} (来自 TLS SAN)")
    print(f"  交叉验证中...")

    cf_verified: list[list[str]] = []
    with ThreadPoolExecutor(max_workers=min(len(new_ips), cfg.api_concurrency)) as ex:
        vmap = {}
        for ip, src in new_ips.items():
            vmap[ex.submit(_verify_ip, ip)] = (ip, src)

        for future in as_completed(vmap):
            ip, src = vmap[future]
            try:
                result = future.result()
                if result:
                    cf_verified.append([ip, src, result.get("org", ""),
                                        result.get("colo", ""),
                                        result.get("country", ""),
                                        result.get("city", "")])
            except Exception:
                pass

    new_count = 0
    if cf_verified:
        with open(verified_file, "r") as f:
            existing = f.read()

        with open(verified_file, "w") as f:
            f.write(existing.rstrip() + "\n")
            for row in cf_verified:
                ip, src, org, colo, country, city = row
                # 复用源节点其他列 (端口 443, TLS TRUE)
                line = f"{ip},443,TRUE,{colo},{country},{city},,,{org}"
                f.write(line + "\n")
                new_count += 1

    print(c(f"  合并: +{new_count} 个新节点 (来源: TLS SAN 反查)", C.G))
    print(c(f"  本步耗时: {int(time.time() - step_start)}s", C.W))
    return new_count


def _verify_ip(ip: str) -> Optional[dict]:
    """调用 API 验证 IP 是否 CF 节点"""
    try:
        url = f"{API_URL}?ip={ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "ip-tidy/2.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if data.get("cf", False) or data.get("colo"):
                return {"org": data.get("org", ""), "colo": data.get("colo", ""),
                        "country": data.get("country", ""), "city": data.get("city", "")}
    except Exception:
        pass
    return None


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

        # 拆分超大范围 (如 10000-65535) 为多个子批次
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

    # 预检: sudo -n 是否可用
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

    print("  探测 masscan 最佳速率...", end="", flush=True)

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

            # 每 0.5s 检查进程健康，masscan 失败则提前退出
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
    print(f" {best_rate} pps")
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

    pub_ip = get_public_ip()

    # 离线优先: MaxMind GeoLite2
    if geo_available():
        g = geo_lookup(pub_ip)
        cfg.global_ip = pub_ip
        cfg.global_country = g.get("country", "")
        cfg.global_city = g.get("city", "")
        cfg.global_isp = g.get("isp", "")
        print(c("  [GeoIP] 离线数据库 (MaxMind GeoLite2)", C.W))
        print(f"  地区: {cfg.global_city}, {cfg.global_country}  机构: {cfg.global_isp}")
    else:
        cfg.global_ip, cfg.global_country, cfg.global_isp, cfg.global_city = detect_isp(pub_ip)

    return cfg


def ensure_cf_scanner() -> None:
    if not CF_SCANNER.is_file():
        print(c("  [FAIL] cf-scanner 未找到，请先编译: cd cf-scanner-src && go build -o ../cf-scanner main.go", C.Y))
        sys.exit(1)
    if not os.access(CF_SCANNER, os.X_OK):
        CF_SCANNER.chmod(0o755)


# ── ASN 缓存 ──

_ASN_CACHE = BASE / ".asn_cache.json"
_ASN_CACHE_TTL = 7 * 86400  # 7 天


def _asn_cache_load() -> dict[str, Any]:
    try:
        if _ASN_CACHE.exists():
            data = json.loads(_ASN_CACHE.read_bytes())
            if isinstance(data, dict):
                return data
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _asn_cache_save(data: dict[str, Any]) -> None:
    try:
        _ASN_CACHE.write_text(json.dumps(data, ensure_ascii=False))
    except OSError:
        pass


# ── Pipeline Steps ──

def step_fetch_prefixes(cfg: ScannerConfig, asns: list[str], v4_cidrs: list[str], v6_cidrs: list[str]) -> tuple[list[str], list[str]]:
    all_v4 = list(v4_cidrs)
    all_v6 = list(v6_cidrs)
    if v4_cidrs:
        print(f"  直接 IPv4 CIDR: {len(v4_cidrs)} 个 ({', '.join(v4_cidrs[:5])}{'...' if len(v4_cidrs) > 5 else ''})")
    if v6_cidrs:
        print(f"  直接 IPv6 CIDR: {len(v6_cidrs)} 个 ({', '.join(v6_cidrs[:5])}{'...' if len(v6_cidrs) > 5 else ''})")

    cache = _asn_cache_load()
    now_ts = time.time()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    for asn in asns:
        cache_key = f"AS{asn}"
        if cache_key in cache and now_ts - cache[cache_key].get("ts", 0) < _ASN_CACHE_TTL:
            entry = cache[cache_key]
            all_v4.extend(entry.get("v4", []))
            all_v6.extend(entry.get("v6", []))
            v4_cnt = entry.get("v4_count", 0)
            v6_cnt = entry.get("v6_count", 0)
            age_h = (now_ts - entry["ts"]) / 3600
            parts = []
            if v4_cnt: parts.append(f"{v4_cnt} v4")
            if v6_cnt: parts.append(f"{v6_cnt} v6")
            print(f"  AS{asn} -> {', '.join(parts)} CIDR (缓存, {age_h:.1f}h前)")
            continue

        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        v4_new = 0
        v6_new = 0
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            prefixes_v4, prefixes_v6 = [], []
            for p in data["data"]["prefixes"]:
                prefix = p["prefix"]
                if ":" in prefix:
                    prefixes_v6.append(prefix)
                    all_v6.append(prefix)
                    v6_new += 1
                else:
                    prefixes_v4.append(prefix)
                    all_v4.append(prefix)
                    v4_new += 1
            cache[cache_key] = {"ts": now_ts, "v4_count": v4_new, "v6_count": v6_new,
                                "v4": prefixes_v4, "v6": prefixes_v6, "updated": now_str}
            parts = []
            if v4_new: parts.append(f"{v4_new} v4")
            if v6_new: parts.append(f"{v6_new} v6")
            print(f"  AS{asn} -> {', '.join(parts)} CIDR")
        except (urllib.error.URLError, json.JSONDecodeError, OSError,
                KeyError) as e:
            if cache_key in cache:
                entry = cache[cache_key]
                all_v4.extend(entry.get("v4", []))
                all_v6.extend(entry.get("v6", []))
                summary = []
                if entry.get("v4_count"): summary.append(f"v4={entry['v4_count']}")
                if entry.get("v6_count"): summary.append(f"v6={entry['v6_count']}")
                print(f"  AS{asn} -> {e}, 使用上次缓存 ({', '.join(summary)})")
            else:
                print(f"  AS{asn} -> 失败: {e}")

    _asn_cache_save(cache)

    # 合并去重
    final_v4, final_v6 = _split_v4_v6(all_v4 + all_v6)
    all_cidrs = final_v4 + final_v6

    (BASE / "cidrs.txt").write_text("\n".join(all_cidrs))
    (BASE / "cidrs_v4.txt").write_text("\n".join(final_v4))
    (BASE / "cidrs_v6.txt").write_text("\n".join(final_v6))

    v4_ip_count = _cidr_count(final_v4)
    v6_ip_count = _cidr_count(final_v6)
    msg = f"  共 {len(all_cidrs)} 个 CIDR"
    if final_v4:
        msg += f" (v4: {len(final_v4)} 段 ~{v4_ip_count:,} IP)"
    if final_v6:
        msg += f" (v6: {len(final_v6)} 段)"
    print(msg)

    if not all_cidrs:
        print(c("  [FAIL] 无可用 CIDR，请检查输入是否正确", C.Y))
        sys.exit(1)
    return final_v4, final_v6


def _read_masscan_stderr(proc, prefix: str = "") -> list[str]:
    """后台线程读 stderr + 主线程轮询进度，跨平台兼容 (Unix/Windows)。"""
    lines: list[str] = []
    t0 = time.time()
    last_progress = t0

    # 后台线程阻塞读 stderr，写入共享列表
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

        # 解析新行中的进度
        while idx < len(lines):
            m = re.search(r"(\d+\.?\d*)%\s*done", lines[idx])
            if m:
                pct = min(float(m.group(1)), 100)
                if pct >= 100:
                    seen_100 = True
                last_progress = time.time()  # 仅进度行更新时间戳
                elapsed = last_progress - t0
                eta = (elapsed / pct * (100 - pct)) if pct > 0 else 0
                extra = f" | ETA {int(eta // 60)}m {int(eta % 60)}s" if pct > 0.5 else ""
                write_progress(pct, prefix + extra)
            idx += 1

        # 读线程完成 (stderr 已关闭)
        if not t.is_alive():
            break

        # 进程已退出，等待线程收尾
        if proc.poll() is not None:
            t.join(timeout=2.0)
            break

        # 100% 后最久等 10s 兜底
        if seen_100 and time.time() - last_progress > 10:
            break

        # 60s 无进度 → kill
        if time.time() - last_progress > 60:
            proc.kill()
            proc.wait()
            break

    return lines


def step_masscan(cfg: ScannerConfig) -> int:
    step_start = time.time()

    # IPv6 模式下跳过 masscan
    if cfg.ip_mode == "v6":
        print(c("  [INFO] v6-only 模式，masscan 仅支持 IPv4，跳过", C.W))
        return 0

    ip_file = BASE / "cidrs_v4.txt"
    if not ip_file.exists() or ip_file.stat().st_size == 0:
        # 兼容：回退到 cidrs.txt
        ip_file = BASE / "cidrs.txt"
        if not ip_file.exists() or ip_file.stat().st_size == 0:
            print(c("  [FAIL] 无 IPv4 CIDR，跳过 masscan", C.Y))
            return 0

    # 过滤 IPv6 行 (cidrs.txt 可能包含混合内容)
    if ip_file.name == "cidrs.txt":
        v4_only = []
        with open(ip_file) as f:
            for line in f:
                line = line.strip()
                if line and ":" not in line:
                    v4_only.append(line)
        if not v4_only:
            print(c("  [FAIL] cidrs.txt 无 IPv4，跳过 masscan", C.Y))
            return 0
        tmp_v4 = BASE / "cidrs_v4.txt"
        tmp_v4.write_text("\n".join(v4_only) + "\n")
        ip_file = tmp_v4

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

        sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
        cmd = sudo + [
            "masscan", "-iL", str(ip_file),
            "-p", batch_ports,
            "--rate", str(cfg.masscan_rate),
            "-oX", str(batch_xml),
            "--wait", "3",
        ]

        prefix = f"[{bi + 1}/{batch_total}] " if batch_total > 1 else ""
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        stderr_lines = _read_masscan_stderr(proc, prefix)
        proc.wait()

        if proc.returncode != 0:
            sys.stderr.write("\n")
            sys.stderr.flush()
            err = "".join(stderr_lines).lower()
            if "permission denied" in err or "init: failed" in err:
                print(c("  [FAIL] masscan 需要 raw socket 权限", C.Y))
                if os.geteuid() != 0:
                    print("  解决: sudo python3 run.py ...  (以 root 运行)")
                    print("  或: sudo setcap cap_net_raw+ep $(which masscan)")
            elif "password is required" in err or "a password is required" in err:
                print(c("  [FAIL] sudo 需要密码交互，当前环境无法输入", C.Y))
                print("  解决: sudo python3 run.py ...  (以 root 运行)")
                print("  或: sudo setcap cap_net_raw+ep $(which masscan)")
            else:
                sys.stderr.write("".join(stderr_lines))
                sys.stderr.flush()
                print(c(f"\n  [FAIL] masscan 返回码 {proc.returncode}", C.Y))
            raise subprocess.CalledProcessError(
                proc.returncode, cmd, output=None,
                stderr="".join(stderr_lines))

        write_progress_done(prefix)

        if os.geteuid() != 0:
            subprocess.run(["sudo", "-n", "chown",
                            f"{os.getuid()}:{os.getgid()}", str(batch_xml)],
                           stdin=subprocess.DEVNULL, check=False)

        # Parse batch XML
        if batch_total > 1:
            print(f"  解析 {batch_xml.name} ...", flush=True)
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
    print(c(f"  本步耗时: {int(time.time() - step_start)}s", C.W))
    return len(all_open)


def _pipeline(cfg: ScannerConfig) -> tuple[int, int]:
    """流式流水线: cf-scanner + API 精筛合并执行"""
    step_start = time.time()
    input_file = BASE / "masscan_result.txt"
    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"

    if input_file.stat().st_size == 0:
        return 0, 0

    ensure_cf_scanner()
    hits_file.write_text("")
    verified_file.write_text("")

    adj = _adjust_concurrency(cfg.cf_concurrency, cfg.cpu)
    if adj != cfg.cf_concurrency:
        print(f"  cf-scanner 并发: {cfg.cf_concurrency} -> {adj} (系统负载)")
        cfg.cf_concurrency = adj

    # ── cf-scanner (前台, 显示进度) ──
    proc = subprocess.Popen(
        [str(CF_SCANNER), "-i", str(input_file), "-o", str(hits_file),
         "-c", str(cfg.cf_concurrency)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    # 后台精筛: hits 一出现就静默启动
    verify_running = threading.Event()
    cf_done = threading.Event()

    def _bg_verify() -> None:
        for _ in range(60):
            try:
                if hits_file.stat().st_size > 200:
                    break
            except OSError:
                pass
            if cf_done.is_set():
                return
            time.sleep(1)
        verify_running.set()
        try:
            adj_api = _adjust_concurrency(cfg.api_concurrency, cfg.cpu)
            subprocess.run([
                sys.executable, str(VERIFY_PY),
                "--input", str(hits_file),
                "--output", str(verified_file),
                "--api", API_URL,
                "--chunk", str(cfg.api_chunk),
                "--concurrent", str(adj_api),
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except Exception:
            pass
        verify_running.clear()

    vt = threading.Thread(target=_bg_verify, daemon=True)
    vt.start()

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
                tag = " | 精筛并行" if verify_running.is_set() else ""
                extra = f" | ETA {int(eta // 60)}m {int(eta % 60)}s" if pct > 0.5 else ""
                write_progress(pct, tag + extra)
                last_pct = pct
    proc.wait()

    if proc.returncode != 0:
        sys.stderr.write("\n"); sys.stderr.flush()
        raise subprocess.CalledProcessError(proc.returncode, proc.args)

    write_progress_done()
    cf_done.set()

    with open(hits_file) as f:
        hits = sum(1 for _ in f)

    # ── 最终精筛 (前台, 覆盖后台结果, 确保完整) ──
    vt.join(timeout=300)
    adj_api = _adjust_concurrency(cfg.api_concurrency, cfg.cpu)
    subprocess.run([
        sys.executable, str(VERIFY_PY),
        "--input", str(hits_file),
        "--output", str(verified_file),
        "--api", API_URL,
        "--chunk", str(cfg.api_chunk),
        "--concurrent", str(adj_api),
    ], check=True)

    with open(verified_file) as f:
        passed = sum(1 for _ in f) - 1
    passed = max(0, passed)

    rate_pct = passed / hits * 100 if hits else 0
    rate_color = C.G if rate_pct >= 50 else C.Y
    msg = f"  CF 节点: {hits}  |  精筛通过: {rate_pct:.0f}% ({passed}/{hits})"
    print(c(msg, rate_color))
    print(c(f"  本步耗时: {int(time.time() - step_start)}s", C.W))
    return hits, passed


def step_deep_scan(cfg: ScannerConfig) -> int:
    """二阶段深度扫描: 对 CF 命中的 IP 追加宽端口扫描"""
    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"

    if not hits_file.exists() or hits_file.stat().st_size == 0:
        print("  无 CF 节点，跳过")
        return 0

    ips: set[str] = set()
    with open(hits_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ips.add(line.split(":")[0] if ":" in line else line)

    if not ips:
        print("  无目标 IP，跳过")
        return 0

    # 保存已有结果 (去重 key = IP:port)
    saved: dict[str, str] = {}
    saved_header = "IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN,协议"
    if verified_file.exists() and verified_file.stat().st_size > 0:
        with open(verified_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("IP"):
                    saved_header = line
                    continue
                parts = line.split(",", 2)
                key = f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else line
                saved[key] = line

    port_count = _port_count(WIDE_PORTS)
    print(f"\n  深度扫描: {len(ips)} 个 IP × {port_count} 端口 ({cfg.masscan_rate} pps)")
    eta_s = max(1, port_count * len(ips) // max(1, cfg.masscan_rate))
    print(f"  预计: {eta_s // 60}m {eta_s % 60}s ({', '.join(sorted(ips)[:5])}{'...' if len(ips) > 5 else ''})")

    ip_file = BASE / "deep_ips.txt"
    ip_file.write_text("\n".join(sorted(ips)) + "\n")

    # ── masscan ──
    xml_file = BASE / "deep_result.xml"
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]

    batches = _split_port_batches(WIDE_PORTS)
    all_open: list[str] = []

    for bi, batch_ports in enumerate(batches):
        batch_xml = xml_file if len(batches) == 1 else BASE / f"deep_batch_{bi + 1}.xml"
        cmd = sudo + [
            "masscan", "-iL", str(ip_file),
            "-p", batch_ports,
            "--rate", str(cfg.masscan_rate),
            "-oX", str(batch_xml),
            "--wait", "3",
        ]
        prefix = f"[{bi + 1}/{len(batches)}] " if len(batches) > 1 else ""
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        stderr_lines = _read_masscan_stderr(proc, prefix)
        proc.wait()

        if proc.returncode != 0:
            sys.stderr.write("\n"); sys.stderr.flush()
            err = "".join(stderr_lines).lower()
            if "permission denied" in err or "password is required" in err:
                print(c("  [FAIL] masscan 权限不足", C.Y))
            raise subprocess.CalledProcessError(proc.returncode, cmd,
                                                output=None, stderr="".join(stderr_lines))

        write_progress_done(prefix)

        if os.geteuid() != 0:
            subprocess.run(["sudo", "-n", "chown",
                            f"{os.getuid()}:{os.getgid()}", str(batch_xml)],
                           stdin=subprocess.DEVNULL, check=False)

        # 解析 XML
        batch_before = len(all_open)
        try:
            tree = ET.parse(batch_xml)
            for host in tree.getroot().findall("host"):
                addr = host.find("address")
                if addr is None:
                    continue
                ip_addr = addr.get("addr", "")
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
                    if ip_addr and portid:
                        all_open.append(f"{ip_addr}:{portid}")
        except ET.ParseError:
            pass

        new_in_batch = len(all_open) - batch_before
        pfx = f"[{bi + 1}/{len(batches)}] " if len(batches) > 1 else ""
        print(f"  {pfx}端口开放: +{new_in_batch} (累计 {len(all_open)})", flush=True)

        # 本批无新增且后续还有批次，询问是否继续
        if new_in_batch == 0 and bi + 1 < len(batches) and sys.stdin.isatty():
            try:
                ch = input(c("   > 本批无新端口, 继续下批? (y/n, 回车继续): ", C.Y)).strip().lower()
            except (EOFError, KeyboardInterrupt):
                ch = ""
            if ch == "n":
                print(c("  [已跳过] 用户终止剩余 {len(batches) - bi - 1} 批次", C.G))
                break

        if len(batches) > 1:
            try:
                batch_xml.unlink()
            except OSError:
                pass

    result_file = BASE / "masscan_result.txt"
    result_file.write_text("\n".join(all_open) + "\n")
    print(c(f"  深度 masscan 完成: {len(all_open)} 开放端口", C.LB))

    if not all_open:
        print("  无新增开放端口")
        return len(saved)

    # ── 对深度结果跑 cf-scanner + 精筛 ──
    print(c("  CF 检测中...", C.W))
    hits, _passed = _pipeline(cfg)

    # 合并结果
    new_set: dict[str, str] = {}
    if verified_file.exists() and verified_file.stat().st_size > 0:
        with open(verified_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("IP"):
                    continue
                parts = line.split(",", 2)
                key = f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else line
                new_set[key] = line

    merged = dict(saved)
    for key, val in new_set.items():
        if key not in merged:
            merged[key] = val

    result_lines = [saved_header] + list(merged.values())
    verified_file.write_text("\n".join(result_lines) + "\n")

    new_found = len(merged) - len(saved)
    if new_found > 0:
        print(c(f"  合并: {len(saved)} -> {len(merged)} 条 (新增 {new_found})", C.G))
    else:
        print(c(f"  合并: 无新增 (维持 {len(saved)} 条)", C.Y))
    return len(merged)


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


def _smart_wrapper(cfg: ScannerConfig) -> tuple[list[str], list[str]]:
    """子网分级探活，将结果写回 cidrs_v4.txt"""
    v4_file = BASE / "cidrs_v4.txt"
    if not v4_file.exists():
        return [], []

    v4_cidrs = [l.strip() for l in open(v4_file) if l.strip() and ":" not in l]
    if not v4_cidrs:
        return [], []

    alive = step_smart_subnet(cfg, v4_cidrs)
    v4_file.write_text("\n".join(alive) + "\n")
    v6 = [l.strip() for l in open(BASE / "cidrs_v6.txt") if l.strip()] if (BASE / "cidrs_v6.txt").exists() else []
    return alive, v6


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
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN,协议\n")
        for p in parsed:
            ip_part = p.split(",")[0]
            proto = "IPv6" if ":" in ip_part else "IPv4"
            f.write(p + f",{proto}\n")

    print(c(f"\n  结果: {len(parsed)} 条 -> {csv_path.name}", C.G))
    _serve_download(csv_path)


def _parse_targets(raw_args: list[str]) -> tuple[list[str], list[str], list[str]]:
    """解析输入，返回 (ASN列表, IPv4CIDR列表, IPv6CIDR列表)"""
    raw = ""
    if not raw_args:
        try:
            raw = input(c("  输入 ASN 或 CIDR (多个用逗号分隔): ", C.Y)).strip()
        except (EOFError, KeyboardInterrupt):
            try:
                with open("/dev/tty") as tty:
                    os.dup2(tty.fileno(), 0)
                raw = input(c("  输入 ASN 或 CIDR (多个用逗号分隔): ", C.Y)).strip()
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
            elif arg in ("-s", "-w", "-R", "-d", "--v4-only", "--v6-only", "--smart", "--no-cert"):
                i += 1
            else:
                filtered.append(arg)
                i += 1
        raw = ",".join(filtered)

    asns: list[str] = []
    v4_cidrs: list[str] = []
    v6_cidrs: list[str] = []
    for item in raw.replace("，", ",").split(","):
        item = item.strip()
        if not item:
            continue
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
                if net.version == 6:
                    v6_cidrs.append(str(net))
                else:
                    v4_cidrs.append(str(net))
            except ValueError:
                print(c(f"  [WARN] 无效 CIDR: {item}，已忽略", C.Y))
        else:
            asn = item.replace("AS", "").replace("as", "")
            if asn.isdigit():
                asns.append(asn)
            else:
                print(c(f"  [WARN] 无法识别: {item}，已忽略", C.Y))
    return asns, v4_cidrs, v6_cidrs


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
    main_start = time.time()
    parser = argparse.ArgumentParser(
        prog="xiaoqian",
        description=f"IP-Tidy {VERSION} -- CIDR/ASN -> masscan -> CF 节点检测",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  ip-tidy AS209242\n"
               "  ip-tidy AS209242 -w -s\n"
               "  ip-tidy 1.2.3.0/24,5.6.7.0/24\n"
               "  ip-tidy AS209242 -w -r 4000\n"
               "  ip-tidy 2001:db8::/32,AS209242 --v4-only")
    parser.add_argument("targets", nargs="*", help="ASN 编号 或 CIDR (可多个，空格或逗号分隔)")
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
    parser.add_argument("--skip-masscan", action="store_true",
                        help="跳过 masscan，使用已有 masscan_result.txt")
    parser.add_argument("-d", "--deep", action="store_true",
                        help="深度扫描: 对 CF 命中的 IP 追加 55546 个端口扫描 (发现隐藏节点)")
    parser.add_argument("-v", "--version", action="version",
                        version=f"IP-Tidy {VERSION}")
    parser.add_argument("-g", "--geo-update", action="store_true",
                        help="下载/更新 MaxMind GeoLite2 离线数据库")
    parser.add_argument("--v4-only", action="store_true",
                        help="仅处理 IPv4 (过滤 IPv6 CIDR, masscan 正常扫描)")
    parser.add_argument("--v6-only", action="store_true",
                        help="仅处理 IPv6 (跳过 masscan, 导出 IPv6 CIDR 列表)")
    parser.add_argument("--smart", action="store_true",
                        help="智能子网分级: 大 CIDR 拆 /24 抽样探活, 仅扫活跃子网")
    parser.add_argument("--no-cert", action="store_true",
                        help="跳过 TLS 证书反查步骤")
    a = parser.parse_args()

    if a.geo_update:
        print_banner()
        print("  [GeoIP] 下载 MaxMind GeoLite2 离线数据库")
        print()
        if geo_update_interactive():
            print()
            print(f"  [OK] 数据库已保存到 {Path.home() / '.config' / 'ip-tidy'}")
        sys.exit(0)

    if a.v4_only and a.v6_only:
        print(c("  [FAIL] --v4-only 和 --v6-only 不能同时使用", C.Y))
        sys.exit(1)

    print_banner()
    cfg = init_runtime()

    if a.v4_only:
        cfg.ip_mode = "v4"
    elif a.v6_only:
        cfg.ip_mode = "v6"

    asns, v4_cidrs, v6_cidrs = _parse_targets(sys.argv[1:] if not a.targets else a.targets)

    if not asns and not v4_cidrs and not v6_cidrs:
        print("用法: ip-tidy AS209242 [...] 或 ip-tidy 1.2.3.0/24 [...]")
        sys.exit(1)

    # 过滤不符合 IP 模式的 CIDR
    if cfg.ip_mode == "v4" and v6_cidrs:
        print(c(f"  [已跳过] {len(v6_cidrs)} 个 IPv6 CIDR (--v4-only)", C.G))
        v6_cidrs = []
    elif cfg.ip_mode == "v6" and v4_cidrs:
        print(c(f"  [已跳过] {len(v4_cidrs)} 个 IPv4 CIDR (--v6-only)", C.G))
        v4_cidrs = []

    print_hardware_info(cfg.cpu, cfg.ram_mb, cfg.masscan_rate,
                        cfg.cf_concurrency, cfg.api_concurrency,
                        cfg.global_city, cfg.global_isp)

    # 确认目标
    targets_desc = []
    if asns:
        targets_desc.append(", ".join(f"AS{x}" for x in asns))
    if v4_cidrs:
        targets_desc.append(f"IPv4 x{len(v4_cidrs)} ({', '.join(v4_cidrs[:3])}{'...' if len(v4_cidrs) > 3 else ''})")
    if v6_cidrs:
        targets_desc.append(f"IPv6 x{len(v6_cidrs)} ({', '.join(v6_cidrs[:3])}{'...' if len(v6_cidrs) > 3 else ''})")
    mode_tag = ""
    if cfg.ip_mode == "v4":
        mode_tag = " [v4-only]"
    elif cfg.ip_mode == "v6":
        mode_tag = " [v6-only]"
    print(c(f"  [已确认] 目标{mode_tag}: {'; '.join(targets_desc)}", C.G))

    if a.rate:
        cfg.masscan_rate = max(100, a.rate)
        print(f"  发包速率: {cfg.masscan_rate} pps (手动)")

    if a.ports:
        cfg.scan_ports = parse_ports(a.ports)
        if not cfg.scan_ports:
            print(c(f"  [FAIL] 无效端口: {a.ports}", C.Y))
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
    elif not sys.argv[1:] and not a.targets:
        print(f"  默认端口: {cfg.scan_ports}")
        print(f"  宽端口: {WIDE_PORTS}")
        try:
            inp = input(c("  端口模式 (回车=默认 / w=宽端口 / r=随机5 / 自定义): ", C.Y)).strip().lower()
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

    port_desc = f"端口 ({_port_count(cfg.scan_ports)} 个)"
    print(c(f"  [已确认] 端口模式: {port_desc}", C.G))

    # ── 智能子网分级交互开关 ──
    if not a.smart and v4_cidrs:
        has_large = any(
            ipaddress.ip_network(c, strict=False).prefixlen < _SUBNET_THRESHOLD
            for c in v4_cidrs
        )
        if has_large:
            print(c(f"  [INFO] 检测到大 CIDR (/{_SUBNET_THRESHOLD}+)，可启用智能子网分级探活", C.W))
            try:
                ch = input(c("  是否启用智能子网分级？(y/n, 回车跳过): ", C.Y)).strip().lower()
            except (EOFError, KeyboardInterrupt):
                ch = ""
            if ch == "y":
                a.smart = True
                print(c("  [已确认] 智能子网分级探活 (拆分 /24 抽样)", C.G))
            else:
                print(c("  [已跳过] 智能子网分级 (全量扫描)", C.G))

    # ── 证书反查交互开关 ──
    do_cert = True
    if a.no_cert:
        do_cert = False
        print(c("  [已跳过] TLS 证书反查 (--no-cert)", C.G))
    elif not sys.argv[1:] and not a.targets:
        try:
            ch = input(c("  是否启用 TLS 证书反查？(y/n, 回车默认跳过): ", C.Y)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ch = ""
        if ch == "y":
            print(c("  [已确认] TLS 证书反查 (SAN -> IP 扩充节点)", C.G))
        else:
            do_cert = False
            print(c("  [已跳过] TLS 证书反查 (手动关闭)", C.G))
    else:
        print(c("  [已确认] TLS 证书反查 (SAN -> IP 扩充节点)", C.G))

    total_steps = 2 if a.skip_masscan else 3
    if do_cert:
        total_steps += 1  # TLS 证书反查
    do_speed = a.speed
    do_deep = a.deep
    if not do_speed:
        try:
            ts = input(c("  是否测速？(y/n, 回车跳过): ", C.Y)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ts = ""
        do_speed = ts == "y"
        if not do_speed:
            print(c("  [已跳过] 测速功能 (回车自动选择)", C.G))
    if not do_deep and not sys.argv[1:]:
        try:
            ch = input(c("  深度扫描？(y/n, 回车跳过): ", C.Y)).strip().lower()
            do_deep = ch == "y"
            if not do_deep:
                print(c("  [已跳过] 深度扫描 (回车自动选择)", C.G))
        except (EOFError, KeyboardInterrupt):
            do_deep = False
    if do_speed:
        total_steps += 1
    if do_deep:
        total_steps += 1
    if a.smart:
        total_steps += 1

    steps: list[tuple[str, Callable[[], object]]] = [
        ("Step 1  ASN -> CIDR", lambda: step_fetch_prefixes(cfg, asns, v4_cidrs, v6_cidrs)),
    ]
    step_num = 1
    if a.smart:
        step_num += 1
        cfg.smart_mode = True
        steps.append((f"Step {step_num}  子网分级探活", lambda: _smart_wrapper(cfg)))
    if a.skip_masscan or cfg.ip_mode == "v6":
        if cfg.ip_mode == "v6":
            print(c("  (v6-only: 跳过 masscan, masscan 仅支持 IPv4)", C.W))
        elif a.skip_masscan:
            print(c("  (跳过 masscan, 使用已有结果)", C.W))
    else:
        step_num += 1
        steps.append((f"Step {step_num}  Masscan 端口扫描", lambda: step_masscan(cfg)))
    step_num += 1
    steps.append((f"Step {step_num}  CF 检测 + API 精筛", lambda: _pipeline(cfg)))
    if do_cert:
        step_num += 1
        steps.append((f"Step {step_num}  TLS 证书反查", lambda: step_cert_enum(cfg)))
    if do_deep:
        step_num += 1
        steps.append((f"Step {step_num}  深度宽端口扫描", lambda: step_deep_scan(cfg)))
    if do_speed:
        step_num += 1
        steps.append((f"Step {step_num}  延迟 + 带宽测速", lambda: step_speed_test(cfg)))

    # 清理上次运行的中间文件，防止残留数据污染
    for stale in ("cidrs.txt", "cidrs_v4.txt", "cidrs_v6.txt",
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
    for p in BASE.glob("deep_*.xml"):
        try:
            p.unlink()
        except OSError:
            pass
    for fname in ("deep_ips.txt",):
        p = BASE / fname
        try:
            if p.exists():
                p.unlink()
        except OSError:
            pass
    if not a.skip_masscan:
        mp = BASE / "masscan_result.txt"
        try:
            if mp.exists():
                mp.unlink()
        except OSError:
            pass

    cidr_count = 0
    v4_cidr_count = 0
    v6_cidr_count = 0
    total_open = 0
    cf_nodes = 0
    passed_count = 0

    for label, fn in steps:
        print_step(label)
        try:
            result = fn()
            if label.startswith("Step 1"):
                v4_list, v6_list = result
                cidr_count = len(v4_list) + len(v6_list)
                v4_cidr_count = len(v4_list)
                v6_cidr_count = len(v6_list)
            elif "子网分级" in label:
                v4_list, v6_list = result
                cidr_count = len(v4_list) + len(v6_list)
                v4_cidr_count = len(v4_list)
                v6_cidr_count = len(v6_list)
                print(c(f"  存活子网: {len(v4_list)} 段 (v4)", C.G))
            elif label.startswith("Step 2") or ("Masscan" in label and "端口" in label):
                total_open = result
            elif label.startswith("Step 3") or ("CF 检测" in label):
                cf_nodes, passed_count = result
            elif "证书反查" in label:
                cert_new = result
                if cert_new:
                    passed_count += cert_new
        except Exception as e:
            print(c(f"  [FAIL] {e}", C.Y))
            sys.exit(1)

    verified_file = BASE / "verified.txt"
    csv_path = None
    if verified_file.exists() and verified_file.stat().st_size > 0:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        tag = "_".join(asns) if asns else "cidr"
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
            f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN,协议\n")
            for p in parsed:
                ip_part = p.split(",")[0]
                proto = "IPv6" if ":" in ip_part else "IPv4"
                f.write(p + f",{proto}\n")

        print(c(f"\n  结果: {len(parsed)} 条 -> {csv_path.name}", C.G))

    elif cfg.ip_mode == "v6":
        # v6-only mode: export CIDR list if no scan results
        v6_file = BASE / "cidrs_v6.txt"
        if v6_file.exists() and v6_file.stat().st_size > 0:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            tag = "_".join(asns) if asns else "cidr"
            csv_path = BASE / f"output_v6_{tag}_{ts}.csv"
            with open(v6_file) as f:
                cidrs = [l.strip() for l in f if l.strip()]
            with open(csv_path, "w") as f:
                f.write("CIDR,IP数量,协议\n")
                for cidr in cidrs:
                    cnt = _cidr_count([cidr])
                    f.write(f"{cidr},{cnt},IPv6\n")
            print(c(f"\n  IPv6 CIDR: {len(cidrs)} 段 -> {csv_path.name}", C.G))

    print_result_header(
        len(asns),
        cidr_count,
        total_open,
        cf_nodes,
        passed_count,
        v4_cidr_count,
        v6_cidr_count
    )

    print_sep("-", C.W)
    print_total_time(time.time() - main_start)

    if csv_path and csv_path.exists():
        _serve_download(csv_path)


def _serve_download(file_path: Path) -> None:
    """启动 HTTP 下载服务，提供 CSV 文件下载链接"""
    lan_ip = get_lan_ip()
    port = 8899

    if not port_is_free(port):
        print(c(f"  端口 {port} 被占用，尝试释放...", C.Y))
        if kill_port_process(port) and port_is_free(port):
            print(c(f"  已释放端口 {port}", C.G))
        else:
            while not port_is_free(port) and port < 9900:
                port += 1
            if port >= 9900:
                print(c("  无可用端口，跳过下载服务", C.Y))
                print(c(f"  [CSV] {file_path}", C.LB))
                return

    server: Optional[subprocess.Popen] = None
    try:
        print()
        print_sep("=", C.LB)
        print(c("  下载服务已启动 (按回车关闭)", C.LG))
        print(c(f"  http://{lan_ip}:{port}/{file_path.name}", C.LB))
        pub = get_public_ip()
        if pub not in ("127.0.0.1", lan_ip):
            print(c(f"  http://{pub}:{port}/{file_path.name}", C.LB))
        print()
        server = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(port),
             "--directory", str(BASE)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if sys.stdin.isatty():
            import time as _time
            print(c("  (请在浏览器中下载文件后按回车关闭服务)", C.LB))
            try:
                input()
            except (EOFError, KeyboardInterrupt):
                pass
            _time.sleep(1.5)
        else:
            print(c("  (非交互终端，按 Ctrl+C 停止服务)", C.W))
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


if __name__ == "__main__":
    main()
