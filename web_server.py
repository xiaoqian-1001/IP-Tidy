#!/usr/bin/env python3
"""
IP-Tidy WEB Mode -- 完整复刻 CLI 全部功能
支持: ASN/CIDR 扫描 / 官方优选 / 自定义扫描 / 证书反查 / 测速 / 导出
"""

import os
import sys
import re
import json
import time
import queue
import socket
import random
import shutil
import threading
import subprocess
import urllib.request
import urllib.error
import ipaddress
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, jsonify, Response, send_from_directory

# Allow importing from workspace
sys.path.insert(0, str(Path(__file__).parent))
from lib.utils import parse_ports

BASE = Path(__file__).parent.resolve()
CF_SCANNER = BASE / "cf-scanner"
VERIFY_PY = BASE / "verify.py"
API_URL = "https://api.090227.xyz/check"
WIDE_PORTS = "912,22,80,443,8080,8443,2053,2083,2087,2096,10000-65535"
MASSCAN_BIN = "/usr/local/bin/masscan"
_MASSCAN_BATCH = 5000
_masscan_available = os.path.exists(MASSCAN_BIN) or shutil.which("masscan")
PORTS_FILE = BASE / "ports.txt"

_RANDOM_ZONES: list[tuple[int, int, int]] = [
    (22, 22, 2), (80, 80, 2), (443, 443, 2),
    (912, 912, 2), (2053, 2053, 2),
    (2083, 2087, 2), (8080, 8080, 2), (8443, 8443, 2),
    (10000, 19999, 2),
    (20000, 60000, 10),
    (60001, 65535, 3),
]

app = Flask(__name__, static_folder="web", static_url_path="")

_V4_URL = "https://www.cloudflare.com/ips-v4"
_V6_URL = "https://www.cloudflare.com/ips-v6"

_ASN_CACHE = BASE / ".asn_cache.json"
_ASN_CACHE_TTL = 7 * 86400

_SPEED_URLS = [
    ("https://speed.cloudflare.com/__down?bytes=1048576", 1),
    ("https://speed.cloudflare.com/__down?bytes=10485760", 10),
    ("https://speed.cloudflare.com/__down?bytes=100000000", 100),
    ("https://cloudflare.cdn.openbsd.org/pub/OpenBSD/7.3/src.tar.gz", 0),
]

_EVENT_QUEUES: dict[str, queue.Queue] = {}
_QUEUE_LOCK = threading.Lock()
_SCAN_RESULTS: dict[str, list[dict]] = {}
_RESULTS_LOCK = threading.Lock()
_CANCEL_FLAGS: dict[str, threading.Event] = {}
_CANCEL_LOCK = threading.Lock()
_CIDR_CACHE: dict[str, list[str]] = {}
_CIDR_LOCK = threading.Lock()
_TMP_DIR = BASE / ".web_tmp"


def _ensure_tmp() -> None:
    _TMP_DIR.mkdir(parents=True, exist_ok=True)


def _gen_session_id() -> str:
    import uuid
    return uuid.uuid4().hex[:12]


def _get_or_create_queue(sid: str) -> queue.Queue:
    with _QUEUE_LOCK:
        if sid not in _EVENT_QUEUES:
            _EVENT_QUEUES[sid] = queue.Queue()
        return _EVENT_QUEUES[sid]


def _emit(sid: str, typ: str, data: object) -> None:
    try:
        _get_or_create_queue(sid).put_nowait({"type": typ, "data": data})
    except Exception:
        pass


def _cancel_get(sid: str) -> threading.Event:
    with _CANCEL_LOCK:
        f = threading.Event()
        _CANCEL_FLAGS[sid] = f
        return f


def _cancel_is(sid: str) -> bool:
    with _CANCEL_LOCK:
        f = _CANCEL_FLAGS.get(sid)
        return f.is_set() if f else False


# ══════════════════════════════════════════
# Port utilities

def _read_default_ports() -> str:
    if PORTS_FILE.exists():
        ports = []
        for line in PORTS_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.isdigit() and 1 <= int(line) <= 65535:
                ports.append(line)
        if ports:
            return ",".join(ports)
    return "443,8443,2053,2083,2087,2096"


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


def _resolve_port_list(port_mode: str, custom_ports: str) -> str:
    if port_mode == "default":
        return _read_default_ports()
    elif port_mode == "wide":
        return parse_ports(WIDE_PORTS) or _read_default_ports()
    elif port_mode == "random":
        return _random_ports()
    elif port_mode == "custom":
        return parse_ports(custom_ports) or _read_default_ports()
    else:
        return _read_default_ports()


def _port_count(port_str: str) -> int:
    total = 0
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                total += int(b) - int(a) + 1
            except ValueError:
                pass
        else:
            total += 1
    return total


# ══════════════════════════════════════════
# Masscan 集成

_MASSCAN_RATE = 2000  # 默认发包速率 (pps)


def _masscan_bin() -> str:
    return shutil.which("masscan") or MASSCAN_BIN


def _masscan_adapter_ip() -> Optional[str]:
    try:
        import subprocess as _sp
        r = _sp.run(["ip", "-4", "addr", "show", "scope", "global"],
                    capture_output=True, text=True, timeout=5)
        found = None
        for line in r.stdout.splitlines():
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
            if m:
                ip = m.group(1)
                if ip.startswith("127.") or ip.startswith("169.254."):
                    continue
                found = ip
        return found
    except Exception:
        pass
    return None


def _probe_masscan_rate() -> int:
    cores = os.cpu_count() or 1
    return max(1000, min(cores * 1000, 16000))


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


def _run_masscan(cidr_file: Path, ports_str: str, rate: int,
                 sid: str) -> list[str]:
    batch_xml = _TMP_DIR / f"masscan_{sid}.xml"
    total_ports = _port_count(ports_str)
    batches = _split_port_batches(ports_str)
    is_multi = len(batches) > 1
    all_open: list[str] = []
    adapter_ip = _masscan_adapter_ip()

    if is_multi:
        _emit(sid, "log", f"masscan: {total_ports} 端口 -> {len(batches)} 批次 (~{_MASSCAN_BATCH}/批)")

    for bi, batch_ports in enumerate(batches):
        batch_file = batch_xml if not is_multi else _TMP_DIR / f"masscan_{sid}_b{bi+1}.xml"
        cmd = [_masscan_bin(),
               "-iL", str(cidr_file),
               "-p", batch_ports,
               "--rate", str(rate),
               "-oX", str(batch_file),
               "--wait", "8"]
        if adapter_ip:
            cmd += ["--adapter-ip", adapter_ip]
        prefix = f"[{bi+1}/{len(batches)}] " if is_multi else ""
        _emit(sid, "log", f"{prefix}masscan 批次 {batch_ports[:60]}... ({rate} pps)")

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        # 读取 stderr 进度
        stderr_lines = []
        def _reader():
            try:
                for line in proc.stderr:
                    stderr_lines.append(line)
            except (ValueError, OSError):
                pass
        rt = threading.Thread(target=_reader, daemon=True)
        rt.start()
        idx = 0
        while True:
            rt.join(timeout=0.5)
            while idx < len(stderr_lines):
                m = re.search(r"(\d+\.?\d*)%\s*done", stderr_lines[idx])
                if m:
                    pct = min(float(m.group(1)), 100)
                    _emit(sid, "scan_progress",
                          {"current": int(pct * total_ports / 100 / max(len(batches), 1)),
                           "total": total_ports,
                           "stage": f"masscan {prefix}".strip()})
                idx += 1
            if not rt.is_alive():
                break
            if proc.poll() is not None:
                rt.join(timeout=1)
                break
        proc.wait()

        if proc.returncode != 0:
            err_text = "".join(stderr_lines)
            if "permission" in err_text.lower() or "init: failed" in err_text.lower():
                _emit(sid, "error", "masscan 需要 raw socket 权限")
                _emit(sid, "log", "尝试: setcap cap_net_raw+ep $(which masscan)")
                _emit(sid, "log", "或: sudo pip3 install ip-tidy")
            return all_open

        # 解析 XML
        import xml.etree.ElementTree as ET
        try:
            if batch_file.exists() and batch_file.stat().st_size > 0:
                tree = ET.parse(batch_file)
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
        except Exception:
            pass
        finally:
            if is_multi:
                try:
                    batch_file.unlink()
                except OSError:
                    pass

    _emit(sid, "log", f"masscan 开放端口: {len(all_open)} (syn-ack 确认)")
    return all_open


# ══════════════════════════════════════════
# GeoIP (可选 -- 如果 GeoLite2 数据库可用)

_geoip_available = False

try:
    from lib.geoip import lookup as geo_lookup, is_available as geo_available
    if geo_available():
        _geoip_available = True
except Exception:
    pass


def _enrich_geoip(results: list[dict]) -> None:
    if not _geoip_available:
        return
    for r in results:
        try:
            info = geo_lookup(r["ip"])
            if info:
                if info.get("country") and not r.get("country"):
                    r["country"] = info["country"]
                if info.get("city") and not r.get("region"):
                    r["region"] = info["city"]
                if info.get("isp"):
                    r["isp"] = info["isp"]
        except Exception:
            pass


# ══════════════════════════════════════════
# Step 1: ASN/CIDR -> IP 列表
# ══════════════════════════════════════════

def _asn_cache_load() -> dict:
    try:
        if _ASN_CACHE.exists():
            return json.loads(_ASN_CACHE.read_bytes())
    except Exception:
        pass
    return {}


def _asn_cache_save(data: dict) -> None:
    try:
        _ASN_CACHE.write_text(json.dumps(data, ensure_ascii=False))
    except OSError:
        pass


def _split_v4_v6(cidrs: list[str]) -> tuple[list[str], list[str]]:
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


def resolve_asn_cidrs(asns: list[str], v4_cidrs: list[str],
                      v6_cidrs: list[str], sid: str) -> tuple[list[str], list[str]]:
    all_v4 = list(v4_cidrs)
    all_v6 = list(v6_cidrs)
    cache = _asn_cache_load()
    now_ts = time.time()

    for asn in asns:
        ck = f"AS{asn}"
        if ck in cache and now_ts - cache[ck].get("ts", 0) < _ASN_CACHE_TTL:
            entry = cache[ck]
            if entry.get("v4_count", 0) == 0 and entry.get("v6_count", 0) == 0:
                cache.pop(ck, None)
            else:
                all_v4.extend(entry.get("v4", []))
                all_v6.extend(entry.get("v6", []))
                _emit(sid, "log",
                      f"AS{asn} -> {entry.get('v4_count',0)}v4/{entry.get('v6_count',0)}v6 (缓存)")
                continue

        _emit(sid, "log", f"正在查询 AS{asn} 前缀...")
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            pv4, pv6 = [], []
            for p in data["data"]["prefixes"]:
                prefix = p["prefix"]
                if ":" in prefix:
                    pv6.append(prefix)
                    all_v6.append(prefix)
                else:
                    pv4.append(prefix)
                    all_v4.append(prefix)
            if pv4 or pv6:
                cache[ck] = {"ts": now_ts, "v4_count": len(pv4), "v6_count": len(pv6),
                             "v4": pv4, "v6": pv6}
                _emit(sid, "log", f"AS{asn} -> {len(pv4)}v4/{len(pv6)}v6")
            else:
                _emit(sid, "log", f"AS{asn} -> API 返回空")
        except Exception as e:
            if ck in cache:
                entry = cache[ck]
                all_v4.extend(entry.get("v4", []))
                all_v6.extend(entry.get("v6", []))
                _emit(sid, "log", f"AS{asn} -> 使用上次缓存")
            else:
                _emit(sid, "log", f"AS{asn} -> 查询失败: {e}")

    _asn_cache_save(cache)

    final_v4, final_v6 = _split_v4_v6(all_v4 + all_v6)
    return final_v4, final_v6


def _expand_cidrs(cidrs: list[str], max_ips: int = 5000,
                  sample: bool = False) -> list[str]:
    ips = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            hosts = list(net.hosts())
            if sample and len(hosts) > 3:
                import random
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


# ══════════════════════════════════════════
# Smart subnet probing (完整版 -- 对齐 run.py step_smart_subnet)

_SUBNET_SPLIT = 24
_SUBNET_PROBE = 3
_SUBNET_THRESHOLD = 20
_SUBNET_PORT = 443
_SUBNET_TIMEOUT = 3


def _quick_probe(ip: str, port: int, timeout: float) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except OSError:
        return False


def _sample_ips(subnet: str, n: int) -> list[str]:
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = list(net.hosts())
    if len(hosts) <= n:
        return [str(h) for h in hosts]
    return [str(h) for h in random.sample(hosts, n)]


def _subnet_split(cidr: str) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.prefixlen >= _SUBNET_SPLIT:
        return [str(net)]
    return [str(s) for s in net.subnets(new_prefix=_SUBNET_SPLIT)]


def _smart_subnet_probe(v4_cidrs: list[str], sid: str,
                        threads: int = 100) -> list[str]:
    if not v4_cidrs:
        return []

    to_probe: list[str] = []
    for cidr in v4_cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            to_probe.append(cidr)
            continue
        if net.prefixlen < _SUBNET_THRESHOLD:
            to_probe.extend(_subnet_split(cidr))
        else:
            to_probe.append(cidr)

    if len(to_probe) <= 1:
        return v4_cidrs

    total_subs = len(to_probe)
    _emit(sid, "log", f"智能探活: {len(v4_cidrs)} CIDR -> {total_subs} 子段 (每段抽{_SUBNET_PROBE} IP 探活)")
    _emit(sid, "scan_progress", {"current": 0, "total": total_subs, "stage": "智能探活"})

    alive_subs: set[str] = set()
    total_samples = 0
    fmap: dict = {}
    with ThreadPoolExecutor(max_workers=min(total_subs * _SUBNET_PROBE, threads * 4)) as ex:
        for sub in to_probe:
            for ip in _sample_ips(sub, _SUBNET_PROBE):
                total_samples += 1
                fmap[ex.submit(_quick_probe, ip, _SUBNET_PORT, _SUBNET_TIMEOUT)] = sub

        done = 0
        for future in as_completed(fmap):
            if _cancel_is(sid):
                return v4_cidrs
            sub = fmap[future]
            done += 1
            if done % 100 == 0:
                _emit(sid, "scan_progress", {"current": done, "total": total_samples, "stage": "智能探活"})
            try:
                if future.result():
                    alive_subs.add(sub)
            except Exception:
                pass

    alive_cidrs = sorted(alive_subs)
    if not alive_cidrs:
        _emit(sid, "log", "所有子网均无响应 -- 回退全量扫描")
        return v4_cidrs

    dead_count = total_subs - len(alive_cidrs)
    if dead_count > 0:
        _emit(sid, "log", f"探活完成: {len(alive_cidrs)}/{total_subs} 子段存活 (过滤 {dead_count} 死段)")

    return alive_cidrs


def _fetch_cf_ips(ip_type: int) -> list[str]:
    url = _V4_URL if ip_type == 4 else _V6_URL
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ip-tidy/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return [l.strip() for l in resp.read().decode().splitlines()
                    if l.strip() and not l.startswith("#")]
    except Exception:
        return []


# ══════════════════════════════════════════
# Step 2: cf-scanner TLS 检测
# ══════════════════════════════════════════

def _run_cf_scanner(input_file: Path, output_file: Path,
                    concurrency: int, sid: str) -> int:
    if not CF_SCANNER.is_file():
        _emit(sid, "error", "cf-scanner 未找到，请先编译: cd cf-scanner-src && go build -o ../cf-scanner main.go")
        return 0

    if not os.access(CF_SCANNER, os.X_OK):
        CF_SCANNER.chmod(0o755)

    cmd = [str(CF_SCANNER), "-i", str(input_file), "-o", str(output_file),
           "-c", str(concurrency), "-connect-timeout", "3s"]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)

    total = 0
    pat_total = re.compile(r"(\d+)$")
    pat_prog = re.compile(r"(\d+)/(\d+)\s+\((\d+\.?\d*)%\)")

    got_total = False
    last_done = 0
    for line in proc.stdout:
        if _cancel_is(sid):
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            return 0

        line = line.strip()
        if not got_total:
            m = pat_total.search(line)
            if m and "Counting" not in line:
                try:
                    total = int(m.group(1))
                    if total > 0 and "IP" not in line:
                        pass
                except ValueError:
                    pass
            if "Counting IPs" in line:
                got_total = True

        m = pat_prog.search(line)
        if m:
            done = int(m.group(1))
            tot = int(m.group(2))
            total = tot
            if done > last_done:
                last_done = done
                _emit(sid, "scan_progress", {
                    "current": done, "total": tot, "stage": "cf-scanner TLS检测",
                })

    proc.wait()

    hits = 0
    if output_file.exists():
        with open(output_file) as f:
            hits = sum(1 for _ in f)
    return hits


# ══════════════════════════════════════════
# Step 3: verify.py API 精筛
# ══════════════════════════════════════════

def _verify_batch(entries: list[str], concurrency: int = 32,
                  sid: str = "") -> list[dict]:
    if not entries:
        return []

    _ensure_tmp()
    inp = _TMP_DIR / f"vf_in_{sid}.txt"
    out = _TMP_DIR / f"vf_out_{sid}.txt"
    inp.write_text("\n".join(entries))

    _emit(sid, "log", f"API 验证 {len(entries)} 个节点 (并发={concurrency})...")

    subprocess.run([
        sys.executable, str(VERIFY_PY),
        "--input", str(inp), "--output", str(out),
        "--api", API_URL,
        "--chunk", "500", "--concurrent", str(concurrency),
    ], capture_output=True, text=True, timeout=600)

    results = []
    if out.exists():
        with open(out) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("IP"):
                    continue
                parts = line.split(",")
                if len(parts) >= 7:
                    results.append({
                        "ip": parts[0],
                        "port": int(parts[1]) if parts[1].isdigit() else 0,
                        "colo": parts[3] if len(parts) > 3 else "",
                        "country": parts[4] if len(parts) > 4 else "",
                        "region": parts[5] if len(parts) > 5 else "",
                        "asn": (parts[8].replace("AS", "") if len(parts) > 8 else ""),
                    })

    for f in (inp, out):
        try:
            f.unlink()
        except OSError:
            pass
    return results


# ══════════════════════════════════════════
# Step 4: TCP 延迟测量
# ══════════════════════════════════════════

def _tcp_latency(ip: str, port: int, timeout: float = 3) -> int:
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


def _measure_latencies(results: list[dict], sid: str, threads: int = 100) -> None:
    if not results:
        return
    _emit(sid, "log", f"正在测量 {len(results)} 个节点 TCP 延迟...")
    total = len(results)
    done = 0
    with ThreadPoolExecutor(max_workers=min(threads, 200)) as ex:
        fmap = {ex.submit(_tcp_latency, r["ip"], r["port"], 3): i
                for i, r in enumerate(results)}
        for future in as_completed(fmap):
            if _cancel_is(sid):
                return
            i = fmap[future]
            try:
                lat = future.result()
            except Exception:
                lat = 0
            results[i]["latency"] = lat
            results[i]["latency_str"] = f"{lat}ms" if lat > 0 else "N/A"
            done += 1
            if done % 100 == 0 or done == total:
                _emit(sid, "scan_progress", {
                    "current": done, "total": total, "stage": "延迟测量",
                })


# ══════════════════════════════════════════
# Step 5: 证书反查 (crt.sh)
# ══════════════════════════════════════════

def _cert_enum(results: list[dict], sid: str, threads: int = 100) -> int:
    if not results:
        return 0
    _emit(sid, "log", f"crt.sh 证书反查 {len(results)} 个节点...")

    existing = {r["ip"] for r in results}
    new_ips: dict[str, str] = {}
    total = len(results)
    done = 0

    with ThreadPoolExecutor(max_workers=min(10, threads)) as ex:
        fmap = {}
        for r in results:
            if _cancel_is(sid):
                return 0
            fmap[ex.submit(_crtsh_query, r["ip"])] = r["ip"]

        all_domains: set[str] = set()
        for future in as_completed(fmap):
            if _cancel_is(sid):
                return 0
            done += 1
            try:
                all_domains.update(future.result())
            except Exception:
                pass

    if not all_domains:
        _emit(sid, "log", "crt.sh 未发现关联域名")
        return 0

    _emit(sid, "log", f"发现 {len(all_domains)} 个关联域名, DNS 解析中...")

    with ThreadPoolExecutor(max_workers=min(20, threads)) as ex:
        fmap = {ex.submit(_dns_resolve, d): d for d in all_domains}
        for future in as_completed(fmap):
            if _cancel_is(sid):
                return 0
            try:
                for ip in future.result():
                    if ip not in existing:
                        new_ips[ip] = ""
            except Exception:
                pass

    if not new_ips:
        _emit(sid, "log", "未发现新 IP")
        return 0

    _emit(sid, "log", f"DNS 解析发现 {len(new_ips)} 个新 IP, API 验证中...")

    new_entries = [f"{ip}:443" for ip in new_ips]
    new_results = _verify_batch(new_entries, concurrency=min(32, threads), sid=sid)

    for r in new_results:
        r["latency"] = 0
        r["latency_str"] = "N/A"

    results.extend(new_results)
    _emit(sid, "log", f"证书反查新增 {len(new_results)} 个节点")
    return len(new_results)


def _crtsh_query(ip: str) -> list[str]:
    try:
        url = f"https://crt.sh/?q={ip}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "ip-tidy/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        domains: set[str] = set()
        for entry in (data if isinstance(data, list) else []):
            for field in ("name_value", "common_name"):
                val = entry.get(field, "")
                if val:
                    for d in val.split("\n"):
                        d = d.strip().lower()
                        if d and not d.startswith("*"):
                            domains.add(d)
        return list(domains)
    except Exception:
        return []


def _dns_resolve(domain: str) -> list[str]:
    try:
        result = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        return [r[4][0] for r in result]
    except Exception:
        return []


# ══════════════════════════════════════════
# Step 6: 测速
# ══════════════════════════════════════════

def _run_speed_test(ip: str, port: int) -> str:
    best = 0.0
    for url, size_mb in _SPEED_URLS:
        try:
            timeout = 15 if size_mb < 100 else 45
            r = subprocess.run([
                "curl", "--resolve", f"speed.cloudflare.com:{port}:{ip}",
                "-o", "/dev/null", "-s", "-w", "%{speed_download}",
                "--connect-timeout", "5", "--max-time", str(timeout), url,
            ], capture_output=True, text=True, timeout=timeout + 10)
            mbps = round(float(r.stdout.strip() or 0) * 8 / 1_000_000, 2)
            if mbps > best:
                best = mbps
        except Exception:
            continue
    if best > 0:
        return f"{best:.2f} MB/s"
    return "N/A"


# ══════════════════════════════════════════
# 扫描任务入口
# ══════════════════════════════════════════

def _finalize_results(results: list[dict], delay_threshold: int,
                      sid: str) -> list[dict]:
    filtered = [r for r in results
                if r.get("latency", 0) > 0 and r["latency"] <= delay_threshold]
    if not filtered:
        filtered = [r for r in results if r.get("latency", 0) > 0]
    if not filtered:
        filtered = results
    filtered.sort(key=lambda r: r.get("latency", 9999))
    return filtered


def _build_dc_list(results: list[dict]) -> list[dict]:
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


def _stream_and_save(results: list[dict], sid: str) -> None:
    with _RESULTS_LOCK:
        _SCAN_RESULTS[sid] = results
    for r in results:
        _emit(sid, "scan_result", r)


def run_scan(sid: str, params: dict) -> None:
    mode = params.get("mode", "asn_cidr")
    port_mode = params.get("port_mode", "default")
    custom_ports = params.get("custom_ports", "")
    threads = int(params.get("threads", 100))
    delay_ms = int(params.get("delay", 500))
    do_speed = params.get("speed", False)
    do_cert = params.get("cert", False)
    do_smart = params.get("smart", False)
    ip_mode = params.get("ip_mode", "all")

    _cancel_get(sid)

    # ── 1. 解析端口列表 ──
    ports_str = _resolve_port_list(port_mode, custom_ports)
    _emit(sid, "log", f"端口模式: {port_mode} -> {ports_str[:80]}{'...' if len(ports_str)>80 else ''} ({_port_count(ports_str)} 个)")

    targets: list[str] = []
    masscan_hits: list[str] = []

    # ── 2. 获取目标 ──
    if mode == "asn_cidr":
        _emit(sid, "log", "=== ASN/CIDR 扫描模式 ===")
        asns = [s.strip() for s in params.get("asns", "").split(",") if s.strip().isdigit()]
        v4_cidrs = []
        v6_cidrs = []
        for s in params.get("cidrs", "").replace("，", ",").split(","):
            s = s.strip()
            if not s or "/" not in s:
                continue
            try:
                net = ipaddress.ip_network(s, strict=False)
                if net.version == 6:
                    v6_cidrs.append(str(net))
                else:
                    v4_cidrs.append(str(net))
            except ValueError:
                pass

        if not asns and not v4_cidrs and not v6_cidrs:
            _emit(sid, "error", "请输入 ASN 或 CIDR")
            return

        resolved_v4, resolved_v6 = resolve_asn_cidrs(asns, v4_cidrs, v6_cidrs, sid)
        if ip_mode == "v4":
            cidrs = resolved_v4
            v4_final, v6_final = resolved_v4, []
        elif ip_mode == "v6":
            cidrs = resolved_v6
            v4_final, v6_final = [], resolved_v6
        else:
            cidrs = resolved_v4 + resolved_v6
            v4_final, v6_final = resolved_v4, resolved_v6

        if not cidrs:
            _emit(sid, "error", "无可用 CIDR")
            return

        _emit(sid, "log", f"解析得到 {len(cidrs)} 个 CIDR 段 (v4: {len(v4_final)}, v6: {len(v6_final)})")

        # Save CIDRs for v6 export
        with _CIDR_LOCK:
            _CIDR_CACHE[sid] = cidrs

        # 智能子网分级
        if do_smart and v4_final:
            v4_probed = _smart_subnet_probe(v4_final, sid, threads)
            _emit(sid, "log", f"智能探活后: {len(v4_probed)} IPv4 子段")
            v4_final = v4_probed

        # ── 3. masscan (IPv4 CIDR -> 开放端口) ──
        if v4_final and _masscan_available:
            masscan_rate = _probe_masscan_rate()
            cidr_file = _TMP_DIR / f"cidrs_v4_{sid}.txt"
            cidr_file.write_text("\n".join(v4_final) + "\n")
            _emit(sid, "log", f"masscan 扫描 IPv4 CIDR ({_port_count(ports_str)} 端口, {masscan_rate} pps)...")
            masscan_hits = _run_masscan(cidr_file, ports_str, masscan_rate, sid)
            try:
                cidr_file.unlink()
            except OSError:
                pass
        elif v4_final:
            _emit(sid, "log", "masscan 不可用，回退到直接 cf-scanner 扫描")
            max_ips = 5000
            ips = _expand_cidrs(v4_final, max_ips=max_ips)
            port_list = [p.strip() for p in ports_str.split(",") if p.strip().isdigit()]
            for ip in ips:
                for p in port_list:
                    targets.append(f"{ip}:{p}")

        # ── 4. IPv6 直接 cf-scanner ──
        if v6_final:
            max_ips = 500
            ip_list = _expand_cidrs(v6_final, max_ips=max_ips)
            port_list = [p.strip() for p in ports_str.split(",") if p.strip().isdigit()]
            for ip in ip_list:
                for p in port_list:
                    targets.append(f"{ip}:{p}")

    elif mode == "custom":
        _emit(sid, "log", "=== 自定义扫描模式 ===")
        port_list = ports_str.split(",")
        for line in params.get("ips", "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            ip = parts[0]
            if len(parts) > 1 and parts[1].isdigit():
                targets.append(f"{ip}:{parts[1]}")
            else:
                for p in port_list:
                    p = p.strip()
                    if p:
                        targets.append(f"{ip}:{p}")
        if not targets:
            _emit(sid, "error", "未提供有效 IP")
            return
        _emit(sid, "log", f"解析到 {len(targets)} 个 IP:port 目标")

    else:
        _emit(sid, "error", f"未知模式: {mode}")
        return

    # ── 5. cf-scanner TLS 检测 ──
    _ensure_tmp()
    cf_in = _TMP_DIR / f"cf_in_{sid}.txt"
    cf_out = _TMP_DIR / f"cf_out_{sid}.txt"

    # Merge masscan hits + direct targets
    all_targets = masscan_hits + targets
    if all_targets:
        cf_in.write_text("\n".join(all_targets) + "\n")

    cf_total = len(masscan_hits) + len(targets)
    if cf_total > 0:
        _emit(sid, "log", f"cf-scanner TLS 检测 ({cf_total} 目标, 并发={threads})")
        hit_count = _run_cf_scanner(cf_in, cf_out, threads, sid)
    else:
        hit_count = 0

    if _cancel_is(sid):
        return

    if hit_count == 0:
        _emit(sid, "error", "未检测到 CF 节点")
        _emit(sid, "scan_complete", {"total": 0, "dc_list": []})
        return

    _emit(sid, "log", f"cf-scanner 命中 {hit_count} 个节点")

    # ── 6. API 验证 ──
    hits = []
    with open(cf_out) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                line = f"{line}:{ports_str.split(',')[0].strip()}"
            hits.append(line)

    results = _verify_batch(hits, concurrency=min(32, threads), sid=sid)
    if _cancel_is(sid):
        return

    _emit(sid, "log", f"API 验证通过 {len(results)} 个节点")

    _enrich_geoip(results)

    if not results:
        _emit(sid, "error", "API 验证通过 0 个节点")
        _emit(sid, "scan_complete", {"total": 0, "dc_list": []})
        return

    # ── 7. 证书反查 (可选) ──
    if do_cert:
        added = _cert_enum(results, sid, threads)
        if added:
            _emit(sid, "log", f"证书反查新增 {added} 个节点")

    if _cancel_is(sid):
        return

    # ── 8. TCP 延迟 ──
    _measure_latencies(results, sid, threads=min(threads, 200))
    if _cancel_is(sid):
        return

    # ── 9. 筛选 & 排序 ──
    filtered = _finalize_results(results, delay_ms, sid)
    dc_list = _build_dc_list(filtered)
    _stream_and_save(filtered, sid)

    _emit(sid, "scan_complete", {"total": len(filtered), "dc_list": dc_list})
    _emit(sid, "log", f"扫描完成: {len(filtered)} 个节点 ({len(dc_list)} 个数据中心)")

    # ── 10. 测速 (可选) ──
    if do_speed and filtered:
        _emit(sid, "log", f"开始批量测速 ({len(filtered)} 个节点)...")
        done_spd = 0
        total_spd = len(filtered)
        with ThreadPoolExecutor(max_workers=min(10, threads)) as ex:
            fmap = {}
            for r in filtered:
                if _cancel_is(sid):
                    break
                fmap[ex.submit(_run_speed_test, r["ip"], r["port"])] = r["ip"]
            for future in as_completed(fmap):
                if _cancel_is(sid):
                    break
                ip = fmap[future]
                try:
                    spd = future.result()
                except Exception:
                    spd = "N/A"
                _emit(sid, "speed_result", {"ip": ip, "speed": spd})
                done_spd += 1
                if done_spd % 10 == 0:
                    _emit(sid, "scan_progress", {
                        "current": done_spd, "total": total_spd, "stage": "测速",
                    })
        _emit(sid, "log", "测速完成")

    _emit(sid, "task_complete", None)

    # Cleanup
    for f in (cf_in, cf_out):
        try:
            f.unlink()
        except OSError:
            pass



# ══════════════════════════════════════════
# Flask Routes
# ══════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory("web", "index.html")


@app.route("/api/events")
def api_events():
    sid = request.args.get("session", "")
    if not sid:
        return jsonify({"error": "missing session"}), 400
    q = _get_or_create_queue(sid)

    def generate():
        while True:
            try:
                msg = q.get(timeout=15)
                yield f"data: {json.dumps(msg, ensure_ascii=False)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'ping', 'data': None})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no",
                        "Access-Control-Allow-Origin": "*",
                    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json() or {}
    sid = data.get("session", _gen_session_id())

    params = {
        "mode": data.get("mode", "official"),
        "port": data.get("port", 443),
        "threads": data.get("threads", 100),
        "delay": data.get("delay", 500),
        "speed": data.get("speed", False),
        "cert": data.get("cert", False),
        "ip_type": data.get("ip_type", 4),
        "ip_mode": data.get("ip_mode", "all"),
        "asns": data.get("asns", ""),
        "cidrs": data.get("cidrs", ""),
        "ips": data.get("ips", ""),
        "fallback_port": data.get("fallback_port", 443),
    }

    t = threading.Thread(target=run_scan, args=(sid, params), daemon=True)
    t.start()
    return jsonify({"status": "started", "session": sid})


@app.route("/api/speed-test", methods=["POST"])
def api_speed_test():
    data = request.get_json() or {}
    ip = data.get("ip", "")
    port = int(data.get("port", 443))
    sid = data.get("session", "")
    if not ip:
        return jsonify({"error": "missing ip"}), 400

    def _do():
        r = _run_speed_test(ip, port)
        _emit(sid, "speed_result", {"ip": ip, "speed": r})

    threading.Thread(target=_do, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/cancel", methods=["POST"])
def api_cancel():
    data = request.get_json() or {}
    sid = data.get("session", "")
    if sid:
        with _CANCEL_LOCK:
            f = _CANCEL_FLAGS.get(sid)
            if f:
                f.set()
        _emit(sid, "log", "任务取消中...")
    return jsonify({"status": "cancelled"})


@app.route("/api/export", methods=["POST"])
def api_export():
    data = request.get_json() or {}
    sid = data.get("session", "")
    with _RESULTS_LOCK:
        results = _SCAN_RESULTS.get(sid, [])
    if not results:
        return jsonify({"error": "no results"}), 404

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = BASE / f"export_{ts}.csv"
    with open(path, "w") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN,协议\n")
        for r in results:
            proto = "IPv6" if ":" in r["ip"] else "IPv4"
            f.write(f"{r['ip']},{r.get('port','-')},TRUE,{r.get('colo','')},"
                    f"{r.get('country','')},{r.get('region','')},"
                    f"{r.get('latency','')},,AS{r.get('asn','')},{proto}\n")
    return send_from_directory(str(BASE), path.name, as_attachment=True)


@app.route("/api/export-cidrs", methods=["POST"])
def api_export_cidrs():
    data = request.get_json() or {}
    sid = data.get("session", "")
    with _CIDR_LOCK:
        cidrs = _CIDR_CACHE.get(sid, [])
    if not cidrs:
        return jsonify({"error": "no cidrs"}), 404

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = BASE / f"output_v6_{ts}.csv"
    with open(path, "w") as f:
        f.write("CIDR,IP数量,协议\n")
        for cidr in cidrs:
            try:
                cnt = ipaddress.ip_network(cidr, strict=False).num_addresses
            except ValueError:
                cnt = 0
            proto = "IPv6" if ":" in cidr else "IPv4"
            f.write(f"{cidr},{cnt},{proto}\n")
    return send_from_directory(str(BASE), path.name, as_attachment=True)


@app.route("/api/server-info", methods=["GET"])
def api_server_info():
    import os as _os
    cpu = _os.cpu_count() or 1
    mem = 512
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if "MemAvailable" in line:
                    mem = int(line.split()[1]) // 1024
                    break
    except (FileNotFoundError, OSError):
        pass
    return jsonify({
        "cpu": cpu,
        "memory_mb": mem,
        "cf_scanner": CF_SCANNER.is_file(),
        "geoip": _geoip_available,
    })


@app.route("/api/results", methods=["GET"])
def api_results():
    sid = request.args.get("session", "")
    with _RESULTS_LOCK:
        results = _SCAN_RESULTS.get(sid, [])
    return jsonify(results)


def main():
    parser = argparse.ArgumentParser(description="IP-Tidy WEB Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if CF_SCANNER.is_file():
        print(f"[OK] cf-scanner: {CF_SCANNER}")
    else:
        print(f"[WARN] cf-scanner 未找到: cd cf-scanner-src && go build -o ../cf-scanner main.go")

    print(f"IP-Tidy WEB http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug,
            threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
