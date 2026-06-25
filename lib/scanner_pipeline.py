"""IP-Tidy 共享管道层 -- 扫描步骤，通过 progress_callback 报告进度"""

import os
import sys
import re
import time
import json
import socket
import ipaddress
import threading
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import Optional, Callable, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from .scanner_utils import (
    BASE, CF_SCANNER, VERIFY_PY, API_URL, WIDE_PORTS,
    _MASSCAN_BATCH,
    merge_cidrs,
    subnet_split, quick_probe, sample_ips,
    port_count, split_port_batches,
    masscan_adapter_ip, masscan_bin,
    read_masscan_stderr,
    SUBNET_PROBE, SUBNET_THRESHOLD, SUBNET_PORT, SUBNET_TIMEOUT,
)

_ASN_CACHE = BASE / ".asn_cache.json"
_ASN_CACHE_TTL = 7 * 86400


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


def ensure_cf_scanner() -> None:
    if not CF_SCANNER.is_file():
        print("  [FAIL] cf-scanner 未找到，请先编译: cd cf-scanner-src && go build -o ../cf-scanner main.go")
        sys.exit(1)
    if not os.access(CF_SCANNER, os.X_OK):
        CF_SCANNER.chmod(0o755)


def resolve_asn_cidrs(asns: list[str], v4_cidrs: list[str],
                      progress_callback: Optional[Callable] = None) -> list[str]:
    all_v4 = list(v4_cidrs)
    cache = _asn_cache_load()
    now_ts = time.time()

    for asn in asns:
        ck = f"AS{asn}"
        if ck in cache and now_ts - cache[ck].get("ts", 0) < _ASN_CACHE_TTL:
            entry = cache[ck]
            if entry.get("v4_count", 0) == 0:
                cache.pop(ck, None)
            else:
                all_v4.extend(entry.get("v4", []))
                if progress_callback:
                    progress_callback("log", f"AS{asn} -> {entry.get('v4_count',0)}v4 (缓存)")
                continue

        if progress_callback:
            progress_callback("log", f"正在查询 AS{asn} 前缀...")
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            pv4 = []
            for p in data["data"]["prefixes"]:
                prefix = p["prefix"]
                if ":" not in prefix:
                    pv4.append(prefix)
                    all_v4.append(prefix)
            if pv4:
                cache[ck] = {"ts": now_ts, "v4_count": len(pv4), "v4": pv4}
                if progress_callback:
                    progress_callback("log", f"AS{asn} -> {len(pv4)}v4")
            else:
                if progress_callback:
                    progress_callback("log", f"AS{asn} -> API 返回空")
        except Exception as e:
            if ck in cache:
                entry = cache[ck]
                all_v4.extend(entry.get("v4", []))
                if progress_callback:
                    progress_callback("log", f"AS{asn} -> 使用上次缓存")
            else:
                if progress_callback:
                    progress_callback("log", f"AS{asn} -> 查询失败: {e}")

    _asn_cache_save(cache)
    return merge_cidrs(all_v4)


def run_masscan(cidr_file: Path, ports_str: str, rate: int,
                progress_callback: Optional[Callable] = None,
                sid: str = "") -> list[str]:
    total_ports = port_count(ports_str)
    batches = split_port_batches(ports_str)
    is_multi = len(batches) > 1
    all_open: list[str] = []
    adapter_ip = masscan_adapter_ip()
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]

    if is_multi and progress_callback:
        progress_callback("log", f"masscan: {total_ports} 端口 -> {len(batches)} 批次 (~{_MASSCAN_BATCH}/批)")

    for bi, batch_ports in enumerate(batches):
        batch_xml = BASE / f".masscan_{sid}_b{bi+1}.xml" if is_multi else BASE / ".masscan_result.xml"
        cmd = sudo + [masscan_bin(),
                      "-iL", str(cidr_file),
                      "-p", batch_ports,
                      "--rate", str(rate),
                      "-oX", str(batch_xml),
                      "--wait", "3"]
        if adapter_ip:
            cmd += ["--adapter-ip", adapter_ip]

        prefix = f"[{bi+1}/{len(batches)}] " if is_multi else ""
        if progress_callback:
            progress_callback("log", f"{prefix}masscan 批次 {batch_ports[:60]}... ({rate} pps)")

        def _masscan_progress(pct, extra):
            if progress_callback:
                progress_callback("masscan_progress",
                                  {"current": int(pct * total_ports / 100 / max(len(batches), 1)),
                                   "total": total_ports, "stage": f"masscan {prefix}".strip()})

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        stderr_lines = read_masscan_stderr(proc, prefix, _masscan_progress)
        proc.wait()

        if proc.returncode != 0:
            err_text = "".join(stderr_lines).lower()
            if "permission" in err_text or "init: failed" in err_text:
                if progress_callback:
                    progress_callback("error", "masscan 需要 raw socket 权限")
                    progress_callback("log", "尝试: setcap cap_net_raw+ep $(which masscan)")
            return all_open

        if os.geteuid() != 0:
            subprocess.run(["sudo", "-n", "chown",
                            f"{os.getuid()}:{os.getgid()}", str(batch_xml)],
                           stdin=subprocess.DEVNULL, check=False)

        if batch_xml.exists() and batch_xml.stat().st_size > 0:
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
            except Exception:
                pass

        if is_multi:
            try:
                batch_xml.unlink()
            except OSError:
                pass

    if progress_callback:
        progress_callback("log", f"masscan 开放端口: {len(all_open)}（Syn-Ack确认）")
    return all_open


def run_cf_scanner(input_file: Path, output_file: Path,
                   concurrency: int,
                   progress_callback: Optional[Callable] = None,
                   sid: str = "") -> int:
    ensure_cf_scanner()
    cmd = [str(CF_SCANNER), "-i", str(input_file), "-o", str(output_file),
           "-c", str(concurrency), "-connect-timeout", "3s"]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)

    pat_prog = re.compile(r"(\d+)/(\d+)\s+\((\d+\.?\d*)%\)")
    last_done = 0
    for line in proc.stdout:
        line = line.strip()
        m = pat_prog.search(line)
        if m:
            done = int(m.group(1))
            tot = int(m.group(2))
            if done > last_done:
                last_done = done
                if progress_callback:
                    progress_callback("scan_progress", {
                        "current": done, "total": tot, "stage": "cf-scanner TLS检测",
                    })

    proc.wait()
    hits = 0
    if output_file.exists():
        with open(output_file) as f:
            hits = sum(1 for _ in f)
    return hits


def verify_batch(entries: list[str], concurrency: int = 32,
                 progress_callback: Optional[Callable] = None,
                 sid: str = "") -> list[dict]:
    if not entries:
        return []
    inp = BASE / f".vf_in_{sid}.txt"
    out = BASE / f".vf_out_{sid}.txt"
    inp.write_text("\n".join(entries))

    if progress_callback:
        progress_callback("log", f"API 验证 {len(entries)} 个 IP (并发={concurrency})...")

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


def smart_subnet_probe(v4_cidrs: list[str],
                       progress_callback: Optional[Callable] = None,
                       sid: str = "",
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
        if net.prefixlen < SUBNET_THRESHOLD:
            to_probe.extend(subnet_split(cidr))
        else:
            to_probe.append(cidr)
    if len(to_probe) <= 1:
        return v4_cidrs
    total_subs = len(to_probe)
    if progress_callback:
        progress_callback("log", f"智能探活: {len(v4_cidrs)} CIDR -> {total_subs} 子段 (每段抽{SUBNET_PROBE} IP 探活)")
        progress_callback("scan_progress", {"current": 0, "total": total_subs, "stage": "智能探活"})
    alive_subs: set[str] = set()
    total_samples = 0
    fmap: dict = {}
    with ThreadPoolExecutor(max_workers=min(total_subs * SUBNET_PROBE, threads * 4)) as ex:
        for sub in to_probe:
            for ip in sample_ips(sub, SUBNET_PROBE):
                total_samples += 1
                fmap[ex.submit(quick_probe, ip, SUBNET_PORT, SUBNET_TIMEOUT)] = sub
        done = 0
        for future in as_completed(fmap):
            sub = fmap[future]
            done += 1
            if done % 100 == 0 and progress_callback:
                progress_callback("scan_progress", {"current": done, "total": total_samples, "stage": "智能探活"})
            try:
                if future.result():
                    alive_subs.add(sub)
            except Exception:
                pass
    alive_cidrs = sorted(alive_subs)
    if not alive_cidrs:
        if progress_callback:
            progress_callback("log", "所有子网均无响应 -- 回退全量扫描")
        return v4_cidrs
    dead_count = total_subs - len(alive_cidrs)
    if dead_count > 0 and progress_callback:
        progress_callback("log", f"探活完成: {len(alive_cidrs)}/{total_subs} 子段存活 (过滤 {dead_count} 死段)")
    return alive_cidrs


def run_speed_test(ip: str, port: int) -> str:
    return _run_speed_test_impl(ip, port)


def _run_speed_test_impl(ip: str, port: int) -> str:
    best = 0.0
    for host, url, size_mb, _ in [
        ("speed.cloudflare.com", "https://speed.cloudflare.com/__down?bytes=1048576", 1, "1MB"),
        ("speed.cloudflare.com", "https://speed.cloudflare.com/__down?bytes=10485760", 10, "10MB"),
        ("speed.cloudflare.com", "https://speed.cloudflare.com/__down?bytes=100000000", 100, "100MB"),
    ]:
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


def enrich_geoip(results: list[dict]) -> None:
    try:
        from .geoip import lookup as geo_lookup, is_available as geo_available
    except ImportError:
        return
    if not geo_available():
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


def geo_available() -> bool:
    try:
        from .geoip import is_available as _ga
        return _ga()
    except Exception:
        return False
