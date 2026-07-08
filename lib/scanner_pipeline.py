"""IP-Tidy 共享管道层 -- 扫描步骤，通过 progress_callback 报告进度"""

import os
import re
import sys
import json
import time
import ipaddress
import subprocess
import urllib.request
import tempfile
from pathlib import Path
from typing import Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from .scanner_utils import (
    BASE, CF_SCANNER, VERIFY_PY, API_URL, WIDE_PORTS, MASSCAN_BIN, MASSCAN_BATCH,
    merge_cidrs, parse_masscan_xml,
    subnet_split, quick_probe, sample_ips,
    port_count, split_port_batches,
    masscan_adapter_ip,
    read_masscan_stderr,
    SUBNET_PROBE, SUBNET_THRESHOLD, SUBNET_PORT, SUBNET_TIMEOUT,
)

_ASN_CACHE = BASE / ".asn_cache.json"
_ASN_CACHE_TTL = 7 * 86400


def _asn_cache_load() -> dict:
    try:
        if _ASN_CACHE.exists():
            return json.loads(_ASN_CACHE.read_bytes())
    except (json.JSONDecodeError, OSError):
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
                cache[ck] = {"ts": now_ts, "v4_count": 0, "v4": []}
                if progress_callback:
                    progress_callback("log", f"AS{asn} -> API 返回空")
        except (urllib.error.URLError, json.JSONDecodeError, ValueError) as e:
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
    _tag = sid or str(os.getpid())
    total_ports = port_count(ports_str)
    batches = split_port_batches(ports_str)
    is_multi = len(batches) > 1
    all_open: list[str] = []
    adapter_ip = masscan_adapter_ip()
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]

    if is_multi and progress_callback:
        progress_callback("log", f"Masscan: {total_ports} 端口 -> {len(batches)} 批次 (~{MASSCAN_BATCH}/批)")

    for bi, batch_ports in enumerate(batches):
        batch_xml = BASE / f".masscan_{_tag}_b{bi+1}.xml" if is_multi else BASE / f".masscan_{_tag}.xml"
        cmd = sudo + [MASSCAN_BIN,
                      "-iL", str(cidr_file),
                      "-p", batch_ports,
                      "--rate", str(rate),
                      "-oX", str(batch_xml),
                      "--wait", "3"]
        if adapter_ip:
            cmd += ["--adapter-ip", adapter_ip]

        prefix = f"[{bi+1}/{len(batches)}] " if is_multi else ""
        if progress_callback:
            progress_callback("log", f"{prefix}Masscan 批次 {batch_ports[:60]}... ({rate} pps)")

        def _masscan_progress(pct, extra):
            if progress_callback:
                progress_callback("masscan_progress",
                                  {"current": int(pct * total_ports / 100 / max(len(batches), 1)),
                                   "total": total_ports, "stage": f"masscan {prefix}".strip()})

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        stderr_lines = read_masscan_stderr(proc, prefix, _masscan_progress)
        try:
            proc.wait(timeout=600)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise

        if proc.returncode != 0:
            err_text = "".join(stderr_lines).lower()
            if "permission" in err_text or "init: failed" in err_text:
                if progress_callback:
                    progress_callback("error", "Masscan 需要 raw socket 权限")
                    progress_callback("log", "尝试: setcap cap_net_raw+ep $(which masscan)")
            return all_open

        if os.geteuid() != 0:
            subprocess.run(["sudo", "-n", "chown",
                            f"{os.getuid()}:{os.getgid()}", str(batch_xml)],
                           stdin=subprocess.DEVNULL, check=False)

        if batch_xml.exists() and batch_xml.stat().st_size > 0:
            all_open.extend(parse_masscan_xml(batch_xml))

        if is_multi:
            try:
                batch_xml.unlink()
            except OSError:
                pass

    if progress_callback:
        progress_callback("log", f"开放端口: {len(all_open)}（Syn-Ack确认）")
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

    try:
        proc.wait(timeout=600)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise
    hits = 0
    if output_file.exists():
        with open(output_file, encoding="utf-8") as f:
            hits = sum(1 for _ in f)
    return hits


def verify_batch(entries: list[str], concurrency: int = 32,
                 progress_callback: Optional[Callable] = None,
                 sid: str = "") -> list[dict]:
    if not entries:
        return []
    _tag = sid or str(os.getpid())
    inp = BASE / f".vf_in_{_tag}.txt"
    out = BASE / f".vf_out_{_tag}.txt"
    inp.write_text("\n".join(entries))

    if progress_callback:
        progress_callback("log", f"API 验证 {len(entries)} 个 IP (并发={concurrency})...")

    subprocess.run([
        sys.executable, str(VERIFY_PY),
        "--input", str(inp), "--output", str(out),
        "--api", API_URL,
        "--chunk", "500", "--concurrent", str(concurrency),
    ], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, text=True, timeout=600)

    results = []
    if out.exists():
        with open(out, encoding="utf-8") as f:
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
    with ThreadPoolExecutor(max_workers=min(total_subs * SUBNET_PROBE, threads, 200)) as ex:
        for sub in to_probe:
            for ip in sample_ips(sub, SUBNET_PROBE):
                total_samples += 1
                fmap[ex.submit(quick_probe, ip, SUBNET_PORT, SUBNET_TIMEOUT)] = sub
        done = 0
        for future in as_completed(fmap):
            sub = fmap[future]
            done += 1
            if (done % 100 == 0 or done == total_samples) and progress_callback:
                progress_callback("scan_progress", {"current": done, "total": total_samples, "stage": "智能探活"})
            try:
                if future.result():
                    alive_subs.add(sub)
            except (OSError, RuntimeError):
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
        except (KeyError, TypeError):
            pass
