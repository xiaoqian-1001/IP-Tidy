"""
IP-Tidy -- ASN -> CIDR -> masscan -> CF 反代 IP 检测 -> CSV 输出
CLI 模式入口: 终端交互 + 渲染，核心逻辑由共享模块提供
"""

import sys
import os
import re
import time
import json
import ipaddress
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
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
from lib.scanner_utils import (
    find_iface, probe_masscan_rate, detect_hardware, tcp_latency, cf_download, test_one,
    read_masscan_stderr, parse_masscan_xml,
    read_default_ports, parse_targets, expand_cidrs, port_count,
    split_port_batches, adjust_concurrency, random_ports, random_probe_ports,
    WIDE_PORTS, cidr_count,
    CF_SCANNER, VERIFY_PY, API_URL, _MASSCAN_BATCH,
    load_incremental_state, save_incremental_state, compute_cidr_diff, _incr_tag, INCR_DIR,
)
from lib.scanner_pipeline import (
    BASE, resolve_asn_cidrs, run_masscan, run_cf_scanner, verify_batch,
    smart_subnet_probe, ensure_cf_scanner,
    enrich_geoip, geo_available as pipeline_geo_available,
)

VERSION = "unknown"
try:
    _vp = BASE / "VERSION"
    if _vp.is_file():
        VERSION = _vp.read_text().strip()
except OSError:
    pass

_SUBNET_THRESHOLD = 20


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
    smart_mode: bool = False


def init_runtime() -> ScannerConfig:
    cfg = ScannerConfig()
    cfg.cpu, cfg.ram_mb = detect_hardware()
    cfg.masscan_rate = probe_masscan_rate()
    cfg.cf_concurrency = max(200, min(cfg.cpu * 100, 500))
    cfg.api_concurrency = min(cfg.cpu * 16, 32)
    cfg.api_chunk = 2000 if cfg.ram_mb < 1024 else 5000
    cfg.scan_ports = read_default_ports(BASE / "ports.txt")

    pub_ip = get_public_ip()
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


def step_fetch_prefixes(cfg: ScannerConfig, asns: list[str],
                        v4_cidrs: list[str]) -> list[str]:
    all_v4 = list(v4_cidrs)
    if v4_cidrs:
        print(f"  监测 IPv4 CIDR: {len(v4_cidrs)} 个 ({', '.join(v4_cidrs[:5])}{'...' if len(v4_cidrs) > 5 else ''})")

    def _cb(typ, data):
        if typ == "log":
            print(f"  {data}")

    final_v4 = resolve_asn_cidrs(asns, v4_cidrs, progress_callback=_cb)

    (BASE / "cidrs.txt").write_text("\n".join(final_v4))
    (BASE / "cidrs_v4.txt").write_text("\n".join(final_v4))

    v4_ip_count = cidr_count(final_v4)
    print(f"  -> 合并: IPv4 共计 {len(final_v4)} 段 -> {v4_ip_count:,} IP")

    if not final_v4:
        print(c("  [FAIL] 无可用 CIDR，请检查输入是否正确", C.LR))
        sys.exit(1)
    return final_v4


def step_masscan(cfg: ScannerConfig) -> int:
    step_start = time.time()

    ip_file = BASE / "cidrs_v4.txt"
    if not ip_file.exists() or ip_file.stat().st_size == 0:
        ip_file = BASE / "cidrs.txt"
        if not ip_file.exists() or ip_file.stat().st_size == 0:
            print(c("  [FAIL] 无 IPv4 CIDR，跳过 Masscan", C.LR))
            return 0

    if ip_file.name == "cidrs.txt":
        v4_only = []
        with open(ip_file) as f:
            for line in f:
                line = line.strip()
                if line and ":" not in line:
                    v4_only.append(line)
        if not v4_only:
            print(c("  [FAIL] cidrs.txt 无 IPv4，跳过 Masscan", C.LR))
            return 0
        tmp_v4 = BASE / "cidrs_v4.txt"
        tmp_v4.write_text("\n".join(v4_only) + "\n")
        ip_file = tmp_v4

    batches = split_port_batches(cfg.scan_ports)
    total_ports = port_count(cfg.scan_ports)
    if len(batches) > 1:
        print(f"  端口总数 {total_ports} -> {len(batches)} 批次扫描 (~{_MASSCAN_BATCH}/批)")

    all_open: list[str] = []
    batch_total = len(batches)
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
    adapter_ip = None
    step_start = time.time()

    for bi, batch_ports in enumerate(batches):
        batch_xml = BASE / "masscan_result.xml" if batch_total == 1 else BASE / f"masscan_batch_{bi + 1}.xml"
        cmd = sudo + [
            "masscan", "-iL", str(ip_file),
            "-p", batch_ports,
            "--rate", str(cfg.masscan_rate),
            "-oX", str(batch_xml),
            "--wait", "3",
        ]
        prefix = f"[{bi + 1}/{batch_total}] " if batch_total > 1 else ""

        def _masscan_progress(pct, _extra):
            elapsed = time.time() - step_start
            eta = (elapsed / pct * (100 - pct)) if pct > 1 else 0
            eta_s = f" | ETA {int(eta // 60)}分{int(eta % 60)}秒" if pct > 1 else ""
            write_progress(pct, prefix + eta_s)

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        stderr_lines = read_masscan_stderr(proc, prefix, _masscan_progress)
        proc.wait()

        if proc.returncode != 0:
            sys.stderr.write("\n")
            sys.stderr.flush()
            err = "".join(stderr_lines).lower()
            if "permission denied" in err or "init: failed" in err:
                print(c("  [FAIL] Masscan 需要 raw socket 权限", C.LR))
                if os.geteuid() != 0:
                    print("  解决: sudo python3 run.py ...  (以 root 运行)")
                    print("  或: sudo setcap cap_net_raw+ep $(which masscan)")
            elif "password is required" in err or "a password is required" in err:
                print(c("  [FAIL] sudo 需要密码交互，当前环境无法输入", C.LR))
                print("  解决: sudo python3 run.py ...  (以 root 运行)")
                print("  或: sudo setcap cap_net_raw+ep $(which masscan)")
            else:
                sys.stderr.write("".join(stderr_lines))
                sys.stderr.flush()
                print(c(f"\n  [FAIL] Masscan 返回码 {proc.returncode}", C.LR))
            raise subprocess.CalledProcessError(proc.returncode, cmd)

        write_progress_done(prefix)

        if os.geteuid() != 0:
            subprocess.run(["sudo", "-n", "chown",
                            f"{os.getuid()}:{os.getgid()}", str(batch_xml)],
                           stdin=subprocess.DEVNULL, check=False)

        if batch_total > 1:
            print(f"  解析 {batch_xml.name} ...", flush=True)
        all_open.extend(parse_masscan_xml(batch_xml))

        if batch_total > 1:
            try:
                batch_xml.unlink()
            except OSError:
                pass

    text_file = BASE / "masscan_result.txt"
    text_file.write_text("\n".join(all_open) + "\n")
    print(f"  开放端口: {len(all_open)}（Syn-Ack确认）")
    step_s = int(time.time() - step_start)
    m, s = divmod(step_s, 60)
    print(c(f"  本步耗时: {m}分{s}秒" if m else f"  本步耗时: {step_s}秒", C.GY))

    return len(all_open)

def _pipeline(cfg: ScannerConfig) -> tuple[int, int]:
    step_start = time.time()
    input_file = BASE / "masscan_result.txt"
    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"

    if input_file.stat().st_size == 0:
        return 0, 0

    ensure_cf_scanner()
    hits_file.write_text("")
    verified_file.write_text("")

    adj = adjust_concurrency(cfg.cf_concurrency, cfg.cpu)
    if adj != cfg.cf_concurrency:
        print(f"  cf-scanner 并发: {cfg.cf_concurrency} -> {adj} (系统负载)")
        cfg.cf_concurrency = adj

    proc = subprocess.Popen(
        [str(CF_SCANNER), "-i", str(input_file), "-o", str(hits_file),
         "-c", str(cfg.cf_concurrency)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    pat = re.compile(r"(\d+\.?\d*)%")
    last_pct = -1
    last_extra = ""
    t0 = time.time()

    for line in proc.stdout:
        m = pat.search(line)
        if m:
            pct = min(float(m.group(1)), 100)
            if abs(pct - last_pct) >= 0.5:
                elapsed = time.time() - t0
                eta = (elapsed / pct * (100 - pct)) if pct > 0 else 0
                extra = f" | ETA {int(eta // 60)}分{int(eta % 60)}秒" if pct > 0.5 else ""
                stage_label = " | CF检测"
                last_extra = extra + stage_label
                write_progress(pct, last_extra)
                last_pct = pct
    proc.wait()

    if proc.returncode != 0:
        sys.stderr.write("\n"); sys.stderr.flush()
        raise subprocess.CalledProcessError(proc.returncode, proc.args)

    write_progress_done(last_extra)

    with open(hits_file) as f:
        hits = sum(1 for _ in f)

    adj_api = adjust_concurrency(cfg.api_concurrency, cfg.cpu)
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
    msg = f"  CF可用IP数量: {hits}  |  精筛通过率: {rate_pct:.0f}% ({passed}/{hits})"
    print(c(msg, C.W))
    print(c(f"  本步耗时: {int(time.time() - step_start)}秒", C.GY))
    return hits, passed


def step_deep_scan(cfg: ScannerConfig) -> int:
    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"
    if not hits_file.exists() or hits_file.stat().st_size == 0:
        print("  无 CF IP，跳过")
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

    port_count_val = port_count(WIDE_PORTS)
    print(f"\n  深度扫描: {len(ips)} 个 IP × {port_count_val} 端口 ({cfg.masscan_rate} pps)")
    eta_s = max(1, port_count_val * len(ips) // max(1, cfg.masscan_rate))
    print(f"  预计: {eta_s // 60}m {eta_s % 60}s ({', '.join(sorted(ips)[:5])}{'...' if len(ips) > 5 else ''})")

    ip_file = BASE / "deep_ips.txt"
    ip_file.write_text("\n".join(sorted(ips)) + "\n")

    xml_file = BASE / "deep_result.xml"
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
    batches = split_port_batches(WIDE_PORTS)
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

        deep_masscan_start = time.time()
        def _deep_progress(pct, _extra):
            elapsed = time.time() - deep_masscan_start
            eta = (elapsed / pct * (100 - pct)) if pct > 1 else 0
            eta_s = f" | ETA {int(eta // 60)}分{int(eta % 60)}秒" if pct > 1 else ""
            write_progress(pct, prefix + eta_s)

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        stderr_lines = read_masscan_stderr(proc, prefix, _deep_progress)
        proc.wait()

        if proc.returncode != 0:
            sys.stderr.write("\n"); sys.stderr.flush()
            err = "".join(stderr_lines).lower()
            if "permission denied" in err or "password is required" in err:
                print(c("  [FAIL] masscan 权限不足", C.LR))
            raise subprocess.CalledProcessError(proc.returncode, cmd)

        write_progress_done(prefix)

        if os.geteuid() != 0:
            subprocess.run(["sudo", "-n", "chown",
                            f"{os.getuid()}:{os.getgid()}", str(batch_xml)],
                           stdin=subprocess.DEVNULL, check=False)

        batch_before = len(all_open)
        all_open.extend(parse_masscan_xml(batch_xml))

        new_in_batch = len(all_open) - batch_before
        print(f"  {prefix}端口开放: +{new_in_batch} (累计 {len(all_open)})", flush=True)

        if new_in_batch == 0 and bi + 1 < len(batches) and sys.stdin.isatty():
            try:
                ch = input(c("   > 本批无新端口, 继续下批? (y/n, 回车继续): ", C.Y)).strip().lower()
            except (EOFError, KeyboardInterrupt):
                ch = ""
            if ch == "n":
                print(c(f"  [已跳过] 用户终止剩余 {len(batches) - bi - 1} 批次", C.G))
                break

        if len(batches) > 1:
            try:
                batch_xml.unlink()
            except OSError:
                pass

    result_file = BASE / "masscan_result.txt"
    result_file.write_text("\n".join(all_open) + "\n")
    print(c(f"  深度 Masscan 完成: {len(all_open)} 开放端口", C.CY))

    if not all_open:
        print("  无新增开放端口")
        return len(saved)

    print(c("  CF 检测中...", C.CY))
    hits, _passed = _pipeline(cfg)

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
    step_start = time.time()
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无 IP，跳过")
        return

    adj = adjust_concurrency(cfg.api_concurrency, cfg.cpu)
    if adj != cfg.api_concurrency:
        print(f"  测速并发: {cfg.api_concurrency} -> {adj} (系统负载)")
        cfg.api_concurrency = adj

    with open(verified_file) as f:
        lines = [l.strip() for l in f
                 if l.strip() and not l.startswith("#")]
    if len(lines) <= 1:
        print("  无 IP，跳过")
        return

    header, entries = lines[0], lines[1:]
    total = len(entries)
    print(f"  IP 数: {total}")

    results: list[tuple[str, int]] = []
    with ThreadPoolExecutor(max_workers=min(total, cfg.api_concurrency)) as ex:
        fmap = {}
        for idx, entry in enumerate(entries):
            parts = entry.split(",")
            if len(parts) < 9:
                continue
            fmap[ex.submit(test_one, parts)] = idx

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
    write_progress_done(f" | 测速完成: {total} 个 IP")
    elapsed = int(time.time() - step_start)
    m, s = divmod(elapsed, 60)
    print(c(f"  本步耗时: {m}分{s}秒" if m else f"  本步耗时: {s}秒", C.GY))


def _smart_wrapper(cfg: ScannerConfig) -> list[str]:
    v4_file = BASE / "cidrs_v4.txt"
    if not v4_file.exists():
        return []

    v4_cidrs = [l.strip() for l in open(v4_file) if l.strip() and ":" not in l]
    if not v4_cidrs:
        return []

    alive = smart_subnet_probe(v4_cidrs)
    v4_file.write_text("\n".join(alive) + "\n")
    return alive


def _parse_custom_port(args: list[str]) -> Optional[str]:
    for i, a in enumerate(args):
        if a == "-p" and i + 1 < len(args):
            ports = parse_ports(args[i + 1])
            if ports:
                print(f"  自定义端口: {ports}")
                return ports
            break
    return None


def _print_visualization(csv_path: Path) -> None:
    entries: list[str] = []
    with open(csv_path) as f:
        next(f)
        for line in f:
            line = line.strip()
            if line.count(",") >= 8:
                entries.append(line)
    if not entries:
        return

    buckets = {"  0-50": 0, " 50-100": 0, "100-200": 0, "  200+": 0}
    total = 0
    latencies: list[float] = []
    for e in entries:
        parts = e.split(",")
        try:
            lat = float(parts[6])
        except (ValueError, IndexError):
            continue
        total += 1
        latencies.append(lat)
        if lat < 50:
            buckets["  0-50"] += 1
        elif lat < 100:
            buckets[" 50-100"] += 1
        elif lat < 200:
            buckets["100-200"] += 1
        else:
            buckets["  200+"] += 1

    if total > 0:
        avg_all = sum(latencies) / total
        print(c(f"\n  延迟分布 (总数 {total}, 平均 {avg_all:.0f}ms):", C.LC))
        max_count = max(buckets.values()) or 1
        max_width = 30
        for label, count in buckets.items():
            bar_len = int(count / max_count * max_width)
            bar = "\u2588" * bar_len
            print(f"  {label}ms: {bar} {count}")

    geo: dict[str, list[float]] = {}
    for e in entries:
        parts = e.split(",")
        country = parts[4] if len(parts) > 4 else ""
        if not country:
            country = "Unknown"
        try:
            lat = float(parts[6])
        except (ValueError, IndexError):
            lat = 0
        geo.setdefault(country, []).append(lat)

    if geo:
        print(c("\n  地理聚合 (按国家/地区):", C.LC))
        for country, lats in sorted(geo.items(), key=lambda x: -len(x[1])):
            avg_lat = sum(lats) / len(lats)
            print(f"  {country}: {len(lats)} 节点, 平均延迟 {avg_lat:.0f}ms")


def _resolve_port_mode(a, cfg, sys_args: list[str]) -> bool:
    probe_added = False
    port_mode_name = "默认端口"

    if a.ports:
        cfg.scan_ports = parse_ports(a.ports)
        if not cfg.scan_ports:
            print(c(f"  [FAIL] 无效端口: {a.ports}", C.LR))
            sys.exit(1)
        port_mode_name = "自定义端口"
        print(f"  自定义端口: {cfg.scan_ports}")
    elif a.wide:
        cfg.scan_ports = WIDE_PORTS
        if not a.rate:
            cfg.masscan_rate = max(500, cfg.masscan_rate // 2)
        port_mode_name = "宽端口池"
        print(f"  宽端口模式: {port_count(cfg.scan_ports)} 端口 ({cfg.masscan_rate} pps)")
    elif a.random:
        cfg.scan_ports = random_ports()
        port_mode_name = "随机5个端口"
        print(f"  随机端口: {cfg.scan_ports}")
    elif not sys_args and not a.targets:
        print(f"  默认端口：{cfg.scan_ports}")
        print(f"  宽端口池：{WIDE_PORTS}")
        try:
            inp = input(c("  端口模式（回车=默认端口 | w=宽端口 | r=随机5个端口 | 直接输入=自定义端口）：", C.Y)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            inp = ""
        if inp == "w":
            cfg.scan_ports = WIDE_PORTS
            cfg.masscan_rate = max(500, cfg.masscan_rate // 2)
            port_mode_name = "宽端口池"
            print(f"  宽端口模式: {port_count(cfg.scan_ports)} 端口 ({cfg.masscan_rate} pps)")
        elif inp == "r":
            cfg.scan_ports = random_ports()
            port_mode_name = "随机5个端口"
            print(f"  随机端口: {cfg.scan_ports}")
        elif inp:
            parsed = parse_ports(inp)
            if parsed:
                cfg.scan_ports = parsed
                port_mode_name = "自定义端口"
                print(f"  扫描端口: {cfg.scan_ports}")
        else:
            try:
                probe = input(c("  是否追加随机端口探活：请输入探测数量（取值 1-100），回车则跳过该步骤：", C.Y)).strip()
            except (EOFError, KeyboardInterrupt):
                probe = ""
            if probe.isdigit():
                n = max(1, min(int(probe), 100))
                extra = random_probe_ports(n, cfg.scan_ports)
                if extra:
                    cfg.scan_ports = cfg.scan_ports + "," + extra
                    probe_added = True
                    print(f"  默认端口 +{n} 端口 -> 共 {port_count(cfg.scan_ports)} 端口 ({extra})")
    else:
        cp = _parse_custom_port(sys_args)
        if cp:
            cfg.scan_ports = cp
            port_mode_name = "自定义端口"

    if a.probe_ports:
        n = max(1, min(a.probe_ports, 100))
        extra = random_probe_ports(n, cfg.scan_ports)
        if extra:
            cfg.scan_ports = cfg.scan_ports + "," + extra
            probe_added = True
            print(c(f"  随机探口: +{n} 个端口 -> 共 {port_count(cfg.scan_ports)} 端口 ({extra})", C.CY))
        else:
            print(c(f"  随机探口: 无新端口可追加", C.Y))

    port_desc = f"默认端口+随机端口组合模式 ({port_count(cfg.scan_ports)} 个)" if probe_added else f"{port_mode_name} ({port_count(cfg.scan_ports)} 个)"
    print(c(f"  [已确认] 端口模式: {port_desc}", C.LG))
    return probe_added


def _interactive_choices(a, v4_cidrs: list[str], asns: list[str]) -> tuple[bool, bool]:
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
    if not a.incremental and not sys.argv[1:]:
        incr_tag_hint = _incr_tag(asns, v4_cidrs)
        has_state = (INCR_DIR / f"{incr_tag_hint}_cidrs.txt").exists()
        if has_state:
            try:
                ch = input(c("  是否开启增量扫描模式？仅对新增CIDR网段执行探测 (y/n, 回车跳过): ", C.Y)).strip().lower()
                a.incremental = ch == "y"
                if a.incremental:
                    print(c("  [已确认] 增量扫描 (对比上次CIDR，仅扫新增)", C.G))
                else:
                    print(c("  [已跳过] 增量扫描 (回车自动选择)", C.G))
            except (EOFError, KeyboardInterrupt):
                pass
    return do_speed, do_deep


def _build_steps(a, cfg, asns: list[str], v4_cidrs: list[str],
                 do_speed: bool, do_deep: bool) -> list[tuple[str, Callable[[], object]]]:
    steps: list[tuple[str, Callable[[], object]]] = [
        ("Step 1  通过 ASN 提取 CIDR 网段", lambda: step_fetch_prefixes(cfg, asns, v4_cidrs)),
    ]
    step_num = 1
    if a.smart:
        step_num += 1
        cfg.smart_mode = True
        steps.append((f"Step {step_num}  子网分级探活", lambda: _smart_wrapper(cfg)))
    if a.skip_masscan:
        print(c("  (跳过 Masscan, 使用已有结果)", C.W))
    else:
        step_num += 1
        steps.append((f"Step {step_num}  基于 Masscan 执行端口扫描任务", lambda: step_masscan(cfg)))
    step_num += 1
    steps.append((f"Step {step_num}  Cloudflare IP 检测与 API 精准过滤", lambda: _pipeline(cfg)))
    step_num += 1
    steps.append((f"Step {step_num}  IP 深度挖掘探测", lambda: step_deep_mine(cfg)))
    if do_deep:
        step_num += 1
        steps.append((f"Step {step_num}  深度宽端口扫描", lambda: step_deep_scan(cfg)))
    if do_speed:
        step_num += 1
        steps.append((f"Step {step_num}  网络延迟/带宽速率检测", lambda: step_speed_test(cfg)))
    return steps


def _cleanup_temp_files(a) -> None:
    for stale in ("cidrs.txt", "cidrs_v4.txt",
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


def _generate_csv(verified_file: Path, asns: list[str], a,
                  incr_tag: str, incr_saved_results: list[str],
                  incr_full_cidrs: list[str], v4_list: list[str],
                  passed_count: int) -> tuple[Optional[Path], int]:
    csv_path = None
    if not (verified_file.exists() and verified_file.stat().st_size > 0):
        return csv_path, passed_count

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
            parts = p.split(",")
            ip = parts[0]
            port = parts[1]
            colo = parts[3]
            country = parts[4]
            city = parts[5]
            latency = parts[6]
            asn_val = parts[8]
            proto = "IPv6" if ":" in ip else "IPv4"
            try:
                gi = geo_lookup(ip)
                if gi:
                    if gi.get("country") and not country:
                        country = gi["country"]
                    if gi.get("city"):
                        city = gi["city"]
            except Exception:
                pass
            spd = parts[7] if len(parts) > 7 else ""
            f.write(f"{ip},{port},TRUE,{colo},{country},{city},{latency},{spd},{asn_val},{proto}\n")

    print(c(f"  结果: {len(parsed)} 条 -> {csv_path.name}", C.G))

    if a.incremental and incr_tag and incr_saved_results:
        merged: dict[str, str] = {}
        for line in incr_saved_results:
            if not line or line.startswith("#") or line.startswith("IP"):
                continue
            parts = line.split(",", 2)
            key = f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else line
            merged[key] = line
        new_count = 0
        for line in parsed:
            parts = line.split(",", 2)
            key = f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else line
            if key not in merged:
                new_count += 1
            merged[key] = line
        merged_lines = sorted(merged.values())
        with open(csv_path, "w") as f:
            f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN,协议\n")
            for p in merged_lines:
                parts = p.split(",")
                ip = parts[0]
                port = parts[1]
                colo = parts[3] if len(parts) > 3 else ""
                country = parts[4] if len(parts) > 4 else ""
                city = parts[5] if len(parts) > 5 else ""
                latency = parts[6] if len(parts) > 6 else ""
                asn_v = parts[8] if len(parts) > 8 else ""
                proto = "IPv4"
                spd = parts[7] if len(parts) > 7 else ""
                f.write(f"{ip},{port},TRUE,{colo},{country},{city},{latency},{spd},{asn_v},{proto}\n")
        print(c(f"  合并: {len(incr_saved_results) - 1} 历史 + {new_count} 新增 -> {len(merged)} 条", C.CY))
        passed_count = len(merged)
        save_incremental_state(incr_tag, incr_full_cidrs or v4_list, merged_lines)
    elif a.incremental and incr_tag:
        if incr_full_cidrs:
            save_incremental_state(incr_tag, incr_full_cidrs, parsed)
        else:
            save_incremental_state(incr_tag, v4_list, parsed)
    return csv_path, passed_count


CFST_DIR = Path.home() / ".config" / "ip-tidy"
CFST_BIN = CFST_DIR / "cfst"
CFST_RESULT_LIMIT = 15


def _ensure_cfst_binary() -> Path:
    if CFST_BIN.exists() and os.access(str(CFST_BIN), os.X_OK):
        return CFST_BIN

    import platform as _platform
    _arch = _platform.machine()
    if _arch == "x86_64":
        _cfst_arch = "amd64"
    elif _arch in ("aarch64", "arm64"):
        _cfst_arch = "arm64"
    else:
        _cfst_arch = "amd64"

    _url = f"https://github.com/XIU2/CloudflareSpeedTest/releases/latest/download/cfst_linux_{_cfst_arch}.tar.gz"
    print(c(f"  [CFST] 下载 cfst 二进制... ({_url})", C.W))

    CFST_DIR.mkdir(parents=True, exist_ok=True)
    import tempfile, tarfile, urllib.request as _req
    _tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as _tmp:
            _tmp_path = _tmp.name
        _req.urlretrieve(_url, _tmp_path)
        with tarfile.open(_tmp_path, "r:gz") as _tar:
            _tar.extract("cfst", str(CFST_DIR))
        os.chmod(str(CFST_BIN), 0o755)
        print(c(f"  [CFST] 已安装到 {CFST_BIN}", C.G))
        return CFST_BIN
    except Exception:
        print(c(f"  [FAIL] cfst 下载失败，请手动安装到 {CFST_BIN}", C.LR))
        raise
    finally:
        if _tmp_path and os.path.exists(_tmp_path):
            os.unlink(_tmp_path)


def _parse_cfst_buffer(_buffer: bytes, _all_lines: list[str],
                        _phase: str, _current: int,
                        _delay_total: int, _download_total: int):
    while b"\r" in _buffer or b"\n" in _buffer:
        _idx_r = _buffer.find(b"\r")
        _idx_n = _buffer.find(b"\n")
        if _idx_r == -1:
            _idx_r = len(_buffer)
        if _idx_n == -1:
            _idx_n = len(_buffer)
        _split_idx = min(_idx_r, _idx_n)

        _line_bytes = _buffer[:_split_idx]
        _buffer = _buffer[_split_idx + 1:]

        _line = _line_bytes.decode("utf-8", errors="replace").strip()
        if not _line:
            continue
        _all_lines.append(_line)

        if "下载测速" in _line:
            _phase = "download"
            _current = 0

        _m = re.search(r"(\d+)\s*/\s*(\d+)", _line)
        if _m:
            _current = int(_m.group(1))
            _detected = int(_m.group(2))
            if _phase == "delay":
                _delay_total = _detected
            else:
                _download_total = _detected

    return _buffer, _phase, _current, _delay_total, _download_total


def _compute_cfst_progress(_phase: str, _current: int,
                           _delay_total: int, _download_total: int) -> float:
    if _phase == "delay":
        return min(_current / max(_delay_total, 1) * 20, 20)
    else:
        return 20 + min(_current / max(_download_total, 1) * 80, 80)


def _run_cfst_speedtest(verified_file: Path, a, tag: str) -> None:
    if not (verified_file.exists() and verified_file.stat().st_size > 0):
        return

    ips: set[str] = set()
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("IP"):
                continue
            parts = line.split(",")
            if parts:
                ips.add(parts[0])

    if not ips:
        return

    if not a.cfst:
        try:
            ch = input(c(f"  是否进行 CloudflareSpeedTest 测速优选？({len(ips)} 个IP, y/n, 回车跳过): ", C.Y)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ch = ""
        if ch != "y":
            print(c("  [已跳过] CloudflareSpeedTest 测速", C.LG))
            return
    else:
        print(c(f"  [CFST] CloudflareSpeedTest 测速 ({len(ips)} 个IP)", C.G))

    try:
        cfst_bin = _ensure_cfst_binary()
    except Exception:
        return

    ip_file = BASE / ".cfst_ips.txt"
    ip_file.write_text("\n".join(sorted(ips)) + "\n")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = BASE / f"cfst_{tag}_{ts}.csv"

    print(c(f"  [CFST] 开始测速，目标取前 {CFST_RESULT_LIMIT} 条最优 IP...", C.W))

    import fcntl as _fcntl

    proc = subprocess.Popen(
        [str(cfst_bin), "-f", str(ip_file),
         "-dn", str(CFST_RESULT_LIMIT), "-p", str(CFST_RESULT_LIMIT),
         "-o", str(result_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        cwd=str(BASE)
    )

    fd = proc.stdout.fileno()
    _fl = _fcntl.fcntl(fd, _fcntl.F_GETFL)
    _fcntl.fcntl(fd, _fcntl.F_SETFL, _fl | os.O_NONBLOCK)

    _buffer = b""
    _all_lines: list[str] = []
    _start_time = time.time()
    _phase = "delay"
    _current = 0
    _delay_total = 1
    _download_total = CFST_RESULT_LIMIT

    while True:
        if proc.poll() is not None:
            try:
                while True:
                    _chunk = os.read(fd, 65536)
                    if not _chunk:
                        break
                    _buffer += _chunk
            except (BlockingIOError, OSError):
                pass
            break

        try:
            _chunk = os.read(fd, 65536)
            if _chunk:
                _buffer += _chunk
        except (BlockingIOError, OSError):
            pass

        _buffer, _phase, _current, _delay_total, _download_total = _parse_cfst_buffer(
            _buffer, _all_lines, _phase, _current, _delay_total, _download_total
        )

        _elapsed = time.time() - _start_time
        _pct = _compute_cfst_progress(_phase, _current, _delay_total, _download_total)
        if _pct > 1:
            _eta = _elapsed / _pct * (100 - _pct)
            _eta_s = f" | ETA {int(_eta // 60)}分{int(_eta % 60)}秒"
        else:
            _eta_s = ""
        _phase_label = "延迟测速" if _phase == "delay" else "下载测速"
        write_progress(_pct, f" | CFST {_phase_label}{_eta_s}")
        time.sleep(0.15)

    _buffer, _phase, _current, _delay_total, _download_total = _parse_cfst_buffer(
        _buffer, _all_lines, _phase, _current, _delay_total, _download_total
    )

    proc.wait()
    write_progress_done(" | CFST测速完成")

    ip_file.unlink(missing_ok=True)

    output = "\n".join(_all_lines)

    if proc.returncode != 0:
        print()
        print(c(f"  [FAIL] cfst 返回码 {proc.returncode}", C.LR))
        return

    result_lines: list[str] = []
    in_table = False
    for line in output.split("\n"):
        stripped = line.strip()
        if "IP 地址" in stripped and "已发送" in stripped:
            in_table = True
            continue
        if in_table and re.match(r'^\d{1,3}\.', stripped):
            result_lines.append(stripped)
        elif in_table and stripped == "":
            in_table = False

    if not result_lines:
        print(c("  [CFST] 未获得有效测速结果", C.LY))
        return

    print_sep("─", C.B)
    print(c(f"  CloudflareSpeedTest 最优 IP（按下载速度排序，共 {len(result_lines)} 条）", C.LC))
    print(c(f"  {'IP 地址':<20} {'已发送':<8} {'已接收':<8} {'丢包率':<8} {'平均延迟':<10} {'下载速度(MB/s)':<16} 地区码", C.W))
    for i, rl in enumerate(result_lines):
        color = C.G if i == 0 else (C.GY if i < 3 else C.W)
        print(c(f"  {rl}", color))

    if result_file.exists() and result_file.stat().st_size > 0:
        print()
        print(c(f"  完整结果已保存到: {result_file.name}", C.G))
    else:
        print(c("  [CFST] 结果文件为空", C.LY))

    return result_file


def main() -> None:
    main_start = time.time()
    parser = argparse.ArgumentParser(
        prog="qian",
        description=f"IP-Tidy {VERSION} -- CIDR/ASN -> masscan -> CF IP 检测",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  qian AS209242\n"
               "  qian AS209242 -w -s\n"
               "  qian 1.2.3.0/24,5.6.7.0/24\n"
               "  qian AS209242 -w -r 4000")
    parser.add_argument("targets", nargs="*", help="ASN 编号 或 CIDR (可多个，空格或逗号分隔)")
    parser.add_argument("-p", "--ports", metavar="PORTS",
                        help="自定义扫描端口 (如 443 或 80,443 或 8000-9000)")
    parser.add_argument("-s", "--speed", action="store_true",
                        help="扫描完成后自动测速")
    parser.add_argument("-w", "--wide", action="store_true",
                        help="宽端口模式")
    parser.add_argument("-R", "--random", action="store_true",
                        help="随机 5 端口探测 (全端口范围)")
    parser.add_argument("-P", "--probe-ports", metavar="N", type=int,
                        help="在常规端口基础上追加 N 个随机端口探活 (全端口范围，排除已选)")
    parser.add_argument("-r", "--rate", metavar="PPS", type=int,
                        help="Masscan 发包速率 (默认自动探测)")
    parser.add_argument("--skip-masscan", action="store_true",
                        help="跳过 Masscan，使用已有 masscan_result.txt")
    parser.add_argument("-d", "--deep", action="store_true",
                        help="深度扫描: 对 CF 命中的 IP 追加 55546 个端口扫描")
    parser.add_argument("-v", "--version", action="version",
                        version=f"IP-Tidy {VERSION}")
    parser.add_argument("-g", "--geo-update", action="store_true",
                        help="下载/更新 MaxMind GeoLite2 离线数据库")
    parser.add_argument("--smart", action="store_true",
                        help="智能子网分级: 大 CIDR 拆 /24 抽样探活, 仅扫活跃子网")
    parser.add_argument("-i", "--incremental", action="store_true",
                        help="增量扫描: 仅扫描上次保存后新增的 CIDR 段")
    parser.add_argument("-c", "--cfst", action="store_true",
                        help="自动运行 CloudflareSpeedTest 对结果 IP 测速优选")
    a = parser.parse_args()

    if a.geo_update:
        print_banner()
        print("  [GeoIP] 下载 MaxMind GeoLite2 离线数据库")
        print()
        if geo_update_interactive():
            print()
            print(f"  [OK] 数据库已保存到 {Path.home() / '.config' / 'ip-tidy'}")
        sys.exit(0)

    print_banner()
    cfg = init_runtime()

    asns, v4_cidrs = parse_targets(sys.argv[1:] if not a.targets else a.targets)

    if not asns and not v4_cidrs:
        print("用法: ip-tidy AS209242 [...] 或 ip-tidy 1.2.3.0/24 [...]")
        sys.exit(1)

    print_hardware_info(cfg.cpu, cfg.ram_mb, cfg.masscan_rate,
                        cfg.cf_concurrency, cfg.api_concurrency,
                        cfg.global_city, cfg.global_isp)

    targets_desc = []
    if asns:
        targets_desc.append(", ".join(f"AS{x}" for x in asns))
    if v4_cidrs:
        targets_desc.append(
            f"IPv4 ({len(v4_cidrs)} 条) {', '.join(v4_cidrs[:3])}"
            f"{'...' if len(v4_cidrs) > 3 else ''}")
    print(c(f"  [验证通过] 目标：{'  '.join(targets_desc)}", C.G))

    if a.rate:
        cfg.masscan_rate = max(100, a.rate)
        print(f"  发包速率: {cfg.masscan_rate} pps (手动)")

    _resolve_port_mode(a, cfg, sys.argv[1:])
    do_speed, do_deep = _interactive_choices(a, v4_cidrs, asns)
    steps = _build_steps(a, cfg, asns, v4_cidrs, do_speed, do_deep)
    _cleanup_temp_files(a)

    cidr_count_val = 0
    v4_cidr_count = 0
    total_open = 0
    cf_nodes = 0
    passed_count = 0

    incr_tag = ""
    incr_saved_results: list[str] = []
    incr_full_cidrs: list[str] = []
    incr_skip = False
    v4_list: list[str] = list(v4_cidrs)

    for label, fn in steps:
        if incr_skip:
            (BASE / "verified.txt").write_text("\n".join(incr_saved_results) + "\n")
            break
        print_step(label)
        try:
            result = fn()
            if label.startswith("Step 1"):
                v4_list = result
                cidr_count_val = len(v4_list)
                v4_cidr_count = len(v4_list)

                if a.incremental:
                    incr_tag = _incr_tag(asns, v4_cidrs)
                    saved_cidrs, incr_saved_results = load_incremental_state(incr_tag)
                    new_cidrs, removed = compute_cidr_diff(v4_list, saved_cidrs)
                    print(c(f"  [增量] 历史 {len(saved_cidrs)} 段, 新增 {len(new_cidrs)} 段, 移除 {len(removed)} 段", C.CY))
                    if not new_cidrs and incr_saved_results:
                        print(c("  无新增 CIDR，跳过扫描，使用上次结果", C.G))
                        (BASE / "cidrs_v4.txt").write_text("")
                        incr_skip = True
                    elif new_cidrs:
                        incr_full_cidrs = list(v4_list)
                        (BASE / "cidrs_v4.txt").write_text("\n".join(new_cidrs) + "\n")
                        cidr_count_val = len(new_cidrs)
                        print(c(f"  仅扫描新增 {len(new_cidrs)} 段 CIDR", C.CY))
                    else:
                        incr_full_cidrs = list(v4_list)
            elif "子网分级" in label:
                v4_list = result
                cidr_count_val = len(v4_list)
                v4_cidr_count = len(v4_list)
                print(c(f"  存活子网: {len(v4_list)} 段 (v4)", C.G))
            elif label.startswith("Step 2") or ("Masscan" in label and "端口" in label):
                total_open = result
            elif label.startswith("Step 3") or ("Cloudflare" in label):
                cf_nodes, passed_count = result
            elif "深度挖掘" in label:
                added = result
                if added > 0:
                    passed_count += added
        except KeyboardInterrupt:
            print(c("\n  [中断] 用户取消", C.LR))
            sys.exit(130)
        except Exception as e:
            print(c(f"  [FAIL] {e}", C.LR))
            sys.exit(1)

    verified_file = BASE / "verified.txt"
    csv_path, passed_count = _generate_csv(verified_file, asns, a,
                                            incr_tag, incr_saved_results,
                                            incr_full_cidrs, v4_list, passed_count)

    cfst_tag = "_".join(asns) if asns else "cidr"
    _run_cfst_speedtest(verified_file, a, cfst_tag)

    print_result_header(
        len(asns), cidr_count_val, total_open, cf_nodes, passed_count, v4_cidr_count,
    )
    print_sep("-", C.W)
    print_total_time(time.time() - main_start)

    if csv_path and csv_path.exists():
        _print_visualization(csv_path)
        _serve_download(csv_path)


def step_deep_mine(cfg: ScannerConfig) -> int:
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        return 0

    existing: set[str] = set()
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("IP"):
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                existing.add(f"{parts[0]}:{parts[1]}")

    if not existing:
        return 0

    print(f"  [当前结果] 通过 {len(existing)} 个 IP:端口")
    try:
        ch = input(c("  是否启用深度挖掘？(提取 IP -> /16 CIDR 二次扫描, y/n, 回车跳过): ", C.Y)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        ch = ""
    if ch != "y":
        print(c("  [已跳过] 深度挖掘", C.LG))
        return 0

    print(c("  [已确认] 深度挖掘", C.LG))

    prefix = 16
    try:
        prefix_inp = input(c("  扩展大小 (/16, /20, /21, /22, /23, /24, 回车=/16): ", C.Y)).strip()
        if prefix_inp:
            p = int(prefix_inp.lstrip("/"))
            if p in (16, 20, 21, 22, 23, 24):
                prefix = p
    except (EOFError, ValueError):
        pass
    print(f"  扩展为 /{prefix} CIDR")

    cidr_set: set[str] = set()
    for ip_port in existing:
        try:
            ip = ip_port.split(":")[0]
            net = ipaddress.ip_network(ip, strict=False)
            cidr_set.add(str(net.supernet(new_prefix=prefix)))
        except ValueError:
            pass

    if not cidr_set:
        return 0

    cidrs = sorted(cidr_set)
    total_possible = sum(ipaddress.ip_network(c).num_addresses for c in cidrs)

    print(f"  深度挖掘: {len(existing)}条IP:端口 -> {len(cidrs)}段 /{prefix} CIDR（{total_possible:,}条IP）")

    ensure_cf_scanner()

    cidr_file = BASE / ".deep_mine_cidrs.txt"
    cidr_file.write_text("\n".join(cidrs) + "\n")

    step_start = time.time()

    def _cb(typ, data):
        if typ == "masscan_progress":
            cur = data.get("current", 0)
            total = data.get("total", 1)
            pct = min(cur / total * 100, 100)
            elapsed = time.time() - step_start
            eta = (elapsed / pct * (100 - pct)) if pct > 1 else 0
            eta_s = f" | ETA {int(eta // 60)}分{int(eta % 60)}秒" if pct > 1 else ""
            write_progress(pct, eta_s)
        elif typ == "scan_progress":
            cur = data.get("current", 0)
            total = data.get("total", 1)
            pct = min(cur / total * 100, 100)
            elapsed = time.time() - step_start
            eta = (elapsed / pct * (100 - pct)) if pct > 1 else 0
            eta_s = f" | ETA {int(eta // 60)}分{int(eta % 60)}秒" if pct > 1 else ""
            write_progress(pct, f" | CF检测{eta_s}")
        elif typ == "log":
            msg = str(data)
            if msg.startswith("API 验证") or "Masscan 批次" in msg:
                return
            sys.stderr.write("\n\r")
            sys.stderr.flush()
            print(f"  {msg}")
        elif typ == "error":
            print(c(f"  [FAIL] {data}", C.LR))

    masscan_hits: list[str] = []

    if os.path.exists("/usr/local/bin/masscan") or os.system("which masscan >/dev/null 2>&1") == 0:
        masscan_rate = probe_masscan_rate(quiet=True)
        print(c("  ─" * 30, C.B))
        print(c("  基于 Masscan 执行端口扫描任务", C.LC))
        print(c("  ─" * 30, C.B))
        ms_start = time.time()
        masscan_hits = run_masscan(cidr_file, cfg.scan_ports, masscan_rate, progress_callback=_cb)
        ms_elapsed = int(time.time() - ms_start)
        ms_m, ms_s = divmod(ms_elapsed, 60)
        print(c(f"  本步耗时: {ms_m}分{ms_s}秒" if ms_m else f"  本步耗时: {ms_s}秒", C.GY))
    else:
        print("  Masscan 不可用，直接从 CIDR 扩展 IP 进行 cf-scanner 扫描...")
        port_list = [p.strip() for p in cfg.scan_ports.split(",") if p.strip().isdigit()]
        ips = expand_cidrs(cidrs, max_ips=5000)
        for ip in ips:
            for p in port_list[:3]:
                masscan_hits.append(f"{ip}:{p}")

    if not masscan_hits:
        write_progress_done(" | 无开放端口")
        print(c("  深度挖掘: 未发现开放端口", C.LY))
        cidr_file.unlink(missing_ok=True)
        return 0

    cf_in = BASE / ".deep_mine_cf_in.txt"
    cf_out = BASE / ".deep_mine_cf_out.txt"
    cf_in.write_text("\n".join(masscan_hits) + "\n")

    adj_cf = adjust_concurrency(cfg.cf_concurrency, cfg.cpu)
    print(c("  ─" * 30, C.B))
    print(c("  Cloudflare IP 检测与 API 精准过滤", C.LC))
    print(c("  ─" * 30, C.B))
    hit_count = run_cf_scanner(cf_in, cf_out, adj_cf, progress_callback=_cb)

    if hit_count == 0:
        write_progress_done(" | CF 未命中")
        print(c("  深度挖掘: CF 未命中", C.LY))
        for f in (cidr_file, cf_in, cf_out):
            try: f.unlink()
            except OSError: pass
        return 0

    write_progress_done(" | ETA 0分0秒 | CF检测")

    hits: list[str] = []
    with open(cf_out) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                line = f"{line}:{cfg.scan_ports.split(',')[0].strip()}"
            hits.append(line)

    adj_api = adjust_concurrency(cfg.api_concurrency, cfg.cpu)
    new_results = verify_batch(hits, concurrency=adj_api, progress_callback=_cb)
    if new_results:
        enrich_geoip(new_results)

    real_new = [r for r in new_results if f"{r['ip']}:{r.get('port','443')}" not in existing]

    if real_new:
        with open(verified_file, "a") as f:
            for r in real_new:
                f.write(f"{r['ip']},{r.get('port','443')},TRUE,{r.get('colo','')},"
                        f"{r.get('country','')},{r.get('region','')},,,AS{r.get('asn','')}\n")

    for f in (cidr_file, cf_in, cf_out):
        try: f.unlink()
        except OSError: pass

    rate = len(new_results) / hit_count * 100 if hit_count else 0
    elapsed = int(time.time() - step_start)
    m, s = divmod(elapsed, 60)
    ep = f"{m}分{s}秒" if m else f"{elapsed}秒"
    done_extra = f" | 通过 {len(new_results)}/{hit_count} | {ep} | API精筛"
    write_progress_done(done_extra)
    print(c(f"  CF可用IP数量: {hit_count}  |  精筛通过率: {rate:.0f}% ({len(new_results)}/{hit_count})  |  深度挖掘: +{len(real_new)} 新 IP", C.W))
    print(c(f"  本步耗时: {m}分{s}秒" if m else f"  本步耗时: {elapsed}秒", C.GY))
    return len(real_new)


def _serve_download(file_path: Path) -> None:
    lan_ip = get_lan_ip()
    port = 8899

    if not port_is_free(port):
        print(c(f"  端口 {port} 被占用，尝试释放...", C.LY))
        if kill_port_process(port) and port_is_free(port):
            print(c(f"  已释放端口 {port}", C.LG))
        else:
            while not port_is_free(port) and port < 9900:
                port += 1
            if port >= 9900:
                print(c("  无可用端口，跳过下载服务", C.LY))
                print(c(f"  [CSV] {file_path}", C.W))
                return

    server: Optional[subprocess.Popen] = None
    try:
        print_sep("─", C.B)
        print(c("  任务执行完毕，文件下载服务已成功启动", C.LG))
        print(c(f"  http://{lan_ip}:{port}/{file_path.name}", C.LM))
        pub = get_public_ip()
        if pub not in ("127.0.0.1", lan_ip):
            print(c(f"  http://{pub}:{port}/{file_path.name}", C.LM))
        print()
        server = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(port),
             "--directory", str(BASE)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if sys.stdin.isatty():
            import time as _time
            print(c("  (请在浏览器中下载文件后按 Ctrl+C 关闭服务)", C.CY))
            try:
                while True:
                    _time.sleep(1)
            except (KeyboardInterrupt, EOFError):
                pass
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
