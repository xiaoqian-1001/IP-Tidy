"""
IP-Tidy -- ASN -> CIDR -> masscan -> CF 反代 IP 检测 -> CSV 输出
CLI 模式入口: 终端交互 + 渲染，核心逻辑由共享模块提供
"""

import sys
import os
import re
import time
import json
import random
import socket
import ipaddress
import threading
import argparse
import subprocess
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
from lib.scanner_utils import (
    find_iface, probe_masscan_rate, detect_hardware, tcp_latency, cf_download, test_one,
    read_masscan_stderr,
    read_default_ports, parse_targets, expand_cidrs, port_count,
    split_port_batches, adjust_concurrency, random_ports,
    WIDE_PORTS, cidr_count,
    CF_SCANNER, VERIFY_PY, API_URL, _MASSCAN_BATCH,
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


def main() -> None:
    main_start = time.time()
    parser = argparse.ArgumentParser(
        prog="xiaoqian",
        description=f"IP-Tidy {VERSION} -- CIDR/ASN -> masscan -> CF IP 检测",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  ip-tidy AS209242\n"
               "  ip-tidy AS209242 -w -s\n"
               "  ip-tidy 1.2.3.0/24,5.6.7.0/24\n"
               "  ip-tidy AS209242 -w -r 4000")
    parser.add_argument("targets", nargs="*", help="ASN 编号 或 CIDR (可多个，空格或逗号分隔)")
    parser.add_argument("-p", "--ports", metavar="PORTS",
                        help="自定义扫描端口 (如 443 或 80,443 或 8000-9000)")
    parser.add_argument("-s", "--speed", action="store_true",
                        help="扫描完成后自动测速")
    parser.add_argument("-w", "--wide", action="store_true",
                        help="宽端口模式")
    parser.add_argument("-R", "--random", action="store_true",
                        help="随机 5 端口快速探测")
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
        targets_desc.append(f"IPv4 x{len(v4_cidrs)} ({', '.join(v4_cidrs[:3])}{'...' if len(v4_cidrs) > 3 else ''})")
    print(c(f"  [已确认] 目标: {'; '.join(targets_desc)}", C.G))

    if a.rate:
        cfg.masscan_rate = max(100, a.rate)
        print(f"  发包速率: {cfg.masscan_rate} pps (手动)")

    if a.ports:
        cfg.scan_ports = parse_ports(a.ports)
        if not cfg.scan_ports:
            print(c(f"  [FAIL] 无效端口: {a.ports}", C.LR))
            sys.exit(1)
        print(f"  自定义端口: {cfg.scan_ports}")
    elif a.wide:
        cfg.scan_ports = WIDE_PORTS
        if not a.rate:
            cfg.masscan_rate = max(500, cfg.masscan_rate // 2)
        print(f"  宽端口模式: {port_count(cfg.scan_ports)} 端口 ({cfg.masscan_rate} pps)")
    elif a.random:
        cfg.scan_ports = random_ports()
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
            print(f"  宽端口模式: {port_count(cfg.scan_ports)} 端口 ({cfg.masscan_rate} pps)")
        elif inp.lower() == "r":
            cfg.scan_ports = random_ports()
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

    port_desc = f"端口 ({port_count(cfg.scan_ports)} 个)"
    print(c(f"  [已确认] 端口模式: {port_desc}", C.LG))

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

    total_steps = 3 if a.skip_masscan else 4
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
    total_steps += 1
    if a.smart:
        total_steps += 1

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

    cidr_count_val = 0
    v4_cidr_count = 0
    total_open = 0
    cf_nodes = 0
    passed_count = 0
    deep_mine_count = 0

    for label, fn in steps:
        print_step(label)
        try:
            result = fn()
            if label.startswith("Step 1"):
                v4_list = result
                cidr_count_val = len(v4_list)
                v4_cidr_count = len(v4_list)
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
                    deep_mine_count = added
        except Exception as e:
            print(c(f"  [FAIL] {e}", C.LR))
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
                parts = p.split(",")
                ip = parts[0]
                port = parts[1]
                colo = parts[3]
                country = parts[4]
                region = parts[5]
                latency = parts[6]
                asn = parts[8]
                proto = "IPv6" if ":" in ip else "IPv4"
                city = region
                isp = ""
                loc = f"{city}, {country}" if city else country
                try:
                    gi = geo_lookup(ip)
                    if gi:
                        if gi.get("country") and not country:
                            country = gi["country"]
                        if gi.get("city"):
                            city = gi["city"]
                        if gi.get("isp"):
                            isp = gi["isp"]
                except Exception:
                    pass
                spd = parts[7] if len(parts) > 7 else ""
                f.write(f"{ip},{port},TRUE,{colo},{country},{city},{latency},{spd},{asn},{proto}\n")

        print(c(f"  结果: {len(parsed)} 条 -> {csv_path.name}", C.G))

    print_result_header(
        len(asns),
        cidr_count_val,
        total_open,
        cf_nodes,
        passed_count,
        v4_cidr_count,
    )

    print_sep("-", C.W)
    print_total_time(time.time() - main_start)

    if csv_path and csv_path.exists():
        _serve_download(csv_path)


def step_deep_mine(cfg: ScannerConfig) -> int:
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        return 0

    existing_ips: set[str] = set()
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("IP"):
                continue
            ip = line.split(",")[0]
            if ":" not in ip:
                existing_ips.add(ip)

    if not existing_ips:
        return 0

    print(f"  [当前结果] 通过 {len(existing_ips)} 个 IP")
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
    for ip in existing_ips:
        try:
            net = ipaddress.ip_network(ip, strict=False)
            cidr_set.add(str(net.supernet(new_prefix=prefix)))
        except ValueError:
            pass

    if not cidr_set:
        return 0

    cidrs = sorted(cidr_set)
    total_possible = sum(ipaddress.ip_network(c).num_addresses for c in cidrs)

    print(f"  深度挖掘: {len(existing_ips)}条IP -> {len(cidrs)}段 / {prefix} CIDR（{total_possible:,}条IP）")

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

    real_new = [r for r in new_results if r["ip"] not in existing_ips]

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
        print(c("  下载服务已启动 (按回车关闭)", C.LG))
        print(c(f"  http://{lan_ip}:{port}/{file_path.name}", C.W))
        pub = get_public_ip()
        if pub not in ("127.0.0.1", lan_ip):
            print(c(f"  http://{pub}:{port}/{file_path.name}", C.W))
        print()
        server = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(port),
             "--directory", str(BASE)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if sys.stdin.isatty():
            import time as _time
            print(c("  (请在浏览器中下载文件后按回车关闭服务)", C.CY))
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
