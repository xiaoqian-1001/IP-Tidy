#!/usr/bin/env python3
"""公共工具模块 -- 进度条、网络检测、端口解析、系统信息"""

import os
import re
import sys
import time
import signal
import socket
import json
import ipaddress
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

__all__ = [
    "BAR_WIDTH", "write_progress", "write_progress_done",
    "get_public_ip", "get_lan_ip", "detect_isp",
    "parse_ports", "port_is_free", "kill_port_process",
    "c", "C", "print_banner", "print_step", "print_sep",
    "print_hardware_info", "print_result_header", "print_total_time",
]

BAR_WIDTH = 24
_FILL = "#"
_EMPTY = "-"

# ── ANSI 颜色（仅原生控制台色） ──

class C:
    R  = "\033[0m"       # reset
    G  = "\033[1;32m"    # bold green ─ success/pass
    LG = "\033[1;32m"    # bold green
    W  = "\033[1;37m"    # bold white ─ numbers/values
    Y  = "\033[1;33m"    # bold yellow ─ warning/interactive
    LY = "\033[1;33m"    # bold yellow
    LB = "\033[1;34m"    # bold blue ─ module names
    B  = "\033[34m"      # blue ─ separator
    LR = "\033[1;31m"    # bold red ─ error
    LC = "\033[1;36m"    # bold cyan ─ title/step
    CY = "\033[1;36m"    # bold cyan ─ module tags
    GY = "\033[90m"      # dark gray ─ minor info
    LM = "\033[1;35m"    # bold magenta ─ highlight/links
    NW = "\033[37m"      # normal white/gray ─ body text


def c(text: str, color: str) -> str:
    if sys.stdout.isatty():
        return f"{color}{text}{C.R}"
    return text


# ── 美化输出 ──

def print_banner() -> None:
    """打印顶部标题区块"""
    try:
        vp = Path(__file__).resolve().parent.parent / "VERSION"
        ver = vp.read_text().strip() if vp.is_file() else ""
    except OSError:
        ver = ""
    BW = 60
    line = "─" * BW
    title = "IP-Tidy"
    title_full = f"{title} {ver}" if ver else title
    tl = len(title_full)
    lp = (BW - tl) // 2
    rp = BW - lp - tl
    sub = "ASN → CIDR → Masscan → TLS → CF CSV"
    sl = len(sub)
    slp = (BW - sl) // 2
    srp = BW - slp - sl
    print()
    print(c(f"┌{line}┐", C.B))
    print(c(f"│{' ' * BW}│", C.B))
    print(c(f"│{'':>{lp}}{title_full}{'':>{rp}}│", C.LC))
    print(c(f"│{'':>{slp}}{sub}{'':>{srp}}│", C.NW))
    print(c(f"│{' ' * BW}│", C.B))
    print(c(f"└{line}┘", C.B))


def print_step(label: str) -> None:
    """打印步骤标题"""
    sep = c("─" * 60, C.B)
    title = c(f"  {label}", C.LC)
    print(sep)
    print(title)
    print(sep)


def print_sep(char: str = "─", color: str = C.B, width: int = 60) -> None:
    """打印分隔符"""
    print(c(char * width, color))


def print_hardware_info(cpu: int, mem_mb: int, rate: int,
                        cf_concurrency: int, api_concurrency: int,
                        city: str = "", org: str = "") -> None:
    """打印硬件/环境信息行 (可独立调用)"""
    mem_str = f"{mem_mb}MB" if mem_mb < 1024 else f"{mem_mb / 1024:.1f}GB"
    hw = (f"  [硬件]  CPU {cpu} 核  |  可用内存 {mem_str}  |  "
          f"Masscan {rate} pps")
    print(c(hw, C.GY))
    cfg = (f"  [并发]  CF 检测 {cf_concurrency}c  |  "
           f"API 查询 {api_concurrency}c")
    print(c(cfg, C.GY))
    if org:
        loc = city if city else ""
        print(c(f"  [环境]  {loc}  |  {org}", C.GY))
    print_sep("─", C.B)


def write_progress(pct: float, extra: str = "") -> None:
    """显示 # 进度条"""
    filled = int(pct / 100 * BAR_WIDTH)
    bar = c(_FILL * filled, C.G) + c(_EMPTY * (BAR_WIDTH - filled), C.NW)
    pct_s = f"{pct:5.1f}%".rjust(6)
    line = f"\r  [{bar}] {pct_s}{extra}"
    sys.stderr.write(line)
    # Pad to 80 cols to erase leftover chars from previous longer line
    visible = re.sub(r'\x1b\[[0-9;]*m', '', line)
    pad = max(0, 80 - len(visible))
    sys.stderr.write(" " * pad)
    sys.stderr.flush()


def write_progress_done(extra: str = "") -> None:
    """完成进度条"""
    bar = c(_FILL * BAR_WIDTH, C.G)
    pct_s = "100.0%".rjust(6)
    line = f"\r  [{bar}] {pct_s}{extra}"
    # Compute visible width (strip ANSI escape sequences)
    import re
    visible = re.sub(r'\x1b\[[0-9;]*m', '', line)
    sys.stderr.write(line)
    pad = max(0, 80 - len(visible))
    sys.stderr.write(" " * pad + "\n")
    sys.stderr.flush()


def print_result_header(total_asn: int, total_cidr: int,
                        total_open: int, cf_nodes: int, passed: int,
                        v4_cidr: int = 0) -> None:
    """打印结果摘要头部"""
    cidr_info = str(total_cidr)
    if v4_cidr:
        cidr_info += f" (IPV4={v4_cidr})"
    print_sep("─", C.B)
    print(c("  [TASK COMPLETE]", C.LG))
    print(c(f"  ASN: {total_asn}  |  CIDR: {cidr_info}  |  "
            f"Open Ports: {total_open}  |  CF Nodes: {cf_nodes}  |  "
            f"Passed: {passed}", C.W))
    print_sep("─", C.B)


def print_total_time(elapsed: float) -> None:
    """打印总耗时"""
    m, s = divmod(int(elapsed), 60)
    print(c(f"  总耗时: {m}分{s}秒", C.GY))


# ── 公网 IP 获取（并发 HTTP + DNS 兜底） ──

_HTTP_APIS = [
    ("https://api.ipify.org", 5),
    ("https://api-ipv4.ip.sb/ip", 5),
    ("https://ifconfig.me/ip", 5),
    ("https://icanhazip.com", 5),
]

_DNS_QUERIES = [
    (["dig", "+short", "myip.opendns.com", "@resolver1.opendns.com"], 5),
    (["dig", "TXT", "+short", "o-o.myaddr.l.google.com", "@ns1.google.com"], 5),
    (["dig", "+short", "whoami.akamai.net", "@ns1-1.akamaitech.net"], 5),
]


def _try_http_ip(url: str, timeout: int) -> Optional[str]:
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8").strip()
    except (OSError, socket.timeout, urllib.error.URLError):
        return None


def _try_dns_ip(cmd: list[str], timeout: int) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = r.stdout.strip().strip('"')
        if out:
            ipaddress.ip_address(out)
            return out
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass
    return None


def get_public_ip() -> str:
    with ThreadPoolExecutor(max_workers=len(_HTTP_APIS)) as ex:
        futures = [ex.submit(_try_http_ip, url, t) for url, t in _HTTP_APIS]
        for f in as_completed(futures):
            ip = f.result()
            if ip:
                return ip
    with ThreadPoolExecutor(max_workers=len(_DNS_QUERIES)) as ex:
        futures = [ex.submit(_try_dns_ip, cmd, t) for cmd, t in _DNS_QUERIES]
        for f in as_completed(futures):
            ip = f.result()
            if ip:
                return ip
    return "127.0.0.1"


def get_lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# ── ISP/运营商检测 ──

_IPINFO_TOKEN_PATHS = [
    Path("/root/.ipinfo_token"),
    Path.home() / ".ipinfo_token",
]


def _load_ipinfo_token() -> Optional[str]:
    for p in _IPINFO_TOKEN_PATHS:
        if p.is_file():
            return p.read_text().strip()
    return None


def detect_isp(ip: str) -> tuple[str, str, str, str]:
    """返回 (ip, country, org, city)，不打印"""
    if ip == "127.0.0.1":
        return ip, "", "", ""
    try:
        token = _load_ipinfo_token()
        url = f"https://ipinfo.io/{ip}/json"
        if token:
            url += f"?token={token}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        country = data.get("country", "")
        org = data.get("org", "")
        city = data.get("city", "")
        return ip, country, org, city
    except (OSError, TypeError, KeyError):
        pass
    return ip, "", "", ""


# ── 端口解析 ──

def parse_ports(port_str: str) -> str:
    ports: set[str] = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                pa, pb = int(a), int(b)
                if 1 <= pa <= pb <= 65535:
                    ports.update(str(p) for p in range(pa, pb + 1))
            elif part.isdigit():
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(part)
        except ValueError:
            continue
    return ",".join(sorted(ports, key=int)) if ports else ""


def port_is_free(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(1)
        return sock.connect_ex(("127.0.0.1", port)) != 0
    finally:
        sock.close()


def kill_port_process(port: int) -> bool:
    try:
        r = subprocess.run(["ss", "-tlnp", f"sport = :{port}"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.split("\n"):
            pid_match = re.search(r"pid=(\d+)", line)
            if pid_match:
                os.kill(int(pid_match.group(1)), signal.SIGTERM)
                time.sleep(0.3)
                return True
    except (subprocess.TimeoutExpired, OSError):
        pass
    try:
        r = subprocess.run(["lsof", "-ti", f":{port}"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.split("\n"):
            if line.strip().isdigit():
                os.kill(int(line.strip()), signal.SIGTERM)
                time.sleep(0.3)
                return True
    except (subprocess.TimeoutExpired, OSError):
        pass
    return False
